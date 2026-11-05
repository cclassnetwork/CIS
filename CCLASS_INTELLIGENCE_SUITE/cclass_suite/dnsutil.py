"""DNS client that degrades gracefully (offline sample data, missing library, timeouts)."""

from __future__ import annotations

import json
import logging
from typing import Dict, List, Optional, Tuple

from .config import Settings

log = logging.getLogger("cclass.dns")


class DnsClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._sample: Optional[Dict[str, Dict[str, List[str]]]] = None

    # ------------------------------------------------------------------
    def _load_sample(self) -> Dict[str, Dict[str, List[str]]]:
        if self._sample is None:
            try:
                self._sample = json.loads((self.settings.sample_dir / "sample_dns.json").read_text())
            except (OSError, ValueError):
                self._sample = {}
        return self._sample

    def query(self, name: str, rtype: str) -> Tuple[List[str], Optional[str]]:
        """Return ``(records, error)``.  ``error`` is None for success and for a clean empty answer."""
        name = name.strip().rstrip(".").lower()
        rtype = rtype.upper()
        if self.settings.offline_mode:
            data = self._load_sample().get(name)
            if data is None:
                return [], "no offline sample data for this name"
            return list(data.get(rtype, [])), None
        try:
            import dns.exception
            import dns.resolver
        except ImportError:
            return [], "dnspython is not installed"
        resolver = dns.resolver.Resolver()
        resolver.lifetime = resolver.timeout = float(self.settings.dns_timeout)
        try:
            answer = resolver.resolve(name, rtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return [], "NXDOMAIN"
        except dns.resolver.NoNameservers:
            return [], "no nameserver answered"
        except dns.exception.Timeout:
            return [], "timeout"
        except dns.exception.DNSException as exc:
            return [], f"{exc.__class__.__name__}"
        except Exception as exc:  # noqa: BLE001
            log.warning("Unexpected DNS failure for %s %s: %s", name, rtype, exc)
            return [], f"unexpected: {exc.__class__.__name__}"
        records: List[str] = []
        if answer.rrset is None:
            return records, None
        for rdata in answer:
            if rtype == "TXT":
                records.append(b"".join(rdata.strings).decode("utf-8", "replace"))
            elif rtype == "MX":
                records.append(f"{rdata.preference} {str(rdata.exchange).rstrip('.')}")
            else:
                records.append(rdata.to_text().rstrip("."))
        return records, None

    def reverse(self, ip: str) -> Tuple[List[str], Optional[str]]:
        if self.settings.offline_mode:
            data = self._load_sample().get(f"ptr:{ip}")
            return (list(data.get("PTR", [])), None) if data else ([], "no offline sample data")
        try:
            import dns.reversename

            rev = dns.reversename.from_address(ip)
        except ImportError:
            return [], "dnspython is not installed"
        except Exception:  # noqa: BLE001
            return [], "invalid address"
        return self.query(str(rev), "PTR")
