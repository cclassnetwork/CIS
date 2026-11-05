"""NETWORKINTEL - authorised local network inventory and asset discovery.

SAFETY MODEL
* Disabled unless the operator explicitly confirms authorisation for the target.
* Targets are limited to private / loopback / link-local ranges unless the
  operator changes a setting (``allow_public_network_targets``).
* Only TCP connect probes, optional ICMP echo and reverse DNS are used.  There
  is no banner grabbing, no credential testing, no exploit logic.
"""

from __future__ import annotations

import csv
import errno
import ipaddress
import re
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

from ..config import Settings
from ..models import ModuleResult
from ..utils import clean_text
from .base import Module, ModuleContext

SRC = "Local network observation"
LIVENESS_PORTS = (22, 80, 443, 445, 3389)

RISKY_PORTS: Dict[int, Tuple[str, str]] = {
    21: ("FTP (clear-text credentials)", "medium"), 23: ("Telnet (clear-text remote shell)", "medium"),
    25: ("SMTP service exposed", "low"), 110: ("POP3 (clear text)", "low"), 143: ("IMAP (clear text)", "low"),
    139: ("NetBIOS session service", "low"), 445: ("SMB file sharing", "low"), 3389: ("Remote Desktop", "low"),
    5900: ("VNC remote desktop", "low"), 3306: ("MySQL reachable", "low"), 5432: ("PostgreSQL reachable", "low"),
}


class AuthorizationError(Exception):
    """Raised when a scan is requested without explicit, valid authorisation."""


@lru_cache(maxsize=2)
def _oui(path: str) -> Dict[str, str]:
    table: Dict[str, str] = {}
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                table[row["prefix"].upper()] = row["vendor"]
    except (OSError, KeyError):
        pass
    return table


def local_networks() -> List[ipaddress.IPv4Network]:
    """IPv4 networks of the machine's own interfaces (best effort)."""
    nets: List[ipaddress.IPv4Network] = []
    if shutil.which("ip"):
        try:
            out = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True, timeout=5).stdout
            for m in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", out):
                net = ipaddress.ip_interface(m.group(1)).network
                if not net.is_loopback and not net.is_link_local:
                    nets.append(net)
        except (OSError, subprocess.SubprocessError, ValueError):
            pass
    if not nets:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("192.0.2.1", 9))  # UDP connect sends no packet
                nets.append(ipaddress.ip_network(f"{s.getsockname()[0]}/24", strict=False))
        except OSError:
            pass
    return nets


def resolve_targets(spec: str, settings: Settings) -> List[ipaddress.IPv4Address]:
    spec = spec.strip()
    if spec.lower() == "local":
        networks = local_networks()
        if not networks:
            raise ValueError("could not determine local networks; specify a CIDR such as 192.168.1.0/24")
    else:
        try:
            networks = [ipaddress.ip_network(spec, strict=False)]
        except ValueError:
            raise ValueError("target must be an IPv4 address, a CIDR range such as 192.168.1.0/24, or 'local'") from None
    hosts: List[ipaddress.IPv4Address] = []
    for net in networks:
        if net.version != 4:
            raise ValueError("only IPv4 inventory is supported")
        if not settings.allow_public_network_targets and not (net.is_private or net.is_loopback or net.is_link_local):
            raise AuthorizationError(
                f"{net} is not a private range. Scanning public address space is blocked by default; "
                "enable 'allow_public_network_targets' only for networks you own or are contracted to test.")
        hosts.extend(net.hosts() if net.num_addresses > 2 else list(net))
        if len(hosts) > settings.max_scan_hosts:
            raise ValueError(f"target covers more than {settings.max_scan_hosts} hosts (max_scan_hosts setting)")
    return hosts


def tcp_state(ip: str, port: int, timeout: float) -> str:
    """'open', 'closed' (RST - host is up) or 'filtered'."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            code = s.connect_ex((ip, port))
        except OSError:
            return "filtered"
    if code == 0:
        return "open"
    return "closed" if code == errno.ECONNREFUSED else "filtered"


def ping(ip: str) -> bool:
    exe = shutil.which("ping")
    if not exe:
        return False
    try:
        return subprocess.run([exe, "-c", "1", "-W", "1", ip], capture_output=True, timeout=4).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def read_arp() -> Dict[str, str]:
    table: Dict[str, str] = {}
    try:
        with open("/proc/net/arp", encoding="utf-8") as fh:
            next(fh, None)
            for line in fh:
                cols = line.split()
                if len(cols) >= 4 and cols[2] != "0x0" and cols[3] != "00:00:00:00:00:00":
                    table[cols[0]] = cols[3].lower()
    except OSError:
        pass
    return table


class NetworkIntel(Module):
    name = "NETWORKINTEL"
    description = ("Authorised local network inventory: live hosts, open common ports, reverse DNS, MAC/vendor. "
                   "Requires explicit authorisation; private ranges only by default.")
    accepts = ("network", "ip")
    requires_authorization = True

    def run(self, query: str, ctx: ModuleContext, authorized: bool = False, ports: Optional[List[int]] = None,
            **options: Any) -> ModuleResult:
        res = ModuleResult(self.name, query.strip())
        if not authorized:
            return res.fail("authorisation required: confirm that you own or are explicitly permitted to inventory "
                            "this network before running NETWORKINTEL")
        try:
            hosts = resolve_targets(query, ctx.settings)
        except AuthorizationError as exc:
            return res.fail(str(exc))
        except ValueError as exc:
            return res.fail(str(exc))
        port_list = sorted(set(ports or ctx.settings.scan_ports))
        timeout = ctx.settings.scan_timeout
        workers = ctx.settings.scan_workers

        def alive(h: ipaddress.IPv4Address) -> Optional[str]:
            ip = str(h)
            for p in LIVENESS_PORTS:
                if tcp_state(ip, p, timeout) in ("open", "closed"):
                    return ip
            return ip if ping(ip) else None

        with ThreadPoolExecutor(max_workers=workers) as pool:
            live = [ip for ip in pool.map(alive, hosts) if ip]

        def scan(ip: str) -> Dict[str, Any]:
            open_ports = [p for p in port_list if tcp_state(ip, p, timeout) == "open"]
            try:
                rdns = socket.gethostbyaddr(ip)[0].lower()
            except (OSError, UnicodeError):
                rdns = None
            return {"ip": ip, "open_ports": open_ports, "rdns": rdns}

        with ThreadPoolExecutor(max_workers=min(workers, 32)) as pool:
            scanned = list(pool.map(scan, live))
        arp = read_arp()
        oui = _oui(str(ctx.settings.sample_dir / "oui_sample.csv"))

        for h in scanned:
            ip = h["ip"]
            ref = ("ip", ip)
            mac = arp.get(ip)
            vendor = oui.get(mac[:8].upper()) if mac else None
            services = {}
            for p in h["open_ports"]:
                try:
                    services[p] = socket.getservbyport(p, "tcp")
                except OSError:
                    services[p] = "unknown"
            res.add_entity("ip", ip, attributes={"open_ports": h["open_ports"], "services": services,
                                                  "asset_status": "discovered", "classification": "internal"})
            if h["rdns"]:
                res.add_entity("hostname", h["rdns"])
                res.relate(ref, ("hostname", h["rdns"]), "reverse_dns", SRC, 0.9)
            if mac:
                res.add_entity("mac", mac, attributes={"vendor": vendor})
                res.relate(ref, ("mac", mac), "has_mac", SRC, 0.9)
            desc = f"Open: {', '.join(f'{p}/{s}' for p, s in services.items()) or 'none of the scanned ports'}."
            if mac:
                desc += f" MAC {mac}" + (f" ({vendor})." if vendor else ".")
            res.add_finding(f"Host discovered: {ip}" + (f" ({h['rdns']})" if h["rdns"] else ""), desc,
                            source=SRC, entity=ref, quality=0.9, data={"ports": h["open_ports"]})
            for p in h["open_ports"]:
                if p in RISKY_PORTS:
                    label, sev = RISKY_PORTS[p]
                    res.add_finding(f"{label} on {ip}:{p}", "Inventory observation on an authorised network - review "
                                    "whether this exposure is intended and restrict or encrypt it.", sev, source=SRC,
                                    entity=ref, quality=0.9)
        res.add_finding(f"Inventory of {query.strip()}: {len(scanned)} live host(s) of {len(hosts)} addresses",
                        f"Ports probed: {', '.join(map(str, port_list))}. Methods: TCP connect, ICMP echo, reverse DNS, "
                        "ARP cache.", source=SRC, quality=0.9)
        res.raw = {"hosts_probed": len(hosts), "live": len(scanned)}
        return res
