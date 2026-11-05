import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cclass_suite.config import Settings  # noqa: E402
from cclass_suite.context import AppContext  # noqa: E402


@pytest.fixture()
def settings(tmp_path):
    s = Settings.load(tmp_path / "data")
    s.offline_mode = True
    return s


@pytest.fixture()
def ctx(settings):
    return AppContext(settings, console_log=False)


@pytest.fixture()
def inv(ctx):
    return ctx.db.create_investigation("test investigation", "unit test")
