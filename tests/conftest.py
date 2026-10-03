import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import mock_epo  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SHIM = Path(__file__).resolve().parent / "shim"
PYTHON = os.environ.get("HUNTER_PYTHON", sys.executable)


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def epo():
    port = _free_port()
    srv = mock_epo.start(port)
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


@pytest.fixture
def state():
    mock_epo.S.reset()
    return mock_epo.S


@pytest.fixture
def base_env(epo):
    return {
        "EPO_URL": epo,
        "EPO_USERNAME": "api_user",
        "EPO_PASSWORD": "s3cret",
        "WEBHOOK_URL": f"{epo}/webhook",
        "EPO_VERIFY_SSL": "false",
    }


@pytest.fixture
def run(tmp_path):
    """Copy the script into a temp dir, write a .env there and run it as a subprocess."""

    def _run(env_vars, *args):
        shutil.copy(ROOT / "compliance_hunter.py", tmp_path)
        (tmp_path / ".env").write_text("\n".join(f"{k}={v}" for k, v in env_vars.items()) + "\n")
        env = {k: v for k, v in os.environ.items() if not k.startswith(("EPO_", "WEBHOOK", "STALE", "TAG_", "DAT_"))}
        env["PYTHONPATH"] = str(SHIM)
        env["NO_PROXY"] = "127.0.0.1,localhost"
        return subprocess.run(
            [PYTHON, str(tmp_path / "compliance_hunter.py"), *args],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

    return _run
