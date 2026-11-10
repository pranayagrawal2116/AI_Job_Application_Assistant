"""Isolated FastAPI + React test server fixture for Playwright acceptance testing.

Spins up an ephemeral, hermetic backend server using an isolated SQLite database,
temporary candidate storage directories, mock discovery adapters, and a dynamic port.
"""

from contextlib import contextmanager
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from typing import Generator, Optional
import urllib.request
import urllib.error

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def find_free_port() -> int:
    """Finds an available TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class IsolatedTestServer:
    """Manages lifecycle of an isolated FastAPI test instance on a dynamic port."""

    def __init__(self, port: Optional[int] = None):
        self.port = port or find_free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

        # Isolated database & storage locations
        self.db_path = self.temp_path / "isolated_jobflow.db"
        self.storage_base = self.temp_path / "user_storage"
        self.storage_base.mkdir(parents=True, exist_ok=True)

        self.process: Optional[subprocess.Popen] = None
        self._server_log_file = None

    def start(self, timeout_seconds: float = 12.0) -> None:
        """Starts the FastAPI uvicorn server in a subprocess and waits for /api/health."""
        env = os.environ.copy()
        env["APP_ENV"] = "test"
        env["DATABASE_PATH"] = str(self.db_path)
        env["USER_STORAGE_BASE"] = str(self.storage_base)
        env["MOCK_DISCOVERY_ADAPTERS"] = "1"
        env["ACTION_TICKET_SECRET_KEY"] = "0123456789abcdef" * 4
        env["PUBLIC_BASE_URL"] = self.base_url

        cmd = [
            sys.executable,
            "-m",
            "uvicorn",
            "backend.api.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(self.port),
            "--log-level",
            "warning",
        ]

        self.server_log_path = self.temp_path / "server.log"
        self._server_log_file = open(self.server_log_path, "w", encoding="utf-8")
        self.process = subprocess.Popen(
            cmd,
            cwd=str(PROJECT_ROOT),
            env=env,
            stdout=self._server_log_file,
            stderr=subprocess.STDOUT,
        )

        # Wait for health endpoint
        health_url = f"{self.base_url}/api/health"
        start_time = time.time()
        while time.time() - start_time < timeout_seconds:
            if self.process.poll() is not None:
                _, stderr = self.process.communicate()
                raise RuntimeError(f"Server process terminated prematurely with error:\n{stderr.decode('utf-8', errors='ignore')}")
            try:
                with urllib.request.urlopen(health_url, timeout=1.0) as resp:
                    if resp.status in (200, 503):
                        return
            except (urllib.error.URLError, ConnectionRefusedError, socket.timeout):
                time.sleep(0.15)

        self.stop()
        raise TimeoutError(f"Isolated server failed to respond on {health_url} within {timeout_seconds}s")

    def stop(self) -> None:
        """Terminates the uvicorn subprocess cleanly."""
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2.0)
            self.process = None
        if self._server_log_file and not self._server_log_file.closed:
            self._server_log_file.close()

    def restart(self, timeout_seconds: float = 12.0) -> None:
        """Stops and restarts the server with the exact same database to simulate restarts/recovery."""
        self.stop()
        time.sleep(0.5)
        self.start(timeout_seconds=timeout_seconds)

    def cleanup(self) -> None:
        """Stops the server and removes all temporary files and databases."""
        self.stop()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass


@contextmanager
def run_isolated_server() -> Generator[IsolatedTestServer, None, None]:
    """Context manager yielding a running IsolatedTestServer instance."""
    server = IsolatedTestServer()
    try:
        server.start()
        yield server
    finally:
        server.cleanup()
