"""Check safe installation behavior around the vendor package transaction."""

import importlib.util
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import call, patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen


if os.name == "posix":
    path = Path(__file__).with_name("lib") / "install-offline-crowdsec.py"
    spec = importlib.util.spec_from_file_location("offline_installer", path)
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)


@unittest.skipUnless(os.name == "posix", "requires POSIX file locking")
class OfflineInstallTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def test_keeps_configured_agent_and_operator_override(self):
        config = self.root / "config"
        config.mkdir()
        override = config / "config.yaml.local"
        override.write_bytes(b"# operator override\n")
        with patch.object(installer, "CONFIG", config), patch.object(
            installer, "package_status", return_value=("installed", "1.8.1")
        ), patch.object(installer.subprocess, "run") as command:
            installer.prepare_agent(self.root / "missing-snapshot", self.root / "missing-repository")
        command.assert_not_called()
        self.assertEqual(override.read_bytes(), b"# operator override\n")

    def test_copy_is_idempotent_and_rejects_conflicts(self):
        source = self.root / "source"
        source.write_bytes(b"snapshot")
        target = self.root / "config" / "file"
        installer.copy_verified(source, target)
        installer.copy_verified(source, target)
        target.write_bytes(b"operator data")
        with self.assertRaisesRegex(ValueError, "conflicts"):
            installer.copy_verified(source, target)
        self.assertEqual(target.read_bytes(), b"operator data")

    def test_copy_refuses_symlink_directory(self):
        source = self.root / "source"
        source.write_bytes(b"snapshot")
        redirected = self.root / "elsewhere"
        redirected.mkdir()
        linked = self.root / "link"
        linked.symlink_to(redirected, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink directory"):
            installer.copy_verified(source, linked / "file")
        self.assertFalse((redirected / "file").exists())

    def test_created_directories_allow_service_traversal_under_private_umask(self):
        existing = self.root / "operator"
        existing.mkdir(mode=0o700)
        target = existing / "crowdsec" / "acquis.d"
        previous = os.umask(0o077)
        try:
            installer.mkdir_tree(target)
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(existing.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)

    def test_agent_restart_recovers_after_one_failure(self):
        args = ["systemctl", "restart", "crowdsec.service"]
        failure = subprocess.CalledProcessError(1, args)
        with patch.object(installer.subprocess, "run", side_effect=[failure, None]) as run, patch.object(
            installer.time, "sleep"
        ) as sleep:
            installer.restart_agent()
        self.assertEqual(run.call_args_list, [call(args, check=True)] * 2)
        sleep.assert_called_once_with(2)

    def test_agent_restart_stops_after_three_failures(self):
        args = ["systemctl", "restart", "crowdsec.service"]
        failure = subprocess.CalledProcessError(1, args)
        with patch.object(installer.subprocess, "run", side_effect=failure) as run, patch.object(
            installer.time, "sleep"
        ) as sleep:
            with self.assertRaises(subprocess.CalledProcessError):
                installer.restart_agent()
        self.assertEqual(run.call_args_list, [call(args, check=True)] * 3)
        self.assertEqual(sleep.call_args_list, [call(2)] * 2)

    def test_mirror_serves_only_embedded_index(self):
        index = b'{"fixture": {}}'
        with installer.serve_index(index) as port:
            endpoint = f"http://127.0.0.1:{port}"
            index_url = endpoint + installer.INDEX_ROUTE + "?with_content=true"
            with urlopen(Request(index_url, method="HEAD"), timeout=3) as response:
                self.assertEqual(response.read(), b"")
                self.assertEqual(int(response.headers["Content-Length"]), len(index))
            with urlopen(index_url, timeout=3) as response:
                self.assertEqual(response.read(), index)
            with self.assertRaises(HTTPError) as rejected:
                urlopen(endpoint + "/snapshot/other.yaml", timeout=3)
            self.assertEqual(rejected.exception.code, 404)

    def test_mirror_serves_requests_with_an_idle_connection(self):
        index = b'{"fixture": {}}'
        with installer.serve_index(index) as port:
            address = ("127.0.0.1", port)
            with socket.create_connection(address, timeout=2):
                url = f"http://{address[0]}:{port}{installer.INDEX_ROUTE}?with_content=true"
                with urlopen(url, timeout=2) as response:
                    self.assertEqual(response.read(), index)

    def test_mirror_closes_idle_connections(self):
        with patch.object(installer, "INDEX_SOCKET_TIMEOUT", 0.5), installer.serve_index(b"{}") as port:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as idle:
                self.assertEqual(idle.recv(1), b"")


if __name__ == "__main__":
    unittest.main()
