"""Bootstrap the CrowdSec agent from a verified private offline bundle."""

import filecmp
import fcntl
import hashlib
import os
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from threading import Thread


CONFIG = Path("/etc/crowdsec")
DATA = Path("/var/lib/crowdsec/data")
RUN = Path("/run/lock")
PENDING = ".easy-waf-offline-install"
INDEX_ROUTE = "/snapshot/.index.json"
INDEX_SOCKET_TIMEOUT = 5
ACQUISITION = b"""source: file
filenames:
  - /var/log/haproxy.log
labels:
  type: haproxy
---
source: file
filenames:
  - /var/log/messages
  - /var/log/syslog
  - /var/log/kern.log
  - /var/log/auth.log
  - /var/log/secure
labels:
  type: syslog
---
source: file
filenames:
  - /var/log/postgresql/*.log
labels:
  type: postgres
"""


def output(*command):
    return subprocess.check_output(command, text=True).strip()


def package_status():
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${db:Status-Status} ${Version}", "crowdsec"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode == 1 and not result.stdout:
        return "not-installed", ""
    result.check_returncode()
    status, _, version = result.stdout.strip().partition(" ")
    return status, version


def mkdir_tree(path):
    """Refuse symlinks at every level where installer files are written."""
    for folder in (*reversed(path.parents), path):
        if folder.is_symlink():
            raise ValueError(f"refusing symlink directory {folder}")
        try:
            folder.mkdir(mode=0o755)
        except FileExistsError:
            if not folder.is_dir():
                raise
        else:
            # The packaged SPOA service must be able to traverse its config
            # parent, even if the installer inherited root's private umask.
            folder.chmod(0o755)


def copy_verified(source, destination):
    mkdir_tree(destination.parent)
    if not destination.is_symlink() and not destination.exists():
        with tempfile.NamedTemporaryFile(dir=destination.parent) as temporary:
            with source.open("rb") as contents:
                shutil.copyfileobj(contents, temporary)
            temporary.flush()
            os.fchmod(temporary.fileno(), 0o644)
            try:
                os.link(temporary.name, destination)
                return
            except FileExistsError:
                pass
    if (destination.is_symlink() or not destination.is_file()
            or not filecmp.cmp(source, destination, shallow=False)):
        raise ValueError(f"CrowdSec file conflicts with the snapshot: {destination}")


@contextmanager
def serve_index(index):
    class IndexRequest(BaseHTTPRequestHandler):
        timeout = INDEX_SOCKET_TIMEOUT

        def respond(self, send_body):
            if self.path not in (INDEX_ROUTE, INDEX_ROUTE + "?with_content=true"):
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(index)))
            self.end_headers()
            if send_body:
                self.wfile.write(index)

        def do_GET(self):
            self.respond(True)

        def do_HEAD(self):
            self.respond(False)

        def log_message(self, *_args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), IndexRequest) as server:
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield server.server_port
        finally:
            server.shutdown()
            worker.join()


def prepare_agent(snapshot, repository):
    status, installed = package_status()
    pending = CONFIG / PENDING
    override = CONFIG / "config.yaml.local"
    override_target = pending / "hub.yaml"
    if status == "installed" and not os.path.lexists(pending):
        print("[offline-install] keeping the existing CrowdSec installation")
        return

    packages = list(repository.glob("crowdsec_*.deb"))
    if len(packages) != 1 or output("dpkg-deb", "-f", packages[0], "Package") != "crowdsec":
        raise ValueError("expected exactly one CrowdSec agent package in the bundle")
    version = output("dpkg-deb", "-f", packages[0], "Version")
    if not version or installed and installed != version:
        raise ValueError("CrowdSec package version differs from the pending offline installation")

    with tempfile.TemporaryDirectory(prefix="easy-waf-crowdsec-") as directory:
        scratch = Path(directory)
        staged = scratch / "verified"
        verifier = Path(__file__).with_name("offline-crowdsec-snapshot.py")
        subprocess.run([sys.executable, "-I", verifier, snapshot, staged, version], check=True)
        identity = hashlib.sha256((staged / "SHA256SUMS").read_bytes()).hexdigest()
        if os.path.lexists(pending):
            if pending.is_symlink() or not pending.is_dir():
                raise ValueError(f"unexpected CrowdSec installation state: {pending}")
            receipt = pending / "snapshot"
            if receipt.is_symlink() or not receipt.is_file() or receipt.read_text() != identity:
                raise ValueError("retry the pending CrowdSec installation with the original snapshot")
        else:
            if status != "not-installed" or os.path.lexists(CONFIG):
                raise ValueError("CrowdSec has existing package state or configuration; resolve it before installing")
            mkdir_tree(CONFIG)
            pending.mkdir(mode=0o700)
            (pending / "snapshot").write_text(identity)

        if override.is_symlink() and override.readlink() == override_target:
            override.unlink()
        if os.path.lexists(override):
            raise ValueError(f"existing CrowdSec override: {override}")
        acquisition = scratch / "acquisition.yaml"
        acquisition.write_bytes(ACQUISITION)
        copy_verified(acquisition, CONFIG / "acquis.d/easy-waf-offline.yaml")
        index = (staged / "hub/.index.json").read_bytes()

        with serve_index(index) as port:
            override_target.write_text(
                "cscli:\n  hub_branch: snapshot\n"
                f"  __hub_url_template__: http://127.0.0.1:{port}/%s/%s\n"
                "  hub_with_content: true\n"
            )
            override.symlink_to(override_target)
            try:
                if status != "installed":
                    subprocess.run(
                        ["debconf-set-selections"],
                        input="crowdsec crowdsec/lapi boolean true\ncrowdsec crowdsec/capi boolean false\n",
                        text=True, check=True,
                    )
                    env = os.environ | {
                        "DEBIAN_FRONTEND": "noninteractive",
                        "CROWDSEC_SETUP_UNATTENDED_DISABLE": "1",
                    }
                    subprocess.run(["apt-get", "update", "-qq"], env=env, check=True)
                    subprocess.run([
                        "apt-get", "-o", "Dpkg::Options::=--force-confold", "--no-remove",
                        "install", "--no-install-recommends", "-y", f"crowdsec={version}",
                    ], env=env, check=True)
                    if package_status() != ("installed", version):
                        raise ValueError("CrowdSec did not finish package configuration")
                subprocess.run(["systemctl", "disable", "--now", "crowdsec-hubupdate.timer"], check=True)
                for source_root, target_root in ((staged / "hub", CONFIG / "hub"), (staged / "data", DATA)):
                    for source in sorted(source_root.rglob("*")):
                        if source.is_file():
                            copy_verified(source, target_root / source.relative_to(source_root))
                subprocess.run(["cscli", "setup", "install-hub", staged / "setup.yaml", "--color", "no"], check=True)
                enabled = output("cscli", "collections", "list", "-o", "raw").splitlines()
                for collection in ("linux", "haproxy", "sshd", "pgsql"):
                    prefix = f"crowdsecurity/{collection},enabled,"
                    if not any(line.startswith(prefix) for line in enabled):
                        raise ValueError(f"CrowdSec collection did not activate: {collection}")
            finally:
                if override.is_symlink() and override.readlink() == override_target:
                    override.unlink()

        subprocess.run(["crowdsec", "-t"], check=True)
        if os.environ.get("EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL", "1") == "1":
            subprocess.run(["systemctl", "restart", "crowdsec.service"], check=True)
        shutil.rmtree(pending)
        print("[offline-install] activated CrowdSec from the verified local snapshot")


def main():
    if len(sys.argv) != 3 or not os.environ.get("APT_CONFIG"):
        sys.exit("usage: install-offline-crowdsec.py SNAPSHOT LOCAL_APT_REPOSITORY (requires bundle APT_CONFIG)")
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
    try:
        with os.fdopen(os.open(RUN / "easy-waf-offline-crowdsec.lock", flags, 0o600), "r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            prepare_agent(Path(sys.argv[1]), Path(sys.argv[2]))
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(f"[offline-install] CrowdSec bootstrap failed: {error}")


if __name__ == "__main__":
    main()
