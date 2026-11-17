"""Stage only verified files from an operator-provided CrowdSec snapshot."""

import hashlib
import os
import re
import shutil
import stat
import sys
from pathlib import Path


REQUIRED = {
    "SNAPSHOT.env",
    "setup.yaml",
    "hub/.index.json",
    *(f"hub/collections/crowdsecurity/{name}.yaml" for name in ("linux", "haproxy", "sshd", "pgsql")),
}
HUB_TYPES = {"appsec-configs", "appsec-rules", "collections", "contexts", "parsers", "postoverflows", "scenarios"}
COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
ENTRY = re.compile(r"([a-f0-9]{64})  (\S+)\Z")


def allowed_path(name):
    if name in REQUIRED:
        return True
    parts = name.split("/")
    if not all(COMPONENT.fullmatch(part) for part in parts):
        return False
    if parts[0] == "data" and len(parts) >= 2:
        return Path(parts[-1]).suffix in {".csv", ".json", ".mmdb", ".regex", ".txt"}
    return len(parts) >= 4 and parts[0] == "hub" and parts[1] in HUB_TYPES and parts[-1].endswith(".yaml")


def open_regular(name, dirfd):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirfd)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError(f"not a regular snapshot file: {name}")
    return os.fdopen(fd, "rb")


def manifest_entries(contents):
    entries = {}
    for line in contents.decode("ascii").splitlines():
        match = ENTRY.fullmatch(line)
        if not match:
            raise ValueError("invalid snapshot checksum record")
        digest, name = match.groups()
        if not allowed_path(name) or name in entries:
            raise ValueError(f"unexpected or duplicate snapshot path: {name}")
        entries[name] = digest
    if REQUIRED - entries.keys() or not any(name.startswith("data/") for name in entries):
        raise ValueError("snapshot is missing required Hub or data files")
    return entries


def check_version(metadata, package_version):
    match = re.fullmatch(
        r"CROWDSEC_CLI_VERSION=v(\d+\.\d+\.\d+)(?:-[A-Za-z0-9._+-]+)?\n"
        r"CROWDSEC_HUB_BRANCH=[A-Za-z0-9][A-Za-z0-9._/-]*\n",
        metadata.read_text(encoding="ascii"),
    )
    upstream = package_version.rsplit(":", 1)[-1].split("-", 1)[0]
    if not match or match[1] != upstream:
        raise ValueError(f"snapshot CLI version does not match CrowdSec package {package_version}")


def walk_error(error):
    raise error


def stage(source, target, package_version):
    source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with open_regular("SHA256SUMS", source_fd) as manifest:
            contents = manifest.read()
        remaining = manifest_entries(contents)
        target.mkdir(mode=0o700)
        try:
            for folder, directories, files, dirfd in os.fwalk(".", dir_fd=source_fd, onerror=walk_error):
                for directory in directories:
                    if not stat.S_ISDIR(os.stat(directory, dir_fd=dirfd, follow_symlinks=False).st_mode):
                        raise ValueError(f"unexpected snapshot directory entry: {directory}")
                for file in files:
                    name = (Path(folder) / file).as_posix()
                    if name == "SHA256SUMS":
                        continue
                    expected = remaining.pop(name, None)
                    if expected is None:
                        raise ValueError(f"unlisted snapshot file: {name}")
                    destination = target / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with open_regular(file, dirfd) as original, destination.open("xb+") as copied:
                        shutil.copyfileobj(original, copied)
                        copied.seek(0)
                        if hashlib.file_digest(copied, "sha256").hexdigest() != expected:
                            raise ValueError(f"snapshot checksum mismatch: {name}")
            if remaining:
                raise ValueError(f"missing snapshot files: {', '.join(sorted(remaining))}")
            check_version(target / "SNAPSHOT.env", package_version)
            (target / "SHA256SUMS").write_bytes(contents)
        except BaseException:
            shutil.rmtree(target)
            raise
    finally:
        os.close(source_fd)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("usage: offline-crowdsec-snapshot.py SOURCE DESTINATION DEB_VERSION")
    try:
        stage(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])
    except (ValueError, OSError) as error:
        sys.exit(f"[offline-build] CrowdSec snapshot rejected: {error}")
