"""Linux descriptor-relative protected file access; no symlink traversal."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import stat

MAX_FILE_BYTES = 1024 * 1024


def _owner(st):
    if st.st_uid not in (0, os.geteuid()):
        raise ValueError


@contextmanager
def parent_fd(path):
    path = Path(path)
    # Path preserves a double-leading slash as a distinct anchor, but Linux
    # resolves it to the same file. Reject it before lexical collision checks
    # can disagree with descriptor-based reads/writes.
    if path.anchor != "/" or ".." in path.parts:
        raise ValueError
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        private_ancestor = False
        parents = path.parts[1:-1]
        for index, part in enumerate(parents):
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            st = os.fstat(fd)
            _owner(st)
            # A private ancestor already prevents other users reaching deeper
            # directories. Still require the immediate parent to be protected.
            if (st.st_mode & 0o022
                    and (not private_ancestor or index == len(parents) - 1)
                    and not (st.st_uid == 0 and st.st_mode & stat.S_ISVTX)):
                raise ValueError
            private_ancestor |= not bool(st.st_mode & 0o011)
        yield fd, path.name
    finally:
        os.close(fd)


def check_regular(st, *, systemd_credential=False):
    _owner(st)
    modes = (0o400, 0o600, 0o440) if systemd_credential else (0o400, 0o600)
    if (not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) not in modes
            or st.st_nlink != 1):
        raise ValueError


def _systemd_credential(path, directory, fd, st):
    # systemd exposes root:service-group or root:root + named-user ACL 0440
    # files inside a 0550 read-only mount. Kernel access checks still apply.
    credential_dir = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if not credential_dir or Path(path).parent != Path(credential_dir):
        return False
    parent = os.fstat(directory)
    return (st.st_uid == parent.st_uid == 0
            and st.st_gid == parent.st_gid and st.st_gid in (0, os.getegid())
            and stat.S_IMODE(parent.st_mode) == 0o550
            and bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY))


def protected_read(path):
    with parent_fd(path) as (directory, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            st = os.fstat(stream.fileno())
            check_regular(st, systemd_credential=(stat.S_IMODE(st.st_mode) == 0o440
                          and _systemd_credential(path, directory, stream.fileno(), st)))
            data = stream.read(MAX_FILE_BYTES + 1)
            if len(data) > MAX_FILE_BYTES:
                raise ValueError
            return data


def _check_destination(directory, name):
    try:
        st = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    check_regular(st)


def validate_destination(path):
    with parent_fd(path) as (directory, name):
        _check_destination(directory, name)


def write_status(path, data):
    import secrets
    with parent_fd(path) as (directory, name):
        _check_destination(directory, name)
        temporary = ".token-sync-" + secrets.token_hex(16)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(data, stream, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            _check_destination(directory, name)
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass


def strict_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    return json.loads(data, object_pairs_hook=unique)
