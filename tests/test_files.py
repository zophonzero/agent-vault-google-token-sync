import os
from pathlib import Path
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from av_google_token_sync.files import check_regular, protected_read


class ProtectedFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / "key"
        self.path.write_bytes(b"synthetic")
        self.path.chmod(0o600)

    def test_only_owner_readable_regular_modes_are_accepted(self):
        for mode in [0o700, 0o500, 0o4600, 0o2600, 0o1600, 0o644, 0o640]:
            with self.subTest(mode=mode):
                self.path.chmod(mode)
                with self.assertRaises(ValueError):
                    protected_read(self.path)
        for mode in [0o400, 0o600]:
            self.path.chmod(mode)
            self.assertEqual(protected_read(self.path), b"synthetic")

    def test_systemd_group_credentials_require_private_readonly_mount(self):
        original = os.fstat
        file_inode = self.path.stat().st_ino
        directory_inode = self.root.stat().st_ino
        gid = os.getegid()
        credential_gid = gid

        def metadata(fd):
            st = original(fd)
            if st.st_ino == file_inode:
                return SimpleNamespace(st_uid=0, st_gid=credential_gid, st_mode=stat.S_IFREG | 0o440, st_nlink=1)
            if st.st_ino == directory_inode:
                return SimpleNamespace(st_uid=0, st_gid=credential_gid, st_mode=stat.S_IFDIR | 0o550)
            return st

        with patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(self.root)}), patch(
            "os.fstat", side_effect=metadata,
        ), patch("os.fstatvfs", return_value=SimpleNamespace(f_flag=os.ST_RDONLY)):
            self.assertEqual(protected_read(self.path), b"synthetic")
            with patch("os.fstatvfs", return_value=SimpleNamespace(f_flag=0)):
                with self.assertRaises(ValueError):
                    protected_read(self.path)
            with patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(self.root / "other")}):
                with self.assertRaises(ValueError):
                    protected_read(self.path)
            with patch("os.getegid", return_value=gid + 1):
                with self.assertRaises(ValueError):
                    protected_read(self.path)
            # systemd 259 can use root:root plus a named-user POSIX ACL.
            credential_gid = 0
            self.assertEqual(protected_read(self.path), b"synthetic")

    def test_group_readable_regular_file_is_not_a_systemd_credential(self):
        self.path.chmod(0o440)
        with patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(self.root)}):
            with self.assertRaises(ValueError):
                protected_read(self.path)

    def test_fifo_directory_hardlink_and_symlink_rejected(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        link = self.root / "link"
        link.symlink_to(self.path)
        hard = self.root / "hard"
        os.link(self.path, hard)
        for path in [fifo, self.root, link, hard]:
            with self.subTest(path=path.name), self.assertRaises((ValueError, OSError)):
                protected_read(path)

    def test_wrong_owner_rejected(self):
        wrong_uid = os.geteuid() + 10000
        st = SimpleNamespace(st_uid=wrong_uid, st_mode=stat.S_IFREG | 0o600, st_nlink=1)
        with self.assertRaises(ValueError):
            check_regular(st)

    def test_oversized_file_rejected(self):
        self.path.write_bytes(b"x" * (1024 * 1024 + 1))
        with self.assertRaises(ValueError):
            protected_read(self.path)


if __name__ == "__main__":
    unittest.main()
