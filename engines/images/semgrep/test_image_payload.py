import io
import tarfile
import unittest
from unittest.mock import patch

from verify_image_payload import payload, verify


class ImagePayloadTests(unittest.TestCase):
    def receipt(self, body=b"verified runtime", mode=0o555, hostname=b"runner-a", mtime=1, duplicate=False):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for name, content, permissions in (("opt/semgrep/bin/semgrep", body, mode), ("etc/hostname", hostname, 0o644)):
                member = tarfile.TarInfo(name)
                member.size, member.mode, member.mtime = len(content), permissions, mtime
                archive.addfile(member, io.BytesIO(content))
                if duplicate:
                    archive.addfile(member, io.BytesIO(content))
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            return payload(archive)

    def test_runtime_bytes_and_execute_permissions_are_bound(self):
        expected = self.receipt()["rootfs_payload_sha256"]
        self.assertNotEqual(self.receipt(body=b"different runtime")["rootfs_payload_sha256"], expected)
        self.assertNotEqual(self.receipt(mode=0o777)["rootfs_payload_sha256"], expected)

    def test_runner_hostname_and_tar_timestamps_do_not_change_image_payload(self):
        self.assertEqual(self.receipt()["rootfs_payload_sha256"], self.receipt(hostname=b"runner-b", mtime=2)["rootfs_payload_sha256"])

    def test_duplicate_archive_members_are_refused(self):
        with self.assertRaisesRegex(ValueError, "repeated"):
            self.receipt(duplicate=True)

    def test_exact_digest_accepts_both_publication_origins_and_refuses_other_images(self):
        digest = "sha256:" + "a" * 64
        for reference in (digest, *(f"ghcr.io/{owner}/ai-security-scanner-engine-semgrep@{digest}"
                                    for owner in ("teddashh", "ted-h-com"))):
            with patch("verify_image_payload.subprocess.run", side_effect=RuntimeError("docker boundary")) as run:
                with self.assertRaisesRegex(RuntimeError, "docker boundary"):
                    verify(reference)
                self.assertEqual(run.call_args.args[0][-1], reference)
        for reference in ("ghcr.io/other/ai-security-scanner-engine-semgrep@" + digest,
                          "ghcr.io/ted-h-com/ai-security-scanner-engine-semgrep:latest",
                          "ghcr.io/ted-h-com/other-engine@" + digest):
            with patch("verify_image_payload.subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "exact Semgrep image digest"):
                    verify(reference)
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
