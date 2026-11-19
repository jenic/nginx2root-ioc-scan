"""Offline tests for deterministic packaging and release validation."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
import zipfile


SCRIPTS = Path(__file__).resolve().parent
REPOSITORY = SCRIPTS.parent.parent
RELEASE = SCRIPTS / "release.sh"
PACKAGE = SCRIPTS / "package.sh"
PROVENANCE = SCRIPTS / "verify_provenance.py"
ARCHIVES = [
    "nginx-ioc-scan_darwin_amd64.tar.gz",
    "nginx-ioc-scan_darwin_arm64.tar.gz",
    "nginx-ioc-scan_linux_amd64.tar.gz",
    "nginx-ioc-scan_linux_arm64.tar.gz",
    "nginx-ioc-scan_windows_amd64.zip",
    "nginx-ioc-scan_windows_arm64.zip",
]


class ReleaseTests(unittest.TestCase):
    def run_release(self, *args, tag="v1.2.3", success=True, cwd=REPOSITORY):
        result = subprocess.run(
            ["bash", str(RELEASE), *args],
            cwd=cwd,
            env=dict(os.environ, RELEASE_TAG=tag),
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def test_semver_metadata(self):
        for tag, prerelease in [
            ("v0.0.0", "false"),
            ("v1.2.3", "false"),
            ("v1.2.3-rc.1", "true"),
        ]:
            with self.subTest(tag=tag):
                output = self.run_release("metadata", tag=tag).stdout
                self.assertIn(f"tag={tag}\n", output)
                self.assertIn(f"prerelease={prerelease}\n", output)
                self.assertIn(
                    "module_path=github.com/jenic/nginx2root-ioc-scan\n", output
                )

    def test_invalid_tags_fail_before_release_work(self):
        for tag in [
            "1.2.3",
            "v1",
            "v01.2.3",
            "v1.2.3-01",
            "v1.2.3+build",
            "v1.2.3;echo unsafe",
        ]:
            with self.subTest(tag=tag):
                self.run_release("metadata", tag=tag, success=False)

    def test_module_major_version_is_validated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "go.mod").write_text("module github.com/example/scanner\n")
            self.run_release("metadata", tag="v2.0.0", success=False, cwd=root)
            (root / "go.mod").write_text("module github.com/example/scanner/v2\n")
            self.run_release("metadata", tag="v2.0.0", cwd=root)

    def test_asset_set_and_checksums(self):
        with tempfile.TemporaryDirectory() as temporary:
            dist = Path(temporary)
            for name in ARCHIVES:
                (dist / name).write_bytes(name.encode())
            (dist / "SHA256SUMS").write_text(
                "".join(
                    f"{hashlib.sha256(name.encode()).hexdigest()}  {name}\n"
                    for name in ARCHIVES
                )
            )
            self.run_release("check-assets", str(dist))
            (dist / "unexpected").touch()
            self.run_release("check-assets", str(dist), success=False)

    def test_linux_and_windows_packages_are_reproducible(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "scanner"
            binary.write_bytes(b"deterministic test binary\n")
            binary.chmod(0o755)
            outputs = [root / "first", root / "second"]
            for output in outputs:
                for target_os in ["linux", "windows"]:
                    subprocess.run(
                        [
                            "bash",
                            str(PACKAGE),
                            str(binary),
                            target_os,
                            "amd64",
                            "1700000000",
                            str(output),
                        ],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
            for name in ["nginx-ioc-scan_linux_amd64.tar.gz", "nginx-ioc-scan_windows_amd64.zip"]:
                self.assertEqual((outputs[0] / name).read_bytes(), (outputs[1] / name).read_bytes())
            with tarfile.open(outputs[0] / "nginx-ioc-scan_linux_amd64.tar.gz") as archive:
                self.assertEqual(archive.getnames(), ["nginx-ioc-scan"])
            with zipfile.ZipFile(outputs[0] / "nginx-ioc-scan_windows_amd64.zip") as archive:
                self.assertEqual(archive.namelist(), ["nginx-ioc-scan.exe"])

    def test_verified_provenance_requires_exact_subjects(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            names = ["asset", "SHA256SUMS"]
            for name in names:
                (root / name).write_text(name)
            subjects = [
                {
                    "name": name,
                    "digest": {"sha256": hashlib.sha256(name.encode()).hexdigest()},
                }
                for name in names
            ]
            payload = [{
                "verificationResult": {
                    "statement": {
                        "_type": "https://in-toto.io/Statement/v1",
                        "predicateType": "https://slsa.dev/provenance/v1",
                        "subject": subjects,
                    }
                }
            }]
            result = subprocess.run(
                ["python3", "-B", str(PROVENANCE), *names],
                cwd=root,
                input=json.dumps(payload),
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload[0]["verificationResult"]["statement"]["subject"].pop()
            result = subprocess.run(
                ["python3", "-B", str(PROVENANCE), *names],
                cwd=root,
                input=json.dumps(payload),
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
