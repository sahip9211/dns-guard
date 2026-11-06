"""Opt-in native credential integration; uses synthetic data and transient user units.

DNS_GUARD_SYSTEMD_TEST_BINARY=./target/release/dns-guard \
    python3 -m unittest discover -s tests/systemd -v
"""
import hashlib
import json
import os
import pathlib
import re
import socket
import subprocess
import tempfile
import time
import unittest
import uuid


@unittest.skipUnless(os.environ.get('DNS_GUARD_SYSTEMD_TEST_BINARY'),
                     'requires explicit binary and a running systemd user manager')
class Credentials(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='dns-credential-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.binary = str(pathlib.Path(os.environ['DNS_GUARD_SYSTEMD_TEST_BINARY']).resolve(strict=True))
        self.database = self.root / 'settings.sqlite'
        self.index = self.root / 'rules.dngi'
        feed = self.root / 'synthetic.txt'
        feed.write_text('blocked.example\n')
        self.run_command([self.binary, 'compile', str(self.index), '--other-bytes', '1000000',
                          '--feed', 'domains', 'ads', str(feed)])
        for label in ('a', 'b'):
            key = self.root / (label + '.key')
            self.run_command([self.binary, 'config', 'keygen', str(key)])
            if label == 'a':
                self.run_command([self.binary, 'config', 'init', str(self.database), str(self.index),
                                  '--key-file', str(key), '--upstream', '192.0.2.1:53',
                                  '--listen', '127.0.0.1:0'])
            self.run_command(['systemd-creds', 'encrypt', '--user', '--with-key=host',
                              '--no-ask-password', '--name=data-key', str(key),
                              str(self.root / (label + '.cred'))])
            key.unlink()

    def run_command(self, command, check=True):
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if check:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def command(self, credential, args, unit=None):
        unit = unit or 'dns-guard-credential-test-' + uuid.uuid4().hex
        return ['systemd-run', '--user', '--quiet', '--wait', '--pipe', '--collect',
                '--unit', unit, '-p', 'UMask=0077', '-p', 'LimitCORE=0',
                '-p', 'LoadCredentialEncrypted=data-key:' + str(credential), '--', *args]

    def config_command(self):
        return [self.binary, 'config', 'show', str(self.database),
                '--key-file', '${CREDENTIALS_DIRECTORY}/data-key']

    def test_unattended_unlock_and_credential_lifetime(self):
        self.assertFalse(list(self.root.glob('*.key')))
        result = self.run_command(self.command(self.root / 'a.cred', self.config_command()))
        self.assertIn('revision=1', result.stdout)
        # Inspect only metadata, never print or persist delivered secret bytes.
        script = ('import json,os,pathlib; '
                  'p=pathlib.Path(os.environ["CREDENTIALS_DIRECTORY"])/"data-key"; '
                  's=p.stat(); print(json.dumps([str(p),s.st_size,s.st_mode & 511]))')
        result = self.run_command(self.command(self.root / 'a.cred',
                                               ['/usr/bin/python3', '-c', script]))
        path, size, mode = json.loads(result.stdout)
        self.assertEqual(size, 32)
        self.assertEqual(mode & 0o377, 0)  # owner read only, no group/other access
        self.assertFalse(pathlib.Path(path).exists())

    def test_another_instances_credential_cannot_unlock_or_change_database(self):
        before = hashlib.sha256(self.database.read_bytes()).digest()
        result = self.run_command(self.command(self.root / 'b.cred', self.config_command()), check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('revision=1', result.stdout)
        self.assertEqual(hashlib.sha256(self.database.read_bytes()).digest(), before)

    def test_invalid_encrypted_credential_does_not_start_application(self):
        invalid = self.root / 'invalid.cred'
        invalid.write_text('invalid encrypted credential\n')
        result = self.run_command(self.command(invalid, self.config_command()), check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('revision=1', result.stdout)

    def test_dns_serves_after_native_credential_unlock(self):
        unit = 'dns-guard-credential-test-' + uuid.uuid4().hex
        args = [self.binary, 'serve', '--config', str(self.database),
                '--key-file', '${CREDENTIALS_DIRECTORY}/data-key']
        log_path = self.root / 'service.log'
        with log_path.open('w') as log:
            process = subprocess.Popen(self.command(self.root / 'a.cred', args, unit),
                                       stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 10
                match = None
                while time.monotonic() < deadline:
                    match = re.search(r'DNS listening on (127\.0\.0\.1):(\d+)', log_path.read_text())
                    if match or process.poll() is not None:
                        break
                    time.sleep(0.02)
                self.assertIsNotNone(match, log_path.read_text())
                query = (b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                         b'\x07blocked\x07example\x00\x00\x01\x00\x01')
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(2)
                    sock.connect((match[1], int(match[2])))
                    sock.send(query)
                    reply = sock.recv(512)
                self.assertGreaterEqual(len(reply), 12)
                self.assertEqual(reply[:2], query[:2])
                self.assertEqual(reply[3] & 15, 5)  # REFUSED, no upstream request
            finally:
                self.run_command(['systemctl', '--user', 'stop', unit], check=False)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == '__main__':
    unittest.main()
