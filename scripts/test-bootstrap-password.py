#!/usr/bin/env python3
"""Exercise the first-install password branch without changing host accounts."""

import os
import pty
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path


BOOTSTRAP = Path(__file__).resolve().parents[1] / "bootstrap.sh"
SOURCE = BOOTSTRAP.read_text()
START = SOURCE.index("ensure_windowops_password() {")
END = SOURCE.index("\n}\n", START) + 2
FUNCTION = SOURCE[START:END]


def run_case(status="L", *, tty=False, key=False, installed=False, fail_set=False):
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        status_file = root / "status"
        calls_file = root / "calls"
        binary = root / "window"
        keys = root / "authorized_keys"
        status_file.write_text(status)
        if key:
            keys.write_text("ssh-ed25519 test-key\n")
        if installed:
            binary.write_text("#!/bin/sh\n")
            binary.chmod(0o700)
        script = f"""set -eu
state_file={shlex.quote(str(status_file))}
calls_file={shlex.quote(str(calls_file))}
passwd() {{
  if [ "$1" = -S ]; then printf 'windowops %s 2026-10-02 0 99999 7 -1\\n' "$(cat "$state_file")"; return; fi
  printf 'called\\n' >> "$calls_file"
  [ -t 0 ] || return 20
  read -r first
  read -r second
  [ "$first" = "$second" ] || return 21
  {'return 22' if fail_set else 'printf P > "$state_file"'}
}}
{FUNCTION}
ensure_windowops_password {shlex.quote(str(binary))} {shlex.quote(str(keys))}
"""
        if tty:
            pid, fd = pty.fork()
            if pid == 0:
                os.execl("/bin/sh", "sh", "-c", script)
            os.write(fd, b"example-password\nexample-password\n")
            output = bytearray()
            while True:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                output.extend(chunk)
            os.close(fd)
            _, raw_status = os.waitpid(pid, 0)
            code = os.waitstatus_to_exitcode(raw_status)
            message = output.decode(errors="replace")
        else:
            result = subprocess.run(["/bin/sh", "-c", script], stdin=subprocess.DEVNULL,
                                    capture_output=True, text=True, check=False,
                                    start_new_session=True, timeout=5)
            code = result.returncode
            message = result.stdout + result.stderr
        return code, status_file.read_text(), calls_file.read_text() if calls_file.exists() else "", message


class BootstrapPasswordTests(unittest.TestCase):
    def test_password_gate_precedes_window_install(self):
        gate = SOURCE.index("\nensure_windowops_password /usr/local/bin/window /home/windowops/.ssh/authorized_keys")
        install = SOURCE.index("\n/usr/bin/updater window install --version")
        self.assertLess(gate, install)

    def test_new_locked_account_prompts_and_sets_password(self):
        code, status, calls, output = run_case(tty=True)
        self.assertEqual((code, status, calls), (0, "P", "called\n"), output)

    def test_passwordless_account_prompts(self):
        code, status, calls, output = run_case(status="NP", tty=True)
        self.assertEqual((code, status, calls), (0, "P", "called\n"), output)

    def test_existing_password_does_not_prompt(self):
        code, status, calls, output = run_case(status="P")
        self.assertEqual((code, status, calls), (0, "P", ""), output)

    def test_existing_key_does_not_prompt(self):
        code, status, calls, output = run_case(key=True)
        self.assertEqual((code, status, calls), (0, "L", ""), output)

    def test_upgrade_does_not_prompt(self):
        code, status, calls, output = run_case(installed=True)
        self.assertEqual((code, status, calls), (0, "L", ""), output)

    def test_unattended_install_stops_before_password_change(self):
        code, status, calls, output = run_case()
        self.assertNotEqual(code, 0)
        self.assertEqual((status, calls), ("L", ""))
        self.assertIn("interactive terminal", output)

    def test_failed_password_change_stops_install(self):
        code, status, calls, output = run_case(tty=True, fail_set=True)
        self.assertNotEqual(code, 0)
        self.assertEqual((status, calls), ("L", "called\n"))
        self.assertIn("password setup failed", output)

    def test_unknown_password_state_stops_install(self):
        code, status, calls, output = run_case(status="unexpected")
        self.assertNotEqual(code, 0)
        self.assertEqual((status, calls), ("unexpected", ""))
        self.assertIn("Cannot determine", output)


if __name__ == "__main__":
    unittest.main()
