"""Offline adapter tests. No CLI process, keyring, or Apple account is used."""

import json
import subprocess
import unittest
from unittest.mock import patch

import server


class AuthInputTests(unittest.TestCase):
    def setUp(self):
        self.server = server.Server.__new__(server.Server)
        self.server.binary = "synthetic-icli"
        self.server.timeout = 1
        self.server.paths = {
            "icli": (),
            "icli_auth": ("auth",),
            **{"icli_auth_" + name.replace("-", "_"): ("auth", name)
               for name in ("add", "verify", "check", "refresh", "app-password", "apple-login")},
        }

    @patch("server.subprocess.run")
    def test_passwords_use_stdin_for_both_credential_types(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, '{"ok": true}', "")
        for name in ("icli_auth_add", "icli_auth_app_password", "icli_auth_apple_login"):
            result = self.server.call({"name": name, "arguments": {"args": ["synthetic@example.invalid"], "password": "synthetic-secret"}})
            self.assertFalse(result["isError"])
            argv = run.call_args.args[0]
            self.assertNotIn("synthetic-secret", argv)
            self.assertIn("--password-stdin", argv)
            self.assertEqual(run.call_args.kwargs["input"], "synthetic-secret")

    @patch("server.subprocess.run")
    def test_verification_code_uses_stdin_and_is_redacted_for_group_calls(self, run):
        run.return_value = subprocess.CompletedProcess([], 1, "", '{"message": "synthetic 012345"}')
        result = self.server.call({"name": "icli", "arguments": {"args": ["auth", "verify", "synthetic@example.invalid"], "code": "012345"}})
        self.assertTrue(result["isError"])
        self.assertIn("--code-stdin", run.call_args.args[0])
        self.assertNotIn("012345", run.call_args.args[0])
        self.assertEqual(run.call_args.kwargs["input"], "012345")
        self.assertNotIn("012345", json.dumps(result))
        self.assertIn("[REDACTED]", json.dumps(result))

    @patch("server.subprocess.run")
    def test_positional_and_flag_secrets_are_rejected_before_starting_cli(self, run):
        for args in (
            ["add", "synthetic@example.invalid", "synthetic-secret"],
            ["app-password", "--email", "synthetic@example.invalid", "--password=synthetic"],
            ["verify", "synthetic@example.invalid", "012345"],
            ["verify", "--email", "synthetic@example.invalid", "--code", "012345"],
        ):
            result = self.server.call({"name": "icli_auth", "arguments": {"args": args}})
            self.assertTrue(result["isError"])
        run.assert_not_called()

    @patch("server.subprocess.run")
    def test_check_password_requires_explicit_app_password_mode(self, run):
        result = self.server.call({"name": "icli_auth_check", "arguments": {"password": "synthetic"}})
        self.assertTrue(result["isError"])
        run.assert_not_called()
        run.return_value = subprocess.CompletedProcess([], 0, '{"ok": true}', "")
        result = self.server.call({"name": "icli_auth_check", "arguments": {"args": ["--app-password"], "password": "synthetic"}})
        self.assertFalse(result["isError"])
        self.assertEqual(run.call_args.kwargs["input"], "synthetic")

    @patch("server.subprocess.run")
    def test_stdin_flags_need_the_matching_secret_input(self, run):
        for command, flag in (("add", "--password-stdin"), ("verify", "--code-stdin")):
            result = self.server.call({"name": "icli_auth", "arguments": {"args": [command, "synthetic@example.invalid", flag]}})
            self.assertTrue(result["isError"])
        run.assert_not_called()

    def test_secrets_cannot_be_combined_or_attached_to_other_commands(self):
        with self.assertRaises(server.RpcError):
            self.server.call({"name": "icli_auth_add", "arguments": {"password": "synthetic", "code": "012345"}})
        result = self.server.call({"name": "icli_auth_refresh", "arguments": {"code": "012345"}})
        self.assertTrue(result["isError"])


if __name__ == "__main__":
    unittest.main()
