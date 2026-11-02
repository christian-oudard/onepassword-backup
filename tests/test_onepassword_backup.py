"""Tests for onepassword-backup. Run: python3 -m unittest"""

import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parent.parent / "onepassword-backup"
loader = importlib.machinery.SourceFileLoader("onepassword_backup", str(SCRIPT))
spec = importlib.util.spec_from_loader("onepassword_backup", loader)
assert spec
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)

VAULT = {"id": "vault1", "name": "Personal"}


def item(**over):
    base = {
        "id": "item1",
        "title": "Example Site",
        "category": "LOGIN",
        "vault": VAULT,
        "created_at": "2024-01-02T03:04:05Z",
        "updated_at": "2025-06-07T08:09:10Z",
        "fields": [],
    }
    base.update(over)
    return base


def field(id, value, type="STRING", **over):
    f = {"id": id, "type": type, "label": id, "value": value}
    f.update(over)
    return f


class ConvertItem(unittest.TestCase):
    def test_login(self):
        out = mod.convert_item(
            item(
                favorite=True,
                tags=["work"],
                urls=[
                    {"label": "website", "href": "https://a.test/"},
                    {"label": "", "primary": True, "href": "https://b.test/"},
                ],
                fields=[
                    field("username", "fake-user", purpose="USERNAME"),
                    field("password", "fake-pass", "CONCEALED", purpose="PASSWORD"),
                    field("notesPlain", "a note", purpose="NOTES"),
                ],
            )
        )
        self.assertEqual(out["uuid"], "item1")
        self.assertEqual(out["categoryUuid"], "001")
        self.assertEqual(out["favIndex"], 1)
        self.assertEqual(out["state"], "active")
        self.assertEqual(out["createdAt"], 1704164645)
        self.assertEqual(out["overview"]["title"], "Example Site")
        self.assertEqual(out["overview"]["subtitle"], "fake-user")
        self.assertEqual(out["overview"]["url"], "https://b.test/")
        self.assertEqual(out["overview"]["tags"], ["work"])
        self.assertEqual(
            [(f["designation"], f["value"]) for f in out["details"]["loginFields"]],
            [("username", "fake-user"), ("password", "fake-pass")],
        )
        self.assertEqual(out["details"]["notesPlain"], "a note")
        self.assertEqual(out["details"]["sections"], [])

    def test_login_fields_keep_their_labels(self):
        out = mod.convert_item(
            item(
                fields=[
                    field("username", "a@b.test", label="email", purpose="USERNAME"),
                    field("password", "pw", "CONCEALED", label="master-password", purpose="PASSWORD"),
                ]
            )
        )
        self.assertEqual(
            [(f["designation"], f["name"]) for f in out["details"]["loginFields"]],
            [("username", "email"), ("password", "master-password")],
        )

    def test_password_category(self):
        out = mod.convert_item(
            item(category="PASSWORD", fields=[field("password", "pw", "CONCEALED", purpose="PASSWORD")])
        )
        self.assertEqual(out["categoryUuid"], "005")
        self.assertEqual(out["details"]["password"], "pw")

    def test_purpose_fields_of_other_categories_stay_in_sections(self):
        out = mod.convert_item(
            item(category="WIRELESS_ROUTER", fields=[field("password", "pw", "CONCEALED", purpose="PASSWORD")])
        )
        self.assertNotIn("password", out["details"])
        [section] = out["details"]["sections"]
        self.assertEqual(section["fields"][0]["value"], {"concealed": "pw"})

    def test_every_category_in_the_account_has_a_code(self):
        document = [{"id": "file1", "name": "scan.pdf", "size": 3}]
        for category in [
            "API_CREDENTIAL", "CREDIT_CARD", "DOCUMENT", "IDENTITY",
            "LOGIN", "PASSWORD", "SECURE_NOTE", "WIRELESS_ROUTER",
        ]:
            mod.convert_item(item(category=category, files=document if category == "DOCUMENT" else []))

    def test_unknown_category_fails(self):
        with self.assertRaises(KeyError):
            mod.convert_item(item(category="NEW_THING"))

    def test_custom_category_uses_op_category_id(self):
        out = mod.convert_item(item(category="CUSTOM", category_id="115"))
        self.assertEqual(out["categoryUuid"], "115")

    def test_field_without_label_gets_empty_title(self):
        unlabeled = field("tip", "text")
        del unlabeled["label"]
        [section] = mod.convert_item(item(category="IDENTITY", fields=[unlabeled]))["details"]["sections"]
        self.assertEqual(section["fields"][0]["title"], "")

    def test_archived(self):
        self.assertEqual(mod.convert_item(item(state="ARCHIVED"))["state"], "archived")

    def test_fields_grouped_into_sections_in_order(self):
        out = mod.convert_item(
            item(
                category="API_CREDENTIAL",
                sections=[{"id": "s1", "label": "Extra"}],
                fields=[
                    field("credential", "key", "CONCEALED"),
                    field("pin", "1234", "CONCEALED", section={"id": "s1", "label": "Extra"}),
                    field("hostname", "api.test"),
                    field("blank", ""),
                ],
            )
        )
        sections = out["details"]["sections"]
        self.assertEqual([(s["name"], s["title"]) for s in sections], [("", ""), ("s1", "Extra")])
        self.assertEqual(
            [(f["id"], f["value"]) for f in sections[0]["fields"]],
            [("credential", {"concealed": "key"}), ("hostname", {"string": "api.test"}), ("blank", {"string": ""})],
        )
        self.assertFalse(sections[0]["fields"][0]["guarded"])
        self.assertEqual(
            sorted(sections[0]["fields"][0]),
            ["dontGenerate", "guarded", "id", "inputTraits", "multiline", "title", "value"],
        )

    def test_ssh_key_metadata_goes_into_the_private_key_value(self):
        out = mod.convert_item(
            item(
                category="SSH_KEY",
                fields=[
                    field("public_key", "ssh-ed25519 AAAA"),
                    field("fingerprint", "SHA256:abc"),
                    field("private_key", "-----BEGIN PRIVATE KEY-----", "SSHKEY"),
                    field("key_type", "ed25519"),
                ],
            )
        )
        [section] = out["details"]["sections"]
        [private_key] = section["fields"]
        self.assertTrue(private_key["guarded"])
        self.assertEqual(
            private_key["value"],
            {
                "sshKey": {
                    "privateKey": "-----BEGIN PRIVATE KEY-----",
                    "metadata": {
                        "privateKey": "-----BEGIN PRIVATE KEY-----",
                        "publicKey": "ssh-ed25519 AAAA",
                        "fingerprint": "SHA256:abc",
                        "keyType": "ed25519",
                    },
                }
            },
        )

    def test_timestamps_round_to_the_nearest_second(self):
        out = mod.convert_item(item(created_at="2024-01-02T03:04:05.6Z", updated_at="2024-01-02T03:04:05.4Z"))
        self.assertEqual((out["createdAt"], out["updatedAt"]), (1704164646, 1704164645))

    def test_value_types(self):
        cases = [
            ("CONCEALED", "x", {"concealed": "x"}),
            ("OTP", "otpauth://totp/a?secret=FAKE", {"totp": "otpauth://totp/a?secret=FAKE"}),
            ("URL", "https://a.test/", {"url": "https://a.test/"}),
            ("EMAIL", "a@b.test", {"email": {"email_address": "a@b.test", "provider": None}}),
            ("PHONE", "555", {"phone": "555"}),
            ("MENU", "WPA2", {"menu": "WPA2"}),
            ("CREDIT_CARD_NUMBER", "4111", {"creditCardNumber": "4111"}),
            ("CREDIT_CARD_TYPE", "visa", {"creditCardType": "visa"}),
            ("MONTH_YEAR", "202701", {"monthYear": 202701}),
            ("MONTH_YEAR", "01/2027", {"monthYear": 202701}),
            ("DATE", "1704164645", {"date": 1704164645}),
            ("DATE", "2024-01-02", {"date": 1704153600}),
            ("REFERENCE", "item2", {"reference": "item2"}),
            ("STRING", "plain", {"string": "plain"}),
        ]
        for kind, value, want in cases:
            with self.subTest(kind=kind, value=value):
                self.assertEqual(mod.field_value(field("f", value, kind)), want)

    def test_empty_values(self):
        cases = [
            ("STRING", {"string": ""}),
            ("CONCEALED", {"concealed": ""}),
            ("PHONE", {"phone": ""}),
            ("DATE", {"date": None}),
            ("MONTH_YEAR", {"monthYear": None}),
            ("EMAIL", {"email": {"email_address": "", "provider": None}}),
            ("ADDRESS", {"address": {"street": "", "city": "", "country": "", "zip": "", "state": ""}}),
        ]
        for kind, want in cases:
            with self.subTest(kind=kind):
                empty = field("f", None, kind)
                del empty["value"]
                self.assertEqual(mod.field_value(empty), want)

    def test_empty_notes(self):
        notes = field("notesPlain", None, purpose="NOTES")
        del notes["value"]
        out = mod.convert_item(item(fields=[notes]))
        self.assertEqual(out["details"]["notesPlain"], "")
        self.assertEqual(out["details"]["sections"], [])

    def test_empty_unknown_field_is_skipped(self):
        # op reports "Sign in with" records this way, without their contents.
        sign_in_with = field("f1", None, "UNKNOWN", label="sign in with", section={"id": "s1", "label": "Saved on a.test"})
        del sign_in_with["value"]
        self.assertEqual(mod.convert_item(item(fields=[sign_in_with]))["details"]["sections"], [])

    def test_unknown_field_with_a_value_fails(self):
        with self.assertRaises(KeyError):
            mod.convert_item(item(fields=[field("f1", "data", "UNKNOWN")]))

    def test_unknown_field_type_fails(self):
        with self.assertRaises(KeyError):
            mod.field_value(field("f", "x", "NEW_TYPE"))

    def test_document(self):
        out = mod.convert_item(
            item(category="DOCUMENT", files=[{"id": "file1", "name": "scan.pdf", "size": 3}])
        )
        self.assertEqual(out["categoryUuid"], "006")
        self.assertEqual(
            out["details"]["documentAttributes"],
            {"fileName": "scan.pdf", "documentId": "file1", "decryptedSize": 3},
        )

    def test_attachment_becomes_a_file_field_in_its_section(self):
        out = mod.convert_item(
            item(files=[{"id": "file1", "name": "a.txt", "size": 2, "section": {"id": "s1"}}],
                 sections=[{"id": "s1", "label": "Files"}])
        )
        [section] = out["details"]["sections"]
        self.assertEqual((section["name"], section["title"]), ("s1", "Files"))
        self.assertEqual(
            section["fields"][0]["value"],
            {"file": {"fileName": "a.txt", "documentId": "file1", "decryptedSize": 2}},
        )


class Build(unittest.TestCase):
    def test_groups_items_by_vault(self):
        other = {"id": "vault2", "name": "Shared"}
        data = mod.build([item(id="a"), item(id="b", vault=other), item(id="c")])
        [account] = data["accounts"]
        vaults = [(v["attrs"]["uuid"], v["attrs"]["name"], [i["uuid"] for i in v["items"]]) for v in account["vaults"]]
        self.assertEqual(vaults, [("vault1", "Personal", ["a", "c"]), ("vault2", "Shared", ["b"])])

    def test_read_items_accepts_concatenated_objects(self):
        text = json.dumps(item(id="a")) + json.dumps(item(id="b")) + "\n" + json.dumps(item(id="c"), indent=2)
        self.assertEqual([i["id"] for i in mod.read_items(text.splitlines(keepends=True))], ["a", "b", "c"])

    def test_read_items_yields_each_item_once_its_lines_arrive(self):
        lines = iter(json.dumps(item(id="a"), indent=2).splitlines(keepends=True) + ["{\n"])
        self.assertEqual(next(mod.read_items(lines))["id"], "a")

    def test_read_items_fails_on_truncated_output(self):
        with self.assertRaises(json.JSONDecodeError):
            list(mod.read_items(['{"id": "a"}\n', '{"id":\n']))


class Write(unittest.TestCase):
    def test_archive_layout_and_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.1pux"
            mod.write_1pux(path, {"accounts": []}, {"file1": ("a b.txt", b"hi")})
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            with zipfile.ZipFile(path) as archive:
                self.assertEqual(
                    sorted(archive.namelist()),
                    ["export.attributes", "export.data", "files/file1__a b.txt"],
                )
                self.assertEqual(json.loads(archive.read("export.data")), {"accounts": []})
                self.assertEqual(archive.read("files/file1__a b.txt"), b"hi")
                attributes = json.loads(archive.read("export.attributes"))
                self.assertEqual(sorted(attributes), ["description", "timestamp", "version"])
                self.assertEqual(attributes["version"], 3)

    def test_refuses_to_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.1pux"
            path.write_bytes(b"")
            with self.assertRaises(FileExistsError):
                mod.write_1pux(path, {"accounts": []}, {})


def fake_op_path(directory, script):
    """Write a shell script named op into directory and return a PATH that finds it first."""
    fake_op = Path(directory) / "op"
    fake_op.write_text("#!/bin/sh\n" + script)
    fake_op.chmod(0o755)
    return f"{directory}:{os.environ['PATH']}"


class OpLines(unittest.TestCase):
    def test_streams_large_input_through(self):
        # More than a pipe buffer each way: without the stdin thread this hangs.
        data = b"".join(b"%06d" % n + b"x" * 100 + b"\n" for n in range(20000))
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, PATH=fake_op_path(tmp, "exec cat\n")):
            self.assertEqual("".join(mod.op_lines("item", input=data)).encode(), data)

    def test_failure_raises(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, PATH=fake_op_path(tmp, "exit 3\n")):
            with self.assertRaises(subprocess.CalledProcessError):
                list(mod.op_lines("item", input=b""))


class Terminal(io.StringIO):
    def isatty(self):
        return True


class Main(unittest.TestCase):
    def assert_rejected_before_export(self, path):
        with mock.patch.object(mod, "op") as op, self.assertRaises(SystemExit):
            mod.main(str(path))
        op.assert_not_called()

    def test_rejects_name_without_1pux_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assert_rejected_before_export(Path(tmp) / "backup.zip")

    def test_rejects_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "backup.1pux"
            path.write_bytes(b"")
            self.assert_rejected_before_export(path)

    def test_exports_items_and_files(self):
        listing = b'[{"id": "item1"}, {"id": "doc1"}]'
        login = item(files=[{"id": "att1", "name": "key.txt", "size": 3}])
        document = item(id="doc1", category="DOCUMENT", files=[{"id": "file1", "name": "scan.pdf", "size": 4}])
        contents = {"op://vault1/item1/att1": b"key", "op://vault1/doc1/file1": b"scan"}

        def op(*args, input=None):
            if args[:2] == ("item", "list"):
                return listing
            self.assertEqual(args[:3], ("read", "--no-newline", "--force"))
            return contents[args[3]]

        def op_lines(*args, input):
            self.assertEqual(args, ("item", "get", "-", "--format=json"))
            self.assertEqual(input, listing)
            return [json.dumps(login) + "\n", json.dumps(document) + "\n"]

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "backup.1pux"
            out, err = io.StringIO(), Terminal()
            with (
                mock.patch.object(mod, "op", op),
                mock.patch.object(mod, "op_lines", op_lines),
                contextlib.redirect_stdout(out),
                contextlib.redirect_stderr(err),
            ):
                mod.main(str(path))
            with zipfile.ZipFile(path) as archive:
                self.assertEqual(archive.read("files/att1__key.txt"), b"key")
                self.assertEqual(archive.read("files/file1__scan.pdf"), b"scan")
                data = json.loads(archive.read("export.data"))
        [vault] = data["accounts"][0]["vaults"]
        self.assertEqual([i["uuid"] for i in vault["items"]], ["item1", "doc1"])
        self.assertEqual(out.getvalue().split("\n"), ["    1 DOCUMENT", "    1 LOGIN", "    2 files", ""])
        self.assertEqual(err.getvalue(), "\ritems 1/2\ritems 2/2\n\rfiles 1/2\rfiles 2/2\n")

    def test_names_the_file_like_the_desktop_app(self):
        def op(*args, input=None):
            if args == ("whoami", "--format=json"):
                return b'{"account_uuid": "ACCT1", "user_uuid": "USER1"}'
            self.assertEqual(args[:2], ("item", "list"))
            return b"[]"

        with tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp):
            with (
                mock.patch.object(mod, "op", op),
                mock.patch.object(mod, "op_lines", lambda *args, input: []),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                mod.main()
            [name] = os.listdir()
        self.assertRegex(name, r"^1PasswordExport-ACCT1-\d{8}-\d{6}\.1pux$")

    def test_shows_op_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {**os.environ, "PATH": fake_op_path(tmp, "echo 'not signed in' >&2\nexit 1\n")}
            result = subprocess.run(
                [sys.executable, SCRIPT, str(Path(tmp) / "backup.1pux")], env=env, capture_output=True, text=True
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not signed in", result.stderr)


if __name__ == "__main__":
    unittest.main()
