import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rich.console import Console

from wpscan_view.cli import main, write_new
from wpscan_view.model import clean, normalize, read_json, scope
from wpscan_view.render import terminal, webpage

ROOT = Path(__file__).resolve().parents[1]


class ReportTests(unittest.TestCase):
    def fixture(self, name="enumeration"):
        return json.loads((ROOT / "examples" / (name + ".json")).read_text())

    def test_scope_variants(self):
        for arg in ("-e vp,vt,u1-5", "--enumerate vp,vt,u1-5", "--enumerate=vp,vt,u1-5", "-evp,vt,u1-5"):
            result = scope("wpscan --url https://example.test " + arg)
            self.assertEqual([c["code"] for c in result["choices"]], ["vp", "vt", "u1-5"])
        self.assertEqual(scope("wpscan --enumerate --format json")["choices"], [])
        self.assertIn("version", scope("wpscan -e")["evidence"])
        self.assertEqual(scope(None)["kind"], "Unknown")
        self.assertTrue(scope("wpscan --url https://example.test")["kind"].startswith("Standard"))
        self.assertTrue(scope("wpscan -- --enumerate=ap")["kind"].startswith("Standard"))
        self.assertTrue(scope('wpscan --user-agent "-evp" --url https://example.test')["kind"].startswith("Standard"))

    def test_data_gaps_are_not_clean_results(self):
        report = normalize(self.fixture("standard"))
        self.assertTrue(report["warnings"])
        self.assertEqual(report["components"][0]["status"], "Data gap")
        raw = self.fixture()
        raw.pop("command_line")
        self.assertEqual(normalize(raw)["scope"]["kind"], "Unknown")
        raw["scan_aborted"] = "timeout"
        self.assertIn("aborted", normalize(raw)["warnings"][0])

    def test_inventory_deduplicates_active_theme_and_preserves_evidence(self):
        report = normalize(self.fixture())
        self.assertEqual(len([c for c in report["components"] if c["kind"] == "Theme"]), 1)
        theme = next(c for c in report["components"] if c["kind"] == "Theme")
        self.assertIn("enumeration_evidence", theme["evidence"])
        self.assertEqual(report["components"][0]["name"], "example-contact-form")

    def test_hostile_text_and_credentials(self):
        raw = self.fixture()
        raw["target_url"] = "<script>alert(1)</script>"
        raw["effective_url"] = raw["target_url"]
        raw["users"]["alice"]["password"] = "DO-NOT-PRINT"
        raw["command_line"] += " --api-token DO-NOT-PRINT"
        raw["plugins"]["example-cache"]["found_by"] = "[red]markup[/red]\x1b[31m\u202etext"
        report = normalize(raw)
        serialized = json.dumps(report)
        self.assertNotIn("DO-NOT-PRINT", serialized)
        self.assertNotIn("\x1b", clean(raw["plugins"]["example-cache"]["found_by"]))
        page = webpage(report)
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)
        stream = io.StringIO()
        terminal(report, Console(file=stream, width=100, no_color=True))
        self.assertNotIn("DO-NOT-PRINT", stream.getvalue())

    def test_parse_and_output_failures(self):
        with self.assertRaises(ValueError):
            read_json(io.BytesIO(b"[+] plain WPScan output"))
        with self.assertRaises(ValueError):
            read_json(io.BytesIO(b"{}"))
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "report.html"
            write_new(file, "original")
            with self.assertRaises(FileExistsError):
                write_new(file, "replacement")
            self.assertEqual(file.read_text(), "original")

    def test_cli_file(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(main([str(ROOT / "examples/enumeration.json"), "--html", str(Path(directory) / "report.html"), "--no-color"]), 0)
            self.assertTrue((Path(directory) / "report.html").is_file())

    def test_wrapper_preserves_choices_and_failure_exit(self):
        raw = self.fixture()

        def fake_run(args, stdout, stderr, check):
            self.assertEqual(args[-2:], ["--format", "json"])
            self.assertIn("vp,vt", args)
            stdout.write(json.dumps(raw).encode())
            return type("Process", (), {"returncode": 7})()

        with patch("wpscan_view.cli.subprocess.run", side_effect=fake_run):
            self.assertEqual(main(["scan", "--no-color", "--", "--url", "https://example.test", "-e", "vp,vt"]), 7)


if __name__ == "__main__":
    unittest.main()
