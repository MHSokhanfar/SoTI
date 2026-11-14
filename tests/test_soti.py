"""Unit tests for SoTI Python CLI.

Created and developed by Mohammad Hossein Sokhanfar.
Repository: https://github.com/MHSokhanfar/SoTI
"""
import csv
import tempfile
import unittest
from pathlib import Path

from api import abuseipdb, alienvault, clean_indicator, detect_indicator_type, virustotal
from config import scheduler
from main import investigate, save_csv


class TestIndicatorParsing(unittest.TestCase):
    def test_refang_defanged_indicators(self):
        self.assertEqual(clean_indicator("1[.]2[.]3[.]4"), "1.2.3.4")
        self.assertEqual(clean_indicator("1(.)2(.)3(.)4"), "1.2.3.4")
        self.assertEqual(clean_indicator("hxxp://evil[.]com"), "evil.com")
        self.assertEqual(clean_indicator("hxxps://sub[.]evil[.]com/login?id=1"), "sub.evil.com")
        self.assertEqual(clean_indicator("evil[dot]org[:]8443/path"), "evil.org")

    def test_detect_indicator_type(self):
        self.assertEqual(detect_indicator_type("8.8.8.8"), "ip")
        self.assertEqual(detect_indicator_type("2001:4860:4860::8888"), "ip")
        self.assertEqual(detect_indicator_type("example.com"), "domain")
        self.assertEqual(detect_indicator_type("44d88612fea8a8f36de82e1278abb02f"), "hash")  # MD5
        self.assertEqual(detect_indicator_type("356a192b7913b04c54574d18c28d46e6395428ab"), "hash")  # SHA1
        self.assertEqual(
            detect_indicator_type("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"),
            "hash",
        )  # SHA256
        self.assertIsNone(detect_indicator_type("not-an-ioc"))


class TestProviderParsers(unittest.TestCase):
    def test_virustotal_verdicts(self):
        mal = virustotal.parse_response("1.2.3.4", "ip", {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 6, "suspicious": 0, "harmless": 70}}}
        })
        self.assertEqual(mal["verdict"], "Malicious")
        self.assertEqual(mal["score"], "6/76")

        sus = virustotal.parse_response("evil.com", "domain", {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 80}}}
        })
        self.assertEqual(sus["verdict"], "Suspicious")

        clean = virustotal.parse_response("8.8.8.8", "ip", {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 85}}}
        })
        self.assertEqual(clean["verdict"], "Clean")

    def test_abuseipdb_verdicts_and_unsupported(self):
        res_domain = abuseipdb.lookup("example.com", "domain")
        self.assertEqual(res_domain["status"], "unsupported")

        mal = abuseipdb.parse_response("1.2.3.4", "ip", {
            "data": {"abuseConfidenceScore": 82, "totalReports": 12}
        })
        self.assertEqual(mal["verdict"], "Malicious")
        self.assertEqual(mal["score"], "82%")

    def test_alienvault_verdicts(self):
        unk = alienvault.parse_response("8.8.8.8", "ip", {"pulse_info": {"count": 0, "pulses": []}})
        self.assertEqual(unk["verdict"], "Unknown")

        mal = alienvault.parse_response("1.2.3.4", "ip", {"pulse_info": {"count": 5, "pulses": []}})
        self.assertEqual(mal["verdict"], "Malicious")


class TestCsvAndBatch(unittest.TestCase):
    def test_save_csv_writes_utf8_sig(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = [virustotal.parse_response("8.8.8.8", "ip", {
                "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 50}}}
            })]
            path = save_csv(sample, reports_dir=Path(tmp))
            self.assertTrue(path.exists())
            with open(path, "r", encoding="utf-8-sig", newline="") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["indicator"], "8.8.8.8")
            self.assertEqual(rows[0]["verdict"], "Clean")

    def test_investigate_demo_batch(self):
        results, csv_path = investigate(
            "1[.]2[.]3[.]4, hxxp://evil[.]com, 44d88612fea8a8f36de82e1278abb02f, invalid_ioc",
            [virustotal, abuseipdb, alienvault],
            demo=True,
            quiet=True,
        )
        # 3 valid indicators * 3 sources = 9 rows
        self.assertEqual(len(results), 9)
        self.assertIsNotNone(csv_path)
        self.assertTrue(csv_path.exists())


class TestSchedulerModule(unittest.TestCase):
    def test_add_toggle_execute_and_remove_schedule(self):
        from datetime import datetime, timedelta, timezone

        with tempfile.TemporaryDirectory() as tmp:
            sched_file = Path(tmp) / "schedules.json"
            job = scheduler.add_schedule(
                name="Unit Watchlist",
                indicators="8.8.8.8, evil.com",
                source="all",
                interval_minutes=30,
                mode="sample",
                schedules_file=sched_file,
            )
            self.assertEqual(job["name"], "Unit Watchlist")
            self.assertEqual(job["indicators"], ["8.8.8.8", "evil.com"])
            self.assertEqual(len(scheduler.load_schedules(sched_file)), 1)

            # Future timestamp is not due; past-shifted now is due
            future = datetime.now(timezone.utc) + timedelta(minutes=45)
            executed = scheduler.run_due_schedules(
                lambda j: ([{"status": "ok", "verdict": "Clean"}], "soti_test.csv"),
                now=future,
                schedules_file=sched_file,
            )
            self.assertEqual(len(executed), 1)
            self.assertEqual(executed[0]["runCount"], 1)
            self.assertEqual(executed[0]["lastStatus"], "success")
            self.assertEqual(executed[0]["lastReportFile"], "soti_test.csv")

            toggled = scheduler.toggle_schedule(job["id"], enabled=False, schedules_file=sched_file)
            self.assertIsNotNone(toggled)
            self.assertFalse(toggled["enabled"])

            self.assertTrue(scheduler.remove_schedule(job["id"], schedules_file=sched_file))
            self.assertEqual(scheduler.load_schedules(sched_file), [])


if __name__ == "__main__":
    unittest.main()

