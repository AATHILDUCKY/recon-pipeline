import sqlite3
import tempfile
import unittest
from pathlib import Path

from recon_pipeline import Database
from webapp import create_app, read_results


class WebApplicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "ADMIN_USERNAME": "admin",
                               "ADMIN_PASSWORD": "correct-password", "CONTROL_DB": str(root / "control.sqlite3"),
                               "LOG_DIR": str(root / "logs"), "RESULTS_DIR": str(root / "results")}, start_worker=False)
        self.client = self.app.test_client()

    def tearDown(self): self.tmp.cleanup()

    def csrf(self):
        self.client.get("/login")
        with self.client.session_transaction() as session: return session["csrf_token"]

    def login(self):
        return self.client.post("/login", data={"csrf_token": self.csrf(), "username": "admin", "password": "correct-password", "next": "/"})

    def test_login_is_required_and_credentials_work(self):
        self.assertEqual(self.client.get("/").status_code, 302)
        response = self.login()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")
        self.assertIn(b"Attack-surface dashboard", self.client.get("/").data)

    def test_invalid_login_is_rejected(self):
        response = self.client.post("/login", data={"csrf_token": self.csrf(), "username": "admin", "password": "wrong"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid username or password", response.data)

    def test_targets_are_normalized_deduplicated_and_queued(self):
        self.login()
        with self.client.session_transaction() as session: token = session["csrf_token"]
        response = self.client.post("/targets", data={"csrf_token": token, "targets": "https://Example.com/a\nexample.com api.example.org",
                                                       "profile": "standard", "authorized": "yes"})
        self.assertEqual(response.status_code, 302)
        with sqlite3.connect(self.app.config["CONTROL_DB"]) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM targets").fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM scans WHERE status='queued'").fetchone()[0], 2)

    def test_authorization_confirmation_and_csrf_are_required(self):
        self.login()
        with self.client.session_transaction() as session: token = session["csrf_token"]
        self.client.post("/targets", data={"csrf_token": token, "targets": "example.com", "profile": "passive"})
        with sqlite3.connect(self.app.config["CONTROL_DB"]) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM targets").fetchone()[0], 0)
        self.assertEqual(self.client.post("/targets", data={"targets": "example.com"}).status_code, 400)

    def test_status_api_does_not_leak_without_login(self):
        self.assertEqual(self.client.get("/api/scans/1").status_code, 302)

    def test_completed_findings_are_read_with_tool_as_source(self):
        result = Path(self.tmp.name) / "results" / "example-run"
        result.mkdir(parents=True)
        database = Database(result / "recon.sqlite3")
        run = database.start("example.com", "standard", {})
        database.execute("""INSERT INTO findings(run_id,tool,severity,template_id,name,matched_at,host,evidence)
                            VALUES(?,?,?,?,?,?,?,?)""",
                         (run, "nuclei", "medium", "x", "Example", "https://example.com/", "example.com", "test"))
        database.conn.commit()
        database.conn.close()
        data = read_results(self.app, str(result))
        self.assertEqual(data["findings"][0]["source"], "nuclei")


if __name__ == "__main__": unittest.main()
