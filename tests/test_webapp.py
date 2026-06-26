import sqlite3
import tempfile
import unittest
from pathlib import Path

from recon_pipeline import Database
from webapp import create_app, markdown_cell, read_results


class WebApplicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "ADMIN_USERNAME": "admin",
                               "ADMIN_PASSWORD": "correct-password", "CONTROL_DB": str(root / "control.sqlite3"),
                               "LOG_DIR": str(root / "logs"), "RESULTS_DIR": str(root / "results"),
                               "SCOPE_UPLOAD_DIR": str(root / "scope-uploads")}, start_worker=False)
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
                                                       "project_name": "ACME deep analysis", "profile": "standard", "authorized": "yes"})
        self.assertEqual(response.status_code, 302)
        with sqlite3.connect(self.app.config["CONTROL_DB"]) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM targets").fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM scans WHERE status='queued'").fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM projects WHERE name='ACME deep analysis'").fetchone()[0], 1)

    def test_scope_only_hosts_are_queued_as_independent_scans(self):
        self.login()
        with self.client.session_transaction() as session: token = session["csrf_token"]
        response = self.client.post("/targets", data={"csrf_token": token, "targets": "",
                                                       "scope_subdomains": "api.example.com\ncdn.example.com",
                                                       "profile": "standard", "authorized": "yes"})
        self.assertEqual(response.status_code, 302)
        with sqlite3.connect(self.app.config["CONTROL_DB"]) as db:
            domains = [row[0] for row in db.execute("SELECT domain FROM targets ORDER BY domain")]
            scopes = [row[0] for row in db.execute("SELECT scope_subdomains FROM scans ORDER BY scope_subdomains")]
            self.assertEqual(domains, ["api.example.com", "cdn.example.com"])
            self.assertEqual(scopes, ["api.example.com", "cdn.example.com"])

    def test_large_scope_list_can_be_uploaded_in_chunks_before_queueing(self):
        self.login()
        with self.client.session_transaction() as session: token = session["csrf_token"]
        first = self.client.post("/api/scope-upload", data={"csrf_token": token, "chunk": "api.example.com\n"})
        self.assertEqual(first.status_code, 200)
        upload_id = first.get_json()["upload_id"]
        second = self.client.post("/api/scope-upload", data={"csrf_token": token, "upload_id": upload_id, "chunk": "cdn.example.com\n"})
        self.assertEqual(second.status_code, 200)
        response = self.client.post("/targets", data={"csrf_token": token, "targets": "", "scope_upload_id": upload_id,
                                                       "profile": "passive", "authorized": "yes"})
        self.assertEqual(response.status_code, 302)
        self.assertFalse((Path(self.app.config["SCOPE_UPLOAD_DIR"]) / f"{upload_id}.txt").exists())
        with sqlite3.connect(self.app.config["CONTROL_DB"]) as db:
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

    def test_live_event_stream_is_authenticated_and_emits_workspace_state(self):
        self.assertEqual(self.client.get("/api/events").status_code, 302)
        self.login()
        response = self.client.get("/api/events", buffered=False)
        first_event = next(response.response)
        response.close()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/event-stream")
        self.assertIn(b"event: workspace", first_event)
        self.assertIn(b'"totals"', first_event)

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

    def test_technology_stacks_are_grouped_by_subdomain_and_rendered_in_target_tab(self):
        result = Path(self.app.config["RESULTS_DIR"]) / "technology-run"
        result.mkdir(parents=True)
        database = Database(result / "recon.sqlite3");run = database.start("example.com", "deep", {})
        for url,host,server,technologies in (
            ("https://example.com/","example.com","nginx/1.24",'["React","Next.js:15"]'),
            ("https://api.example.com/","api.example.com","cloudflare",'["PHP:8.3","WordPress:6.5","Title"]'),
        ):
            database.execute("INSERT INTO http_services(run_id,url,host,status,title,server,technologies,content_type,ip) VALUES(?,?,?,?,?,?,?,?,?)",(run,url,host,200,"Service",server,technologies,"text/html","192.0.2.10"))
        database.execute("INSERT INTO findings(run_id,tool,severity,template_id,name,matched_at,host,evidence) VALUES(?,?,?,?,?,?,?,?)",(run,"nuclei-tech","high","CVE-2024-1234","WordPress vulnerable component","https://api.example.com/","api.example.com","{}"))
        database.finish(run,"complete");database.conn.close()
        data=read_results(self.app,str(result))
        self.assertEqual(data["technology_metrics"],{"hosts":2,"fingerprinted_hosts":2,"technologies":6,"services":2,"versioned":4,"security_matches":1})
        stacks={item["host"]:item for item in data["tech_stacks"]}
        self.assertIn("Frameworks",stacks["example.com"]["categories"])
        self.assertNotIn("Title",stacks["api.example.com"]["technologies"])
        self.assertEqual(stacks["api.example.com"]["cves"],["CVE-2024-1234"])
        wordpress=next(item for item in stacks["api.example.com"]["assessments"] if item["name"].startswith("WordPress"))
        self.assertEqual(wordpress["status"],"matched")
        with sqlite3.connect(self.app.config["CONTROL_DB"]) as control:
            target_id=control.execute("INSERT INTO targets(domain) VALUES(?)",("example.com",)).lastrowid
            control.execute("INSERT INTO scans(target_id,profile,status,result_dir) VALUES(?,?,'complete',?)",(target_id,"deep",str(result)))
        self.login();response=self.client.get(f"/targets/{target_id}#tech-stacks")
        self.assertIn(b"Tech stacks",response.data);self.assertIn(b"api.example.com",response.data);self.assertIn(b"WordPress:6.5",response.data);self.assertIn(b"CVE-2024-1234",response.data)

    def test_infrastructure_tab_groups_detailed_nmap_services_by_ip(self):
        result = Path(self.app.config["RESULTS_DIR"]) / "nmap-run";result.mkdir(parents=True)
        database=Database(result/"recon.sqlite3");run=database.start("example.com","deep",{})
        database.execute("INSERT INTO dns_records(run_id,hostname,type,value,source) VALUES(?,?,?,?,?)",(run,"api.example.com","A","192.0.2.10","dnsx"))
        database.execute("""INSERT INTO ports(run_id,hostname,ip,port,protocol,service,state,reason,product,version,extra_info,cpe,scripts,source)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(run,"api.example.com","192.0.2.10",443,"tcp","ssl/http nginx 1.24","open","syn-ack","nginx","1.24","Ubuntu",'["cpe:/a:igor_sysoev:nginx:1.24"]','{"ssl-cert":"CN=api.example.com"}',"nmap"))
        database.finish(run,"complete");database.conn.close()
        data=read_results(self.app,str(result))
        self.assertEqual(data["ip_metrics"],{"addresses":1,"ipv4":1,"ipv6":0,"open_ports":1,"services":1})
        self.assertEqual(data["ip_inventory"][0]["ports"][0]["product"],"nginx")
        self.assertEqual(data["ip_inventory"][0]["ports"][0]["script_list"][0]["id"],"ssl-cert")
        with sqlite3.connect(self.app.config["CONTROL_DB"]) as control:
            target_id=control.execute("INSERT INTO targets(domain) VALUES(?)",("example.com",)).lastrowid
            control.execute("INSERT INTO scans(target_id,profile,status,result_dir) VALUES(?,?,'complete',?)",(target_id,"deep",str(result)))
        self.login();response=self.client.get(f"/targets/{target_id}#infrastructure")
        self.assertIn(b"192.0.2.10",response.data);self.assertIn(b"nginx",response.data);self.assertIn(b"ssl-cert",response.data)

    def test_httpx_active_subdomain_state_is_highlighted(self):
        result=Path(self.app.config["RESULTS_DIR"])/"active-run";result.mkdir(parents=True)
        database=Database(result/"recon.sqlite3");run=database.start("example.com","deep",{})
        database.execute("INSERT INTO assets(run_id,hostname,source,resolved,http_active,active_url,http_status,first_seen) VALUES(?,?,?,?,?,?,?,?)",(run,"api.example.com","httpx-recursive",1,1,"https://api.example.com/",200,"2026-01-01T00:00:00Z"))
        database.execute("INSERT INTO assets(run_id,hostname,source,resolved,http_active,first_seen) VALUES(?,?,?,?,?,?)",(run,"old.example.com","archive",1,0,"2026-01-01T00:00:00Z"))
        database.finish(run,"complete");database.conn.close()
        data=read_results(self.app,str(result));self.assertEqual(data["active_subdomains"],1)
        with sqlite3.connect(self.app.config["CONTROL_DB"]) as control:
            target_id=control.execute("INSERT INTO targets(domain) VALUES(?)",("example.com",)).lastrowid
            control.execute("INSERT INTO scans(target_id,profile,status,result_dir) VALUES(?,?,'complete',?)",(target_id,"deep",str(result)))
        self.login();response=self.client.get(f"/targets/{target_id}#subdomains")
        self.assertIn(b"active-badge",response.data);self.assertIn(b"HTTP 200",response.data);self.assertIn(b"https://api.example.com/",response.data)

    def test_markdown_report_download_contains_all_recon_sections(self):
        result = Path(self.tmp.name) / "results" / "example-run"
        result.mkdir(parents=True)
        database = Database(result / "recon.sqlite3")
        run = database.start("example.com", "deep", {})
        database.execute("INSERT INTO assets(run_id,hostname,source,resolved,first_seen) VALUES(?,?,?,?,?)",
                         (run, "api.example.com", "crt.sh", 1, "2026-01-01T00:00:00Z"))
        database.execute("INSERT INTO endpoints(run_id,url,host,path,query_keys,extension,source,first_seen) VALUES(?,?,?,?,?,?,?,?)",
                         (run, "https://example.com/cb?token=secret&view=a|b", "example.com", "/cb", '[\"token\",\"view\"]', "", "crawler", "2026-01-01T00:00:00Z"))
        database.finish(run, "complete")
        database.conn.close()
        with sqlite3.connect(self.app.config["CONTROL_DB"]) as control:
            target_id = control.execute("INSERT INTO targets(domain) VALUES(?)", ("example.com",)).lastrowid
            control.execute("""INSERT INTO scans(target_id,profile,status,finished_at,result_dir,exit_code)
                               VALUES(?,?,'complete',CURRENT_TIMESTAMP,?,0)""", (target_id, "deep", str(result)))
        self.login()
        response = self.client.get(f"/targets/{target_id}/report.md")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/markdown")
        self.assertIn("attachment;", response.headers["Content-Disposition"])
        self.assertIn("## Assets", body)
        self.assertIn("api.example.com", body)
        self.assertIn("## Tool execution ledger", body)
        self.assertNotIn("token=secret", body)
        self.assertIn("view=a%7Cb", body)

    def test_markdown_report_requires_login_and_completed_scan(self):
        self.assertEqual(self.client.get("/targets/1/report.md").status_code, 302)
        self.login()
        with sqlite3.connect(self.app.config["CONTROL_DB"]) as control:
            target_id = control.execute("INSERT INTO targets(domain) VALUES(?)", ("empty.example",)).lastrowid
        self.assertEqual(self.client.get(f"/targets/{target_id}/report.md").status_code, 404)

    def test_markdown_cells_escape_tables_and_newlines(self):
        self.assertEqual(markdown_cell("one|two\nthree"), r"one\|two<br>three")
        self.assertEqual(markdown_cell("<script>alert(1)</script>"), "&lt;script&gt;alert(1)&lt;/script&gt;")

    def test_target_request_rate_can_be_configured(self):
        self.login()
        with sqlite3.connect(self.app.config["CONTROL_DB"]) as control:
            target_id = control.execute("INSERT INTO targets(domain) VALUES(?)", ("rate.example",)).lastrowid
        with self.client.session_transaction() as session: token = session["csrf_token"]
        response = self.client.post(f"/targets/{target_id}/settings", data={"csrf_token": token, "request_rate": "12"})
        self.assertEqual(response.status_code, 302)
        with sqlite3.connect(self.app.config["CONTROL_DB"]) as control:
            self.assertEqual(control.execute("SELECT request_rate FROM targets WHERE id=?", (target_id,)).fetchone()[0], 12)

    def test_rescan_snapshots_selected_request_rate(self):
        self.login()
        with sqlite3.connect(self.app.config["CONTROL_DB"]) as control:
            target_id = control.execute("INSERT INTO targets(domain,request_rate) VALUES(?,?)", ("rescan.example", 30)).lastrowid
        with self.client.session_transaction() as session: token = session["csrf_token"]
        response = self.client.post(f"/targets/{target_id}/scan", data={"csrf_token": token, "authorized": "yes",
                                    "profile": "deep", "request_rate": "8"})
        self.assertEqual(response.status_code, 302)
        with sqlite3.connect(self.app.config["CONTROL_DB"]) as control:
            scan = control.execute("SELECT profile,request_rate FROM scans WHERE target_id=?", (target_id,)).fetchone()
            self.assertEqual(scan, ("deep", 8))
            self.assertEqual(control.execute("SELECT request_rate FROM targets WHERE id=?", (target_id,)).fetchone()[0], 8)

    def test_rescan_accepts_uploaded_scope_list(self):
        self.login()
        with sqlite3.connect(self.app.config["CONTROL_DB"]) as control:
            target_id = control.execute("INSERT INTO targets(domain,request_rate) VALUES(?,?)", ("example.com", 30)).lastrowid
        with self.client.session_transaction() as session: token = session["csrf_token"]
        upload = self.client.post("/api/scope-upload", data={"csrf_token": token, "chunk": "api.example.com\n"})
        upload_id = upload.get_json()["upload_id"]
        response = self.client.post(f"/targets/{target_id}/scan", data={"csrf_token": token, "authorized": "yes",
                                    "profile": "standard", "request_rate": "10", "scope_upload_id": upload_id})
        self.assertEqual(response.status_code, 302)
        with sqlite3.connect(self.app.config["CONTROL_DB"]) as control:
            self.assertEqual(control.execute("SELECT scope_subdomains FROM scans WHERE target_id=?", (target_id,)).fetchone()[0], "api.example.com")

    def test_completed_scan_delete_removes_record_and_scoped_artifacts(self):
        result = Path(self.app.config["RESULTS_DIR"]) / "target-1" / "scan-1" / "run"
        log = Path(self.app.config["LOG_DIR"]) / "scan-1.log"
        result.mkdir(parents=True)
        log.parent.mkdir(parents=True)
        (result / "recon.sqlite3").write_text("artifact")
        log.write_text("log")
        with sqlite3.connect(self.app.config["CONTROL_DB"]) as control:
            target_id = control.execute("INSERT INTO targets(domain) VALUES(?)", ("delete.example",)).lastrowid
            scan_id = control.execute("""INSERT INTO scans(target_id,profile,status,result_dir,log_path)
                                      VALUES(?,?,'complete',?,?)""", (target_id, "standard", str(result), str(log))).lastrowid
        self.login()
        with self.client.session_transaction() as session: token = session["csrf_token"]
        response = self.client.post(f"/scans/{scan_id}/delete", data={"csrf_token": token, "next": "/scans"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/scans")
        self.assertFalse(result.exists())
        self.assertFalse(log.exists())
        with sqlite3.connect(self.app.config["CONTROL_DB"]) as control:
            self.assertEqual(control.execute("SELECT COUNT(*) FROM scans WHERE id=?", (scan_id,)).fetchone()[0], 0)

    def test_running_scan_cannot_be_deleted(self):
        with sqlite3.connect(self.app.config["CONTROL_DB"]) as control:
            target_id = control.execute("INSERT INTO targets(domain) VALUES(?)", ("running.example",)).lastrowid
            scan_id = control.execute("INSERT INTO scans(target_id,profile,status) VALUES(?,?,'running')", (target_id, "standard")).lastrowid
        self.login()
        with self.client.session_transaction() as session: token = session["csrf_token"]
        self.client.post(f"/scans/{scan_id}/delete", data={"csrf_token": token, "next": "/scans"})
        with sqlite3.connect(self.app.config["CONTROL_DB"]) as control:
            self.assertEqual(control.execute("SELECT COUNT(*) FROM scans WHERE id=?", (scan_id,)).fetchone()[0], 1)

    def test_new_assets_are_compared_with_previous_scan(self):
        previous = Path(self.tmp.name) / "results" / "previous"
        current = Path(self.tmp.name) / "results" / "current"
        for path, hosts in ((previous, ["old.example.com"]), (current, ["old.example.com", "new.example.com"])):
            path.mkdir(parents=True)
            database = Database(path / "recon.sqlite3")
            run = database.start("example.com", "standard", {})
            for host in hosts:
                database.execute("INSERT INTO assets(run_id,hostname,source,resolved,first_seen) VALUES(?,?,?,?,?)",
                                 (run, host, "test", 1, "2026-01-01T00:00:00Z"))
            database.finish(run, "complete")
            database.conn.close()
        data = read_results(self.app, str(current), str(previous))
        self.assertEqual(data["new_counts"]["subdomains"], 1)
        novelty = {row["hostname"]: row["is_new"] for row in data["subdomains"]}
        self.assertFalse(novelty["old.example.com"])
        self.assertTrue(novelty["new.example.com"])

    def test_workspace_navigation_routes_and_historical_report_render(self):
        result = Path(self.tmp.name) / "results" / "navigation-report"
        result.mkdir(parents=True)
        database = Database(result / "recon.sqlite3")
        run = database.start("example.com", "standard", {})
        database.execute("INSERT INTO assets(run_id,hostname,source,resolved,first_seen) VALUES(?,?,?,?,?)",
                         (run, "api.example.com", "test", 1, "2026-01-01T00:00:00Z"))
        database.finish(run, "complete")
        database.conn.close()
        with sqlite3.connect(self.app.config["CONTROL_DB"]) as control:
            target_id = control.execute("INSERT INTO targets(domain) VALUES(?)", ("example.com",)).lastrowid
            scan_id = control.execute("""INSERT INTO scans(target_id,profile,status,finished_at,result_dir,exit_code)
                                      VALUES(?,?,'complete',CURRENT_TIMESTAMP,?,0)""", (target_id, "standard", str(result))).lastrowid
        self.login()
        for path, marker in (("/targets", b"Managed projects"), ("/scans", b"All scan runs"),
                             ("/attack-surface", b"Coverage by project scope"), ("/reports", b"Report library"),
                             (f"/reports/{scan_id}", b"api.example.com")):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            self.assertIn(marker, response.data, path)


if __name__ == "__main__": unittest.main()
