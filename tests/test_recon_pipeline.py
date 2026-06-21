import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import recon_pipeline as rp


class PipelineTests(unittest.TestCase):
    def test_domain_validation(self):
        self.assertEqual(rp.canonical_domain("Example.COM."), "example.com")
        for bad in ("https://example.com", "127.0.0.1", "example", "bad_name.com"):
            with self.assertRaises(ValueError): rp.canonical_domain(bad)

    def test_scope_and_url_normalization(self):
        self.assertTrue(rp.in_scope_host("a.example.com", "example.com"))
        self.assertFalse(rp.in_scope_host("notexample.com", "example.com"))
        self.assertEqual(rp.canonical_url("https://A.Example.com:443/a//b?z=2&a=1#x", "example.com"), "https://a.example.com/a/b?a=1&z=2")
        self.assertIsNone(rp.canonical_url("https://evil.test/", "example.com"))

    def test_database_deduplicates(self):
        with TemporaryDirectory() as folder:
            db = rp.Database(Path(folder) / "x.db")
            run = db.start("example.com", "passive", {})
            for _ in range(2): db.execute("INSERT OR IGNORE INTO assets(run_id,hostname,source,first_seen) VALUES(?,?,?,?)", (run,"example.com","test",rp.utcnow()))
            db.conn.commit()
            self.assertEqual(db.conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0], 1)

    def test_cli_requires_authorization(self):
        self.assertEqual(rp.main(["example.com", "--profile", "passive"]), 2)

    def test_secret_detection_is_redacted(self):
        cfg = rp.Config("example.com","standard",Path("."),50,10,10,3,100,None,False,set(),100,100_000,10,0.5,3)
        with TemporaryDirectory() as folder:
            cfg.output=Path(folder)
            pipeline=rp.Pipeline(cfg)
            token="ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
            findings=pipeline.scan_text("https://example.com/app.js",f'const token="{token}";')
            self.assertEqual(findings[0]["type"],"GitHub token")
            self.assertNotIn(token,findings[0]["redacted"])
            self.assertEqual(len(findings[0]["fingerprint"]),20)

    def test_placeholder_secret_is_ignored(self):
        cfg = rp.Config("example.com","standard",Path("."),50,10,10,3,100,None,False,set(),100,100_000,10,0.5,3)
        with TemporaryDirectory() as folder:
            cfg.output=Path(folder)
            pipeline=rp.Pipeline(cfg)
            self.assertEqual(pipeline.scan_text("https://example.com/app.js",'api_key="your_api_key_placeholder"'),[])

    def test_sensitive_query_is_redacted_for_report(self):
        self.assertEqual(rp.redact_url("https://example.com/cb?token=supersecretvalue&view=1"),"https://example.com/cb?token=%5BREDACTED%5D&view=1")

    def test_active_candidates_are_ranked_deduplicated_and_secret_safe(self):
        cfg = rp.Config("example.com","deep",Path("."),50,10,10,3,100,None,False,set(),100,100_000,10,0.5,3)
        with TemporaryDirectory() as folder:
            cfg.output=Path(folder);pipeline=rp.Pipeline(cfg)
            pipeline.add_endpoint("https://example.com/product?id=1","test")
            pipeline.add_endpoint("https://example.com/product?id=2","test")
            pipeline.add_endpoint("https://example.com/callback?token=sensitivevalue","test")
            pipeline.add_endpoint("https://example.com/list?color=blue","test")
            pipeline.db.conn.commit();urls=pipeline.active_candidates()
            self.assertEqual(urls[0],"https://example.com/product?id=1")
            self.assertEqual(len(urls),2)
            self.assertFalse(any("token=" in url for url in urls))

    def test_github_repository_discovery_is_normalized(self):
        cfg = rp.Config("example.com","deep",Path("."),50,10,10,3,100,None,False,set(),100,100_000,10,0.5,3)
        with TemporaryDirectory() as folder:
            cfg.output=Path(folder);pipeline=rp.Pipeline(cfg)
            pipeline.add_repository("https://github.com/ExampleOrg/useful-repo/tree/main","crawl")
            pipeline.add_repository("https://github.com/ExampleOrg/useful-repo.git","crawl")
            pipeline.add_repository("https://github.com/features/actions","crawl")
            pipeline.db.conn.commit()
            rows=pipeline.db.values("SELECT url FROM repositories WHERE run_id=?",(pipeline.run_id,))
            self.assertEqual(rows,["https://github.com/ExampleOrg/useful-repo.git"])


if __name__ == "__main__": unittest.main()
