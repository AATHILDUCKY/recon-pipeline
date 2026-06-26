import unittest
import asyncio
import json
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

    def test_scope_entries_accept_wildcards_prefixes_and_paths(self):
        entries = tuple(rp.canonical_scope_subdomain(value, "infomaniak.com") for value in (
            "*.kdrive.infomaniak.com",
            "storage*.infomaniak.com",
            "manager.infomaniak.com/v3/*",
        ))
        self.assertEqual(entries, ("*.kdrive.infomaniak.com", "storage*.infomaniak.com", "manager.infomaniak.com"))
        self.assertTrue(rp.host_in_scope_entries("files.kdrive.infomaniak.com", "infomaniak.com", entries))
        self.assertTrue(rp.host_in_scope_entries("storage12.infomaniak.com", "infomaniak.com", entries))
        self.assertTrue(rp.host_in_scope_entries("manager.infomaniak.com", "infomaniak.com", entries))
        self.assertFalse(rp.host_in_scope_entries("kdrive.infomaniak.com", "infomaniak.com", entries))
        self.assertFalse(rp.host_in_scope_entries("mail.infomaniak.com", "infomaniak.com", entries))
        with self.assertRaises(ValueError):
            rp.canonical_scope_subdomain("*.evil.test", "infomaniak.com")

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

    def test_forms_are_inventoried_without_submitting_them(self):
        cfg = rp.Config("example.com","deep",Path("."),50,10,10,3,100,None,False,set(),100,100_000,10,0.5,3)
        with TemporaryDirectory() as folder:
            cfg.output=Path(folder);pipeline=rp.Pipeline(cfg)
            pipeline.inventory_forms("https://example.com/search",'<form action="/find" method="get"><input name="q"><input type="password" name="password"></form>')
            rows=pipeline.db.conn.execute("SELECT action_url,method,name,input_type FROM input_points ORDER BY name").fetchall()
            self.assertEqual(len(rows),2)
            self.assertEqual(rows[1][0],"https://example.com/find")

    def test_encoded_candidate_classifier_finds_tokens_and_hashes(self):
        cfg = rp.Config("example.com","standard",Path("."),50,10,10,3,100,None,False,set(),100,100_000,10,0.5,3)
        with TemporaryDirectory() as folder:
            cfg.output=Path(folder);pipeline=rp.Pipeline(cfg)
            values=pipeline.encoded_candidates("https://example.com/?data=SGVsbG8gd29ybGQ%3D","digest=5d41402abc4b2a76b9719d911017c592")
            self.assertTrue(any(kind=="url-value" for _,_,kind in values))
            self.assertTrue(any(kind=="hex-or-hash" for _,_,kind in values))

    def test_ducky_analyzer_decodes_without_misclassifying_encoding_as_hash(self):
        cfg = rp.Config("example.com","standard",Path("."),50,10,10,3,100,None,False,set(),100,100_000,10,0.5,3)
        with TemporaryDirectory() as folder:
            cfg.output=Path(folder);pipeline=rp.Pipeline(cfg)
            if not pipeline.tool("ducky-ana"):self.skipTest("bundled ducky-ana is unavailable on this platform")
            asyncio.run(pipeline.analyze_encoded("https://example.com/","value=SGVsbG8gd29ybGQ="))
            row=pipeline.db.conn.execute("SELECT kind,is_hash,decoded_preview FROM encoded_artifacts").fetchone()
            self.assertEqual(row["kind"],"Base64 standard")
            self.assertEqual(row["is_hash"],0)
            self.assertIn("Hello world",row["decoded_preview"])

    def test_ffuf_scans_every_live_origin_at_configured_rate_and_keeps_valid_results(self):
        cfg = rp.Config("example.com","deep",Path("."),17,10,10,2,100,None,False,set(),100,100_000,10,0.5,3)
        with TemporaryDirectory() as folder:
            cfg.output=Path(folder);pipeline=rp.Pipeline(cfg)
            for url,host,status in (
                ("https://example.com/","example.com",200),
                ("https://example.com/login","example.com",200),
                ("https://api.example.com/","api.example.com",401),
            ):
                pipeline.db.execute("INSERT INTO http_services(run_id,url,host,status) VALUES(?,?,?,?)",(pipeline.run_id,url,host,status))
            calls=[]
            async def fake_run_tool(stage, name, args, **kwargs):
                calls.append((args,kwargs))
                output=pipeline.raw/f"{kwargs['artifact_name']}.jsonl"
                target=args[args.index("-u")+1].replace("FUZZ","admin")
                rows=[{"url":target,"status":200},{"url":target+"-missing","status":404},{"url":"https://outside.test/admin","status":200}]
                output.write_text("".join(json.dumps(row)+"\n" for row in rows))
                return 0,output
            pipeline.run_tool=fake_run_tool
            asyncio.run(pipeline.directories())
            self.assertEqual(len(calls),2)
            for args,kwargs in calls:
                self.assertEqual(args[args.index("-rate")+1],"17")
                self.assertEqual(args[args.index("-recursion-depth")+1],"2")
                self.assertEqual(args[args.index("-recursion-strategy")+1],"default")
                self.assertTrue(args[args.index("-w")+1].endswith("wordlists/web-discovery-common.txt"))
                self.assertTrue(kwargs["artifact_name"].startswith("ffuf-"))
            urls=pipeline.db.values("SELECT url FROM endpoints WHERE run_id=? ORDER BY url",(pipeline.run_id,))
            self.assertEqual(urls,["https://api.example.com/admin","https://example.com/admin"])

    def test_httpx_marks_active_hosts_and_recursively_resolves_extracted_subdomains(self):
        cfg = rp.Config("example.com","deep",Path("."),20,10,10,2,100,None,False,set(),100,100_000,10,0.5,3)
        with TemporaryDirectory() as folder:
            cfg.output=Path(folder);pipeline=rp.Pipeline(cfg);calls=[]
            pipeline.db.execute("INSERT INTO assets(run_id,hostname,source,resolved,first_seen) VALUES(?,?,?,?,?)",(pipeline.run_id,"a.example.com","test",1,rp.utcnow()));pipeline.db.conn.commit()
            async def fake_run_tool(stage, name, args, **kwargs):
                artifact=kwargs.get("artifact_name",name);calls.append((name,artifact,args,kwargs));output=pipeline.raw/f"{artifact}.stdout"
                if name=="httpx":
                    target="a.example.com" if artifact.endswith("01") else "b.example.com"
                    row={"url":f"https://{target}/","status_code":200,"title":target,"host_ip":"192.0.2.10","body_fqdn":["b.example.com"] if target.startswith("a.") else []}
                    output.write_text(json.dumps(row)+"\n")
                elif name=="dnsx":output.write_text(json.dumps({"host":"b.example.com","a":["192.0.2.11"],"aaaa":[],"cname":[]})+"\n")
                else:output.write_text("")
                return 0,output
            pipeline.run_tool=fake_run_tool;pipeline.tool=lambda *names:"/fake/"+names[0]
            asyncio.run(pipeline.probe())
            http_calls=[call for call in calls if call[0]=="httpx"]
            self.assertEqual([call[1] for call in http_calls],["httpx-round-01","httpx-round-02"])
            self.assertIn("-nf",http_calls[0][2]);self.assertIn("-efqdn",http_calls[0][2])
            rows=[tuple(row) for row in pipeline.db.conn.execute("SELECT hostname,resolved,http_active,http_status FROM assets ORDER BY hostname")]
            self.assertEqual(rows,[("a.example.com",1,1,200),("b.example.com",1,1,200)])
            self.assertEqual(pipeline.db.conn.execute("SELECT COUNT(*) FROM http_services").fetchone()[0],2)

    def test_scoped_pipeline_keeps_only_matching_hosts_and_urls(self):
        cfg = rp.Config("example.com","deep",Path("."),20,10,10,2,100,None,False,set(),100,100_000,10,0.5,3,scope_subdomains=("*.app.example.com","api.example.com"))
        with TemporaryDirectory() as folder:
            cfg.output=Path(folder);pipeline=rp.Pipeline(cfg)
            self.assertTrue(pipeline.host_allowed("v1.app.example.com"))
            self.assertFalse(pipeline.host_allowed("www.example.com"))
            pipeline.db.execute("INSERT INTO assets(run_id,hostname,source,first_seen) VALUES(?,?,?,?)",(pipeline.run_id,"api.example.com","test",rp.utcnow()))
            pipeline.db.execute("INSERT INTO assets(run_id,hostname,source,first_seen) VALUES(?,?,?,?)",(pipeline.run_id,"www.example.com","test",rp.utcnow()))
            pipeline.add_endpoint("https://v1.app.example.com/health","test")
            pipeline.add_endpoint("https://www.example.com/health","test")
            pipeline.db.execute("INSERT INTO http_services(run_id,url,host,status) VALUES(?,?,?,?)",(pipeline.run_id,"https://www.example.com/","www.example.com",200))
            pipeline.prune_scoped_inventory()
            hosts=pipeline.db.values("SELECT hostname FROM assets WHERE run_id=? ORDER BY hostname",(pipeline.run_id,))
            endpoints=pipeline.db.values("SELECT host FROM endpoints WHERE run_id=? ORDER BY host",(pipeline.run_id,))
            services=pipeline.db.values("SELECT host FROM http_services WHERE run_id=?",(pipeline.run_id,))
            self.assertEqual(hosts,["api.example.com"])
            self.assertEqual(endpoints,["v1.app.example.com"])
            self.assertEqual(services,[])

    def test_wayback_discovery_feeds_archived_hosts_and_prioritized_urls_into_deep_scan(self):
        cfg = rp.Config("example.com","deep",Path("."),20,10,10,2,10,None,False,set(),100,100_000,10,0.5,3)
        with TemporaryDirectory() as folder:
            cfg.output=Path(folder);pipeline=rp.Pipeline(cfg)
            async def fake_run_tool(stage, name, args, **kwargs):
                output=pipeline.raw/"wayback.txt"
                output.write_text("https://old.example.com/plain\nhttps://old.example.com/app.js\nhttps://api.example.com/search?q=old\nhttps://outside.test/nope\n")
                return 0,output
            pipeline.run_tool=fake_run_tool
            asyncio.run(pipeline.archive_discovery())
            hosts=pipeline.db.values("SELECT hostname FROM assets WHERE run_id=? ORDER BY hostname",(pipeline.run_id,))
            urls=pipeline.db.values("SELECT url FROM endpoints WHERE run_id=? ORDER BY url",(pipeline.run_id,))
            self.assertEqual(hosts,["api.example.com","old.example.com"])
            self.assertIn("https://old.example.com/app.js",urls)
            self.assertIn("https://api.example.com/search?q=old",urls)
            self.assertFalse(any("outside.test" in url for url in urls))

    def test_gobuster_active_dns_uses_bundled_wordlist_rate_cap_and_valid_results(self):
        cfg = rp.Config("example.com","standard",Path("."),17,10,10,2,100,None,False,set(),100,100_000,10,0.5,3)
        with TemporaryDirectory() as folder:
            cfg.output=Path(folder);pipeline=rp.Pipeline(cfg);calls=[]
            async def fake_run_tool(stage, name, args, **kwargs):
                calls.append((stage,name,args,kwargs));output=pipeline.raw/"gobuster-dns.stdout"
                output.write_text("api.example.com 192.0.2.10 CNAME: edge.example.net.\nipv6.example.com 2001:db8::10\noutside.test 192.0.2.20\nnot a result\n")
                return 0,output
            pipeline.run_tool=fake_run_tool
            asyncio.run(pipeline.active_dns_enumeration())
            _,name,args,kwargs=calls[0]
            self.assertEqual(name,"gobuster")
            self.assertTrue(args[args.index("--wordlist")+1].endswith("wordlists/subdomains-top1million-5000.txt"))
            self.assertEqual(args[args.index("--threads")+1],"10")
            self.assertEqual(args[args.index("--delay")+1],"589ms")
            self.assertGreaterEqual(kwargs["timeout"],1800)
            hosts=pipeline.db.values("SELECT hostname FROM assets WHERE run_id=? ORDER BY hostname",(pipeline.run_id,))
            self.assertEqual(hosts,["api.example.com","ipv6.example.com"])
            records=[tuple(row) for row in pipeline.db.conn.execute("SELECT hostname,type,value FROM dns_records ORDER BY hostname,type")]
            self.assertEqual(records,[("api.example.com","A","192.0.2.10"),("api.example.com","CNAME","edge.example.net"),("ipv6.example.com","AAAA","2001:db8::10")])

    def test_jsminer_is_bounded_to_safe_in_scope_endpoint_extraction(self):
        cfg = rp.Config("example.com","deep",Path("."),20,10,10,2,100,None,False,set(),100,100_000,10,0.5,3)
        with TemporaryDirectory() as folder:
            cfg.output=Path(folder);pipeline=rp.Pipeline(cfg)
            pipeline.add_endpoint("https://app.example.com/static/main.js","test");pipeline.db.conn.commit()
            calls=[]
            async def fake_run_tool(stage, name, args, **kwargs):
                calls.append((args,kwargs));output=pipeline.raw/"jsminer.json"
                output.write_text(json.dumps([
                    {"source":"https://app.example.com/static/main.js","pattern":"endpoint_path","value":"/api/users"},
                    {"source":"https://app.example.com/static/main.js","pattern":"endpoint_path","value":"/api/${user}"},
                    {"source":"https://app.example.com/static/main.js","pattern":"endpoint_url","value":"https://outside.test/api"},
                ]))
                return 1,output
            pipeline.run_tool=fake_run_tool
            asyncio.run(pipeline.javascript_analysis())
            args,kwargs=calls[0]
            self.assertIn("-external=false",args);self.assertIn("-render=false",args);self.assertIn("-insecure=false",args)
            self.assertEqual(kwargs["success_codes"],{0,1})
            urls=pipeline.db.values("SELECT url FROM endpoints WHERE run_id=? AND source='jsminer'",(pipeline.run_id,))
            self.assertEqual(urls,["https://app.example.com/api/users"])

    def test_deep_technology_analysis_uses_aggressive_bounded_whatweb_and_filters_metadata(self):
        cfg = rp.Config("example.com","deep",Path("."),20,10,10,2,100,None,False,set(),100,100_000,10,0.5,3)
        with TemporaryDirectory() as folder:
            cfg.output=Path(folder);pipeline=rp.Pipeline(cfg);calls=[]
            pipeline.db.execute("INSERT INTO http_services(run_id,url,host,status,technologies) VALUES(?,?,?,?,?)",(pipeline.run_id,"https://app.example.com/","app.example.com",200,'["React"]'))
            async def fake_run_tool(stage, name, args, **kwargs):
                calls.append(args);output=Path(next(arg.split("=",1)[1] for arg in args if arg.startswith("--log-json=")))
                output.write_text(json.dumps([{"target":"https://app.example.com/","plugins":{"WordPress":{"version":["6.4"]},"PHP":{"version":["8.2"]},"Title":{"string":["Ignored"]}}}]))
                return 0,pipeline.raw/"whatweb.stdout"
            pipeline.run_tool=fake_run_tool
            pipeline.fetch_text=lambda url: None
            asyncio.run(pipeline.technologies())
            args=calls[0]
            self.assertIn("--aggression=3",args);self.assertIn("--max-threads=1",args)
            self.assertTrue(any(arg.startswith("--wait=") for arg in args))
            stored=json.loads(pipeline.db.conn.execute("SELECT technologies FROM http_services").fetchone()[0])
            self.assertEqual(stored,["PHP:8.2","React","WordPress:6.4"])
            tech_rows=[tuple(row) for row in pipeline.db.conn.execute("SELECT name,version,source FROM technologies ORDER BY name,version")]
            self.assertIn(("WordPress","6.4","whatweb"),tech_rows)
            self.assertIn(("PHP","8.2","whatweb"),tech_rows)

    def test_page_source_technology_probe_extracts_cms_and_framework_versions(self):
        cfg = rp.Config("example.com","deep",Path("."),20,10,10,2,100,None,False,set(),100,100_000,10,0.5,3)
        with TemporaryDirectory() as folder:
            cfg.output=Path(folder);pipeline=rp.Pipeline(cfg);calls=[]
            pipeline.db.execute("INSERT INTO http_services(run_id,url,host,status,server,technologies) VALUES(?,?,?,?,?,?)",(pipeline.run_id,"https://app.example.com/","app.example.com",200,"nginx/1.24.0","[]"))
            html='''<html><head><meta name="generator" content="WordPress 6.5.4"><script id="__NEXT_DATA__" type="application/json">{}</script><script src="/_next/static/chunks/main.js"></script><script src="/static/react.production.min.js?ver=18.2.0"></script></head></html>'''
            async def fake_run_tool(stage, name, args, **kwargs):
                calls.append((name,args));Path(next(arg.split("=",1)[1] for arg in args if arg.startswith("--log-json="))).write_text("[]")
                return 0,pipeline.raw/"whatweb.stdout"
            pipeline.run_tool=fake_run_tool
            pipeline.fetch_text=lambda url: (url,html)
            asyncio.run(pipeline.technologies())
            rows=[tuple(row) for row in pipeline.db.conn.execute("SELECT name,version,source FROM technologies ORDER BY name,version,source")]
            self.assertIn(("nginx","1.24.0","server-header"),rows)
            self.assertIn(("WordPress","6.5.4","page-source"),rows)
            self.assertIn(("Next.js","","page-source"),rows)
            self.assertIn(("React","18.2.0","page-source"),rows)
            stored=json.loads(pipeline.db.conn.execute("SELECT technologies FROM http_services").fetchone()[0])
            self.assertIn("WordPress:6.5.4",stored);self.assertIn("React:18.2.0",stored);self.assertIn("Next.js",stored)

    def test_subjack_json_only_creates_findings_for_positive_in_scope_results(self):
        cfg = rp.Config("example.com","deep",Path("."),20,10,10,2,100,None,False,set(),100,100_000,10,0.5,3)
        with TemporaryDirectory() as folder:
            cfg.output=Path(folder);pipeline=rp.Pipeline(cfg);report=Path(folder)/"subjack.json"
            report.write_text(json.dumps([
                {"subdomain":"dangling.example.com","vulnerable":True,"service":"github"},
                {"subdomain":"safe.example.com","vulnerable":False},
                {"subdomain":"outside.test","vulnerable":True,"service":"aws"},
            ]))
            pipeline.ingest_subjack(report,{"dangling.example.com","safe.example.com"})
            rows=pipeline.db.conn.execute("SELECT tool,name,host FROM findings WHERE run_id=?",(pipeline.run_id,)).fetchall()
            self.assertEqual([tuple(row) for row in rows],[("subjack","Potential subdomain takeover: github","dangling.example.com")])

    def test_nuclei_updates_templates_and_runs_general_and_technology_aware_passes(self):
        cfg = rp.Config("example.com","deep",Path("."),20,10,10,2,100,None,False,set(),100,100_000,10,0.5,3)
        with TemporaryDirectory() as folder:
            cfg.output=Path(folder);pipeline=rp.Pipeline(cfg);calls=[]
            pipeline.db.execute("INSERT INTO http_services(run_id,url,host,status) VALUES(?,?,?,?)",(pipeline.run_id,"https://example.com/","example.com",200))
            async def fake_run_tool(stage, name, args, **kwargs):
                artifact=kwargs.get("artifact_name",name);calls.append((artifact,args));output=pipeline.raw/f"{artifact}.stdout"
                if artifact=="nuclei-general":output.write_text(json.dumps({"template-id":"generic-check","matched-at":"https://example.com/","info":{"name":"Generic issue","severity":"medium"}})+"\n")
                elif artifact=="nuclei-technology":output.write_text(json.dumps({"template-id":"CVE-2025-1234","matched-at":"https://example.com/","info":{"name":"WordPress component vulnerability","severity":"high"}})+"\n")
                else:output.write_text("")
                return 0,output
            pipeline.run_tool=fake_run_tool;pipeline.tool=lambda *names:"/fake/nuclei"
            asyncio.run(pipeline.nuclei())
            self.assertEqual([name for name,_ in calls],["nuclei-template-update","nuclei-general","nuclei-technology"])
            self.assertIn("-as",calls[2][1])
            rows=[tuple(row) for row in pipeline.db.conn.execute("SELECT tool,template_id FROM findings ORDER BY id")]
            self.assertEqual(rows,[("nuclei","generic-check"),("nuclei-tech","CVE-2025-1234")])
            self.assertIsNotNone(pipeline.db.conn.execute("SELECT 1 FROM domain_info WHERE key='Vulnerability templates'").fetchone())

    def test_wapiti_uses_prioritized_inventory_and_ingests_json_report(self):
        cfg = rp.Config("example.com","deep",Path("."),20,10,10,2,100,None,False,set(),100,100_000,10,0.5,3)
        with TemporaryDirectory() as folder:
            cfg.output=Path(folder);pipeline=rp.Pipeline(cfg);calls=[]
            pipeline.db.execute("INSERT INTO http_services(run_id,url,host,status,server,technologies) VALUES(?,?,?,?,?,?)",(pipeline.run_id,"https://app.example.com/","app.example.com",200,"nginx",'["WordPress:6.5","Java"]'))
            pipeline.db.execute("INSERT INTO endpoints(run_id,url,host,path,query_keys,extension,source,first_seen) VALUES(?,?,?,?,?,?,?,?)",(pipeline.run_id,"https://app.example.com/search?q=test","app.example.com","/search",'["q"]',"","test",rp.utcnow()))
            pipeline.db.execute("INSERT INTO input_points(run_id,page_url,action_url,method,name,input_type) VALUES(?,?,?,?,?,?)",(pipeline.run_id,"https://app.example.com/upload","https://app.example.com/upload","POST","avatar","file"))
            async def fake_run_tool(stage, name, args, **kwargs):
                calls.append((stage,name,args,kwargs));report=Path(args[args.index("-o")+1])
                report.write_text(json.dumps({"classifications":{"SQL Injection":{"desc":"SQLi","sol":"fix","ref":{"OWASP":"https://owasp.org"}}},"vulnerabilities":{"SQL Injection":[{"method":"GET","path":"/search?q=test","info":"SQL injection via parameter q","level":3,"parameter":"q","module":"sql","curl_command":"curl https://app.example.com/search?q=test"}]},"anomalies":{},"additionals":{},"infos":{"target":"https://app.example.com/"}}))
                return 0,pipeline.raw/"wapiti.stdout"
            pipeline.run_tool=fake_run_tool;pipeline.wapiti_executable=lambda:"/fake/wapiti"
            asyncio.run(pipeline.wapiti_checks())
            args=calls[0][2]
            self.assertIn("--max-scan-time",args);self.assertIn("--max-attack-time",args);self.assertIn("--scope",args)
            modules=set(args[args.index("-m")+1].split(","))
            self.assertTrue({"wapp","cms","xss","sql","timesql","upload","log4shell","spring4shell"} <= modules)
            self.assertIn("https://app.example.com/search?q=test",[args[i+1] for i,value in enumerate(args[:-1]) if value=="-s"])
            row=pipeline.db.conn.execute("SELECT tool,severity,template_id,name,matched_at,host FROM findings WHERE run_id=?",(pipeline.run_id,)).fetchone()
            self.assertEqual(tuple(row),("wapiti","high","wapiti:sql:SQL Injection","SQL Injection: SQL injection via parameter q","https://app.example.com/search?q=test","app.example.com"))

    def test_wapiti_target_selection_prefers_parameterized_origins(self):
        cfg = rp.Config("example.com","deep",Path("."),20,10,10,2,100,None,False,set(),100,100_000,10,0.5,3)
        with TemporaryDirectory() as folder:
            cfg.output=Path(folder);pipeline=rp.Pipeline(cfg)
            for url,host in (("https://static.example.com/","static.example.com"),("https://app.example.com/","app.example.com")):
                pipeline.db.execute("INSERT INTO http_services(run_id,url,host,status,technologies) VALUES(?,?,?,?,?)",(pipeline.run_id,url,host,200,"[]"))
            pipeline.db.execute("INSERT INTO endpoints(run_id,url,host,path,query_keys,extension,source,first_seen) VALUES(?,?,?,?,?,?,?,?)",(pipeline.run_id,"https://app.example.com/item?id=1","app.example.com","/item",'["id"]',"","test",rp.utcnow()))
            targets=pipeline.wapiti_origin_targets()
            self.assertEqual(targets[0]["base"],"https://app.example.com/")
            self.assertIn("https://app.example.com/item?id=1",targets[0]["starts"])

    def test_nikto_uses_managed_tool_prioritized_targets_and_ingests_xml(self):
        cfg = rp.Config("example.com","deep",Path("."),20,10,10,2,100,None,False,set(),100,100_000,10,0.5,3)
        with TemporaryDirectory() as folder:
            cfg.output=Path(folder);pipeline=rp.Pipeline(cfg);calls=[]
            pipeline.db.execute("INSERT INTO http_services(run_id,url,host,status,server,technologies) VALUES(?,?,?,?,?,?)",(pipeline.run_id,"https://static.example.com/","static.example.com",200,"nginx","[]"))
            pipeline.db.execute("INSERT INTO http_services(run_id,url,host,status,server,technologies) VALUES(?,?,?,?,?,?)",(pipeline.run_id,"https://app.example.com/","app.example.com",200,"Apache",'["WordPress:6.5","PHP:8.2"]'))
            pipeline.db.execute("INSERT INTO endpoints(run_id,url,host,path,query_keys,extension,source,first_seen) VALUES(?,?,?,?,?,?,?,?)",(pipeline.run_id,"https://app.example.com/admin.php?id=1","app.example.com","/admin.php",'["id"]',"php","test",rp.utcnow()))
            xml='''<?xml version="1.0"?><niktoscan><scandetails><item id="999001"><description>Admin page may disclose sensitive configuration backup file</description><uri>/admin.php</uri><namelink>https://app.example.com/admin.php</namelink></item></scandetails></niktoscan>'''
            async def fake_run_tool(stage,name,args,**kwargs):
                calls.append((stage,name,args,kwargs));Path(args[args.index("-output")+1]).write_text(xml)
                return 0,pipeline.raw/"nikto.stdout"
            pipeline.run_tool=fake_run_tool;pipeline.nikto_executable=lambda:"/fake/nikto";pipeline.nikto_cwd=lambda:Path(folder)
            asyncio.run(pipeline.nikto_checks())
            args=calls[0][2]
            self.assertEqual(args[args.index("-host")+1],"https://app.example.com/")
            self.assertIn("-Tuning",args);self.assertIn("-maxtime",args);self.assertIn("-Pause",args)
            row=pipeline.db.conn.execute("SELECT tool,severity,template_id,name,matched_at,host FROM findings WHERE run_id=?",(pipeline.run_id,)).fetchone()
            self.assertEqual(tuple(row),("nikto","medium","nikto:999001","Admin page may disclose sensitive configuration backup file","https://app.example.com/admin.php","app.example.com"))

    def test_deep_nmap_scans_all_tcp_ports_and_ingests_detailed_services(self):
        cfg = rp.Config("example.com","deep",Path("."),25,10,10,2,100,None,False,set(),100,100_000,10,0.5,3)
        with TemporaryDirectory() as folder:
            cfg.output=Path(folder);pipeline=rp.Pipeline(cfg);calls=[]
            pipeline.db.execute("INSERT INTO assets(run_id,hostname,source,resolved,first_seen) VALUES(?,?,?,?,?)",(pipeline.run_id,"api.example.com","test",1,rp.utcnow()))
            pipeline.db.execute("INSERT INTO dns_records(run_id,hostname,type,value,source) VALUES(?,?,?,?,?)",(pipeline.run_id,"api.example.com","A","192.0.2.10","test"));pipeline.db.conn.commit()
            pipeline.db.execute("INSERT INTO dns_records(run_id,hostname,type,value,source) VALUES(?,?,?,?,?)",(pipeline.run_id,"api.example.com","AAAA","2001:db8::10","test"));pipeline.db.conn.commit()
            xml='''<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><hostnames><hostname name="api.example.com"/></hostnames><ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="http" product="nginx" version="1.24.0" extrainfo="Ubuntu" tunnel="ssl"><cpe>cpe:/a:igor_sysoev:nginx:1.24.0</cpe></service><script id="ssl-cert" output="CN=api.example.com"/></port></ports><hostscript><script id="clock-skew" output="mean: 0s"/></hostscript></host></nmaprun>'''
            xml6='''<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="2001:db8::10" addrtype="ipv6"/><ports><port protocol="tcp" portid="8443"><state state="open" reason="syn-ack"/><service name="https" product="envoy" version="1.30"/></port></ports></host></nmaprun>'''
            async def fake_run_tool(stage, name, args, **kwargs):
                calls.append((name,args,kwargs));output=pipeline.raw/f"{name}.stdout"
                output.write_text((xml6 if "-6" in args else xml) if name=="nmap" else "")
                return 0,output
            pipeline.run_tool=fake_run_tool;pipeline.tool=lambda *names:"/fake/"+names[0]
            asyncio.run(pipeline.ports())
            nmap_calls=[args for name,args,_ in calls if name=="nmap"];nmap_args=nmap_calls[0]
            self.assertIn("-p-",nmap_args);self.assertIn("-sV",nmap_args);self.assertIn("-sC",nmap_args)
            self.assertEqual(nmap_args[nmap_args.index("--max-rate")+1],"25")
            self.assertEqual(len(nmap_calls),2);self.assertTrue(any("-6" in args for args in nmap_calls))
            row=pipeline.db.conn.execute("SELECT hostname,ip,port,state,reason,product,version,extra_info,cpe,scripts,source FROM ports WHERE ip='192.0.2.10'").fetchone()
            self.assertEqual(tuple(row[:8]),("api.example.com","192.0.2.10",443,"open","syn-ack","nginx","1.24.0","Ubuntu"))
            self.assertIn("nginx:1.24.0",row[8]);self.assertIn("ssl-cert",row[9]);self.assertEqual(row[10],"nmap")
            self.assertEqual(pipeline.db.conn.execute("SELECT port FROM ports WHERE ip='2001:db8::10'").fetchone()[0],8443)
            tech=[tuple(row) for row in pipeline.db.conn.execute("SELECT host,name,version,source FROM technologies ORDER BY name")]
            self.assertIn(("api.example.com","nginx","1.24.0","nmap-service"),tech)
            self.assertIn(("api.example.com","Ubuntu","","nmap-service"),tech)


if __name__ == "__main__": unittest.main()
