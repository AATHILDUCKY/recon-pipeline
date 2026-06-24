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
                self.assertTrue(args[args.index("-w")+1].endswith("wordlists/web-discovery-common.txt"))
                self.assertTrue(kwargs["artifact_name"].startswith("ffuf-"))
            urls=pipeline.db.values("SELECT url FROM endpoints WHERE run_id=? ORDER BY url",(pipeline.run_id,))
            self.assertEqual(urls,["https://api.example.com/admin","https://example.com/admin"])

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
            asyncio.run(pipeline.technologies())
            args=calls[0]
            self.assertIn("--aggression=3",args);self.assertIn("--max-threads=1",args)
            self.assertTrue(any(arg.startswith("--wait=") for arg in args))
            stored=json.loads(pipeline.db.conn.execute("SELECT technologies FROM http_services").fetchone()[0])
            self.assertEqual(stored,["PHP:8.2","React","WordPress:6.4"])

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


if __name__ == "__main__": unittest.main()
