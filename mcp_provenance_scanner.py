#!/usr/bin/env python3
"""
mcp-provenance-scanner — "npm audit, but for your agent's tool supply chain."

Reads MCP server configs (Claude Code's ~/.claude.json and Claude Desktop's
claude_desktop_config.json) and reports, per server: transport, command + args,
environment variable *names* (values redacted), version-pinning signals,
registry (npm vs pypi vs local path vs raw URL), and network endpoints.

Risk findings are HEURISTICS — this tool does not verify package signatures
against registries. See README for what is and is not claimed.

Stdlib only. No network access. Never prints secret values.
"""

import argparse
import json
import os
import re
import sys

VERSION = "1.0.0"

NPM_COMMANDS = {"npx", "npm", "node", "pnpm", "yarn", "bunx", "bun"}
PYPI_COMMANDS = {"uvx", "uv", "pipx", "pip", "pip3", "python", "python3", "py"}

SENSITIVE_ENV_RE = re.compile(
    r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE|AUTH)", re.IGNORECASE
)
URL_RE = re.compile(r"https?://[^\s\"']+")
NPM_EXACT_RE = re.compile(r"^(@?[^@\s/]+(?:/[^@\s]+)?)@(\d[\w.\-]*)$")
PYPI_EXACT_RE = re.compile(r"^([A-Za-z0-9_.\-]+)==([^*,\s]+)$")

RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def default_config_paths():
    """Well-known MCP config locations, most specific last."""
    paths = []
    home = os.path.expanduser("~")
    paths.append(os.path.join(home, ".claude.json"))  # Claude Code
    if sys.platform == "darwin":
        paths.append(
            os.path.join(
                home, "Library", "Application Support", "Claude",
                "claude_desktop_config.json",
            )
        )
    else:  # linux and friends
        paths.append(
            os.path.join(home, ".config", "Claude", "claude_desktop_config.json")
        )
    return paths


def load_config(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("config root is not a JSON object: %s" % path)
    servers = data.get("mcpServers", {})
    if not isinstance(servers, dict):
        raise ValueError("'mcpServers' is not an object: %s" % path)
    return servers


# ---------------------------------------------------------------- transport


def detect_transport(cfg):
    """stdio when a command is given; sse/http when a url is given."""
    if cfg.get("url"):
        url = str(cfg["url"])
        if "/sse" in url.lower():
            return "sse"
        return "http"
    if cfg.get("command"):
        return "stdio"
    return "unknown"


# ------------------------------------------------- package / registry / pin


def _base_command(command):
    return os.path.basename(str(command)).lower()


def _looks_like_local_path(token):
    t = str(token)
    if t.startswith(("/", "./", "../", "~/", ".\\")):
        return True
    if re.match(r"^[A-Za-z]:[\\/]", t):  # windows absolute
        return True
    if t.lower().endswith((".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".exe")):
        return True
    return False


def _first_spec_token(args):
    """First non-flag token in args — usually the package spec."""
    for a in args or []:
        s = str(a)
        if not s.startswith("-") and s:
            return s
    return None


def analyze_package(command, args):
    """
    Returns dict(registry, package, version, pinning, pinning_detail).
    registry: npm | pypi | local | url | unknown
    pinning:  pinned | floating | unknown
    """
    result = {
        "registry": "unknown",
        "package": None,
        "version": None,
        "pinning": "unknown",
        "pinning_detail": "no package spec detected",
    }
    if command is None:
        return result
    base = _base_command(command)

    if _looks_like_local_path(command):
        result["registry"] = "local"
        result["package"] = str(command)
        result["pinning"] = "pinned"
        result["pinning_detail"] = "local file path — runs exactly this file"
        return result

    if base in NPM_COMMANDS:
        result["registry"] = "npm"
        token = _first_spec_token(args)
        if token is None:
            return result
        if _looks_like_local_path(token):
            result["registry"] = "local"
            result["package"] = token
            result["pinning"] = "pinned"
            result["pinning_detail"] = "local path passed to %s" % base
            return result
        m = NPM_EXACT_RE.match(token)
        if m:
            result["package"] = m.group(1)
            ver = m.group(2)
            if ver.lower() in ("latest", "next", "*"):
                result["version"] = ver
                result["pinning"] = "floating"
                result["pinning_detail"] = "npm tag '%s' moves over time" % ver
            else:
                result["version"] = ver
                result["pinning"] = "pinned"
                result["pinning_detail"] = "exact version %s" % ver
        else:
            # strip a trailing @tag if present so the package name is clean
            name = token.rsplit("@", 1)[0] if "@" in token.lstrip("@") else token
            result["package"] = name or token
            result["pinning"] = "floating"
            result["pinning_detail"] = "no version specified — resolves to latest at install/run"
        return result

    if base in PYPI_COMMANDS:
        result["registry"] = "pypi"
        token = _first_spec_token(args)
        if token is None:
            return result
        if _looks_like_local_path(token):
            result["registry"] = "local"
            result["package"] = token
            result["pinning"] = "pinned"
            result["pinning_detail"] = "local file passed to %s" % base
            return result
        m = PYPI_EXACT_RE.match(token)
        if m:
            result["package"] = m.group(1)
            result["version"] = m.group(2)
            result["pinning"] = "pinned"
            result["pinning_detail"] = "exact pin %s==%s" % (m.group(1), m.group(2))
        else:
            name = re.split(r"[<>=!~\s\[]", token, 1)[0]
            result["package"] = name or token
            result["pinning"] = "floating"
            result["pinning_detail"] = "no == pin — version range or bare name"
        return result

    # Unknown launcher: still check whether it points at a local file.
    token = _first_spec_token(args)
    if token and _looks_like_local_path(token):
        result["registry"] = "local"
        result["package"] = token
        result["pinning"] = "pinned"
        result["pinning_detail"] = "local path in args"
    return result


# ------------------------------------------------------------------ analysis


def analyze_server(name, cfg):
    """Full per-server analysis. Returns a JSON-serializable dict."""
    transport = detect_transport(cfg)
    command = cfg.get("command")
    args = cfg.get("args") or []
    env = cfg.get("env") or {}
    env_names = sorted(str(k) for k in env.keys())  # names only — values redacted
    url = cfg.get("url")

    pkg = analyze_package(command, args)
    if url and pkg["registry"] == "unknown":
        pkg["registry"] = "url"
        pkg["package"] = str(url)

    endpoints = []
    if url:
        endpoints.append(str(url))
    for a in args:
        for m in URL_RE.finditer(str(a)):
            if m.group(0) not in endpoints:
                endpoints.append(m.group(0))

    findings = []
    score = 0

    if transport in ("sse", "http"):
        score += 3
        findings.append({
            "severity": "high",
            "code": "REMOTE_URL_SERVER",
            "message": "remote %s server at %s — code runs off-machine; "
                       "trust the operator, not just the package" % (transport, url),
        })
    elif transport == "stdio":
        if pkg["registry"] == "local":
            findings.append({
                "severity": "info",
                "code": "LOCAL_PATH",
                "message": "runs a local file — lower supply-chain risk "
                           "(no registry fetch at runtime)",
            })
        elif pkg["registry"] in ("npm", "pypi"):
            pass  # pinning findings below cover it
    else:
        findings.append({
            "severity": "low",
            "code": "UNKNOWN_TRANSPORT",
            "message": "could not determine transport — manual review advised",
        })

    if pkg["pinning"] == "floating":
        score += 2
        findings.append({
            "severity": "medium",
            "code": "FLOATING_VERSION",
            "message": "version not pinned (%s) — a future release can "
                       "change behavior silently" % pkg["pinning_detail"],
        })
    elif pkg["pinning"] == "unknown" and pkg["registry"] in ("npm", "pypi"):
        score += 1
        findings.append({
            "severity": "low",
            "code": "NO_PINNING_INFO",
            "message": "could not determine pinning: %s" % pkg["pinning_detail"],
        })

    for env_name in env_names:
        if SENSITIVE_ENV_RE.search(env_name):
            score += 1
            findings.append({
                "severity": "medium",
                "code": "SENSITIVE_ENV",
                "message": "env var '%s' looks like a credential — value redacted; "
                           "check it is not committed to the config file in plain text"
                           % env_name,
            })

    remote_scripts = [e for e in endpoints
                      if re.search(r"\.(sh|ps1|py|js)$", e, re.IGNORECASE)]
    if remote_scripts and transport == "stdio":
        score += 3
        findings.append({
            "severity": "high",
            "code": "REMOTE_SCRIPT_FETCH",
            "message": "args reference remote script(s): %s"
                       % ", ".join(remote_scripts),
        })

    if score >= 6:
        risk = "CRITICAL"
    elif score >= 4:
        risk = "HIGH"
    elif score >= 2:
        risk = "MEDIUM"
    else:
        risk = "LOW"
    # Any high-severity finding floors the risk at HIGH — the top-line label
    # must never look safer than the worst thing we found.
    if any(f["severity"] == "high" for f in findings):
        if RISK_ORDER.index(risk) < RISK_ORDER.index("HIGH"):
            risk = "HIGH"

    return {
        "name": name,
        "transport": transport,
        "command": command,
        "args": [str(a) for a in args],
        "env": env_names,  # names only
        "registry": pkg["registry"],
        "package": pkg["package"],
        "version": pkg["version"],
        "pinning": pkg["pinning"],
        "pinning_detail": pkg["pinning_detail"],
        "endpoints": endpoints,
        "risk": risk,
        "findings": findings,
    }


def scan(paths):
    """Scan config paths. Returns (servers_dict, errors_list)."""
    servers = {}
    errors = []
    for path in paths:
        if not os.path.exists(path):
            errors.append({"path": path, "error": "file not found"})
            continue
        try:
            for name, cfg in load_config(path).items():
                if not isinstance(cfg, dict):
                    errors.append({"path": path,
                                   "error": "server '%s' is not an object" % name})
                    continue
                servers[name] = analyze_server(name, cfg)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append({"path": path, "error": str(exc)})
    return servers, errors


# ------------------------------------------------------------------- output


def _table(servers):
    names = sorted(servers)
    if not names:
        return "No MCP servers found in the scanned config(s).\n"
    cols = ["Server", "Transport", "Registry", "Package", "Pinning", "Risk"]
    rows = []
    for n in names:
        s = servers[n]
        rows.append([n, s["transport"], s["registry"],
                     str(s["package"] or "-"),
                     s["pinning"], s["risk"]])
    widths = [max(len(r[i]) for r in rows + [cols]) for i in range(len(cols))]
    out = []
    out.append("  ".join(c.ljust(w) for c, w in zip(cols, widths)))
    out.append("  ".join("-" * w for w in widths))
    for r in rows:
        out.append("  ".join(c.ljust(w) for c, w in zip(r, widths)))
    out.append("")
    for n in names:
        s = servers[n]
        if not s["findings"]:
            out.append("%s: no findings." % n)
            continue
        out.append("%s [%s]:" % (n, s["risk"]))
        for f in s["findings"]:
            out.append("  [%s] %s: %s" % (f["severity"].upper(), f["code"],
                                          f["message"]))
        if s["env"]:
            out.append("  env vars (names only): %s" % ", ".join(s["env"]))
        if s["endpoints"]:
            out.append("  endpoints: %s" % ", ".join(s["endpoints"]))
        out.append("")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Scan MCP server configs for supply-chain provenance risks.")
    ap.add_argument("--config", action="append", default=[],
                    help="config file to scan (repeatable); defaults to the "
                         "well-known Claude Code / Claude Desktop locations")
    ap.add_argument("--json", action="store_true",
                    help="emit JSON instead of the text risk table")
    ap.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    args = ap.parse_args(argv)

    paths = args.config or default_config_paths()
    servers, errors = scan(paths)

    if args.json:
        print(json.dumps({
            "tool": "mcp-provenance-scanner",
            "version": VERSION,
            "configs": paths,
            "servers": servers,
            "errors": errors,
            "disclaimer": "Findings are heuristics, not signature verification. "
                          "Env var values are never collected.",
        }, indent=2))
    else:
        print(_table(servers))
        if errors:
            print("Config notes:")
            for e in errors:
                print("  %s: %s" % (e["path"], e["error"]))
        print("Note: findings are heuristics (floating versions, remote URLs, "
              "credential-like env names). This tool does not verify package "
              "signatures against registries.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
