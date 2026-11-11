# mcp-provenance-scanner

**"npm audit, but for your agent's tool supply chain."**

MCP (Model Context Protocol) servers are installed from npm/PyPI with almost no
provenance verification — and in 2026 no comprehensive MCP security platform
exists. Your agent's capabilities are only as trustworthy as the servers behind
them. `mcp-provenance-scanner` reads your MCP server configs and reports what
each server actually is: where its code comes from, whether the version is
pinned, what credentials it touches, and what network endpoints it reaches —
plus honest, labeled heuristic risk findings.

## The problem

A typical Claude Code / Claude Desktop setup pulls in a dozen MCP servers with
one-click installs. Each entry is a standing grant of trust: arbitrary code
running next to your agent, often with API keys in the same config file, often
pinned to nothing (`npx -y some-server` resolves to *latest* on every run). A
compromised or typosquatted package updates silently and your agent keeps
calling it. Nobody maps this.

## Install

Zero dependencies — Python 3.8+ stdlib only. No package manager needed.

```bash
git clone https://github.com/Iceman2050/mcp-provenance-scanner.git
cd mcp-provenance-scanner
python3 mcp_provenance_scanner.py --help
```

## Usage

Scan the well-known configs (Claude Code `~/.claude.json`, Claude Desktop
`claude_desktop_config.json`):

```bash
python3 mcp_provenance_scanner.py
```

Scan a specific config file (handy for testing / CI):

```bash
python3 mcp_provenance_scanner.py --config /path/to/claude.json --config other.json
```

Machine-readable output:

```bash
python3 mcp_provenance_scanner.py --json
```

For each server the tool reports:

| Field | Meaning |
|---|---|
| transport | `stdio`, `sse`, `http`, or `unknown` |
| command / args | exactly how the server is launched |
| env | **names only** — values are redacted, never printed |
| registry | `npm`, `pypi`, `local` (file path), `url`, or `unknown` |
| package / version | the resolved package spec |
| pinning | `pinned` (exact version) vs `floating` (`latest`, ranges, bare names) |
| endpoints | network URLs for SSE/HTTP servers, or URLs found in args |
| risk | LOW / MEDIUM / HIGH / CRITICAL |
| findings | heuristic findings with severity, code, and explanation |

### Heuristics (labeled as such)

- **Floating version → higher risk.** `npx -y pkg` or `pkg>=0.5` can change behavior on the next run without you noticing.
- **Remote-URL server → higher risk.** SSE/HTTP servers run off-machine; you trust the operator, not just the package.
- **Env vars named `*KEY` / `*TOKEN` / `*SECRET` / … → sensitive.** Flagged by name; values are never collected or printed.
- **Local-path servers → lower supply-chain risk.** A file on disk can't be swapped by a registry compromise (it can still be malicious — review it).

## Example output

```
Server         Transport  Registry  Package                                  Pinning   Risk
-------------  ---------  --------  ---------------------------------------  --------  ------
floating-npm   stdio      npm       @acme/mcp-things                         floating  MEDIUM
local-path     stdio      local     /opt/mcp/my-server.py                    pinned    LOW
pinned-npm     stdio      npm       @modelcontextprotocol/server-filesystem  pinned    LOW
remote-sse     sse        url       https://mcp.example.com/sse              unknown   HIGH

floating-npm [MEDIUM]:
  [MEDIUM] FLOATING_VERSION: version not pinned (no version specified — resolves to latest at install/run) — a future release can change behavior silently
  [MEDIUM] SENSITIVE_ENV: env var 'ACME_API_KEY' looks like a credential — value redacted; check it is not committed to the config file in plain text
  env vars (names only): ACME_API_KEY, DEBUG

remote-sse [HIGH]:
  [HIGH] REMOTE_URL_SERVER: remote sse server at https://mcp.example.com/sse — code runs off-machine; trust the operator, not just the package
  [MEDIUM] SENSITIVE_ENV: env var 'REMOTE_TOKEN' looks like a credential — value redacted; check it is not committed to the config file in plain text
  env vars (names only): REMOTE_TOKEN
  endpoints: https://mcp.example.com/sse
```

## What this tool does NOT claim

- **No signature verification against registries.** Findings are heuristics derived from your config files only. The tool never contacts npm, PyPI, or any server.
- **Not a malware detector.** It cannot tell you whether a pinned package is malicious — only whether the *provenance signals* around it are strong or weak.
- **Env values are never read into output.** Names only, always.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

21 tests covering transport detection, npm/pypi pin parsing, local-path
detection, risk scoring, secret redaction, CLI text + JSON output shapes, and
fixture configs in both Claude Code and Claude Desktop formats.

## License

MIT — see [LICENSE](LICENSE).

## Built by Ingenious AI

mcp-provenance-scanner is built by **Ingenious AI**. Explore our security platform suite — get early access to any platform:

- [DisclosureGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard)
- [ModelMinder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder)
- [TermsWatch](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch)
- [Vibe-Code Audit](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit)
- [Rogue-Agent Defense](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense)
- [BreachHunter](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter)
- [ChatBreaker](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker)
- [Agent Flight Recorder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder)
- [Agent Auth Gateway](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway)
- [DomainGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard)
- [ContentCraft AI](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI)


> Built by Ingenious AI
