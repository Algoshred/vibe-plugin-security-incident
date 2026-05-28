# @vibecontrols/vibe-plugin-security-incident

Targeted incident-response scanner for the `incident.response` lifecycle stage in [VibeControls](https://vibecontrols.com). Registers under provider name `cve-secret-blast-radius` against provider type `security.incident`, wrapping pinned Gitleaks (`8.21.2`) and Grype (`0.83.0`) restricted to the caller's targeted CVE / secret-rule subset. **Wave 2 scaffold — real tool integration pending.**

The host security meta plugin ([`@vibecontrols/vibe-plugin-security`](https://www.npmjs.com/package/@vibecontrols/vibe-plugin-security)) dispatches incident-triage scan runs to this provider when the user picks "cve-secret-blast-radius" as their default for `incident.response`.

## Install

```bash
vibe plugin install @vibecontrols/vibe-plugin-security-incident
vibe security providers set-default --stage incident.response --provider cve-secret-blast-radius
```

The plugin downloads the Gitleaks + Grype binaries automatically on first use (sha256-verified per platform) into `~/.boff/vibecontrols/agents/<profile>/tools/{gitleaks,grype}/`.

## Planned behavior

- Reads `input.config.cves[]` and runs `grype` restricted to those CVE IDs only (`--vuln-id` filter). Avoids the multi-minute baseline scan; sub-60s budget.
- Reads `input.config.secretRules[]` and runs `gitleaks` with a synthesized `.gitleaks.toml` that whitelists only those rule IDs.
- Merges output into a single `NormalizedFinding[]` (categories `vuln` + `secret`) and emits both SARIF (Gitleaks) + grype-json evidence so the incident artifact bundle is self-contained.
- Hard timeout from `input.config.timeoutMs` (default 60 000) — partial results streamed on timeout.

## Configuration

Per-vibe / per-incident config (stored in `RepositorySecurityConfig.pluginAssignments["incident.response"].config`):

```yaml
provider: cve-secret-blast-radius
config:
  cves:
    - CVE-2024-12345
    - CVE-2024-67890
  secretRules:
    - aws-access-token
    - generic-api-key
  timeoutMs: 60000 # hard cap for sub-60s triage
```

## License

Proprietary — Burdenoff Consultancy Services Pvt. Ltd.
