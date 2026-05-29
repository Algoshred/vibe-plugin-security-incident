# @vibecontrols/vibe-plugin-security-incident

<!-- VIBECONTROLS_OSS_HEADER_START -->

> **License**: MIT — see [LICENSE](./LICENSE).
> **Note**: This plugin is open source. The `@vibecontrols/agent` runtime that loads it is **not** open source — it is a proprietary product of Burdenoff Consultancy Services Pvt. Ltd. See [vibecontrols.com](https://vibecontrols.com) for the agent.

<!-- VIBECONTROLS_OSS_HEADER_END -->

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

<!-- VIBECONTROLS_OSS_FOOTER_START -->

---

## License

Released under the [MIT License](./LICENSE).

Copyright (c) 2026 Burdenoff Consultancy Services Private Limited, Algoshred Technologies Private Limited, and all its sister companies.

Maintainer: **Vignesh T.V** — <https://github.com/tvvignesh>

## Credits

This plugin builds on the following upstream open-source projects. All trademarks and copyrights remain with their respective owners.

- **Gitleaks** — <https://github.com/gitleaks/gitleaks>
- **Grype** — <https://github.com/anchore/grype>

## About VibeControls

**VibeControls** is the agentic engineering mission control for AI-native teams. Vibe-plugins extend the VibeControls agent with new providers, tools, sessions, tunnels, storage backends, and security stages.

- Website: <https://vibecontrols.com>
- Documentation: <https://docs.vibecontrols.com>
- Plugin SDK: <https://github.com/algoshred/vibecontrols-plugin-sdk>
- All plugins: <https://github.com/algoshred?q=vibe-plugin-&type=all>

## Important: agent is not open source

The `@vibecontrols/agent` runtime that loads and orchestrates these plugins is **closed source** and proprietary to Burdenoff Consultancy Services Pvt. Ltd. Only the plugin contract and the plugins themselves are released under MIT. If you want a fully self-hostable agent, please open an issue or contact the maintainer.

<!-- VIBECONTROLS_OSS_FOOTER_END -->
