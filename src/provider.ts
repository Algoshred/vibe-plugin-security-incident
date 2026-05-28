/**
 * CveSecretBlastRadiusProvider — implements SecurityProvider for stage
 * `incident.response`.
 *
 * Wave 2 scaffold. Real implementation will:
 *   1. Accept `input.config.cves[]` (list of CVE IDs) and run pinned
 *      Grype targeted at those CVEs only (--only-fixed=false,
 *      --vuln-id=<cve>) so triage finishes in well under 60 seconds.
 *   2. Accept `input.config.secretRules[]` (list of Gitleaks rule IDs)
 *      and run pinned Gitleaks with a synthesized config that whitelists
 *      only those rules — same sub-60s budget.
 *   3. Merge the two outputs into a single NormalizedFinding[] with
 *      categories "secret" + "vuln" and emit both SARIF (gitleaks) and
 *      grype-json evidence.
 *
 * For now, the run() stub returns one info-severity NormalizedFinding
 * that echoes the requested cves/secretRules so callers can verify the
 * dispatch path end-to-end while the real binaries are wired in.
 */
import { fingerprint } from "@vibecontrols/vibe-plugin-security/fingerprint";
import type { HostServices } from "@vibecontrols/plugin-sdk/contract";
import type {
  NormalizedFinding,
  ScanEvidenceArtifact,
  SecurityProvider,
  SecurityProviderMetadata,
  SecurityScanInput,
  SecurityScanResult,
  SecurityScanSummary,
  SecurityStage,
} from "@vibecontrols/vibe-plugin-security/types";

import { GITLEAKS_VERSION, GRYPE_VERSION } from "./tools-manifest.js";

interface IncidentConfig {
  cves?: string[];
  secretRules?: string[];
  timeoutMs?: number;
}

export class CveSecretBlastRadiusProvider implements SecurityProvider {
  readonly name = "cve-secret-blast-radius";
  readonly stage: SecurityStage = "incident.response";
  readonly toolVersion = `gitleaks@${GITLEAKS_VERSION}+grype@${GRYPE_VERSION}`;

  private host?: HostServices;

  async init(host: HostServices): Promise<void> {
    this.host = host;
  }

  async ensureToolInstalled(): Promise<void> {
    // Wave 2 scaffold — actual Gitleaks + Grype install happens here
    // once the run() implementation lands. Pinned binaries are declared
    // in ./tools-manifest.ts so the host can pre-stage them if it wants.
    this.host?.logger?.info?.(
      "security-incident-provider",
      `scaffold: tool install deferred; pinned versions are gitleaks@${GITLEAKS_VERSION} + grype@${GRYPE_VERSION}`,
    );
  }

  async run(input: SecurityScanInput): Promise<SecurityScanResult> {
    const startedAt = Date.now();
    const cfg = (input.config as IncidentConfig) ?? {};
    const cves = Array.isArray(cfg.cves) ? cfg.cves : [];
    const secretRules = Array.isArray(cfg.secretRules) ? cfg.secretRules : [];

    input.onProgress?.({
      pct: 30,
      message: `Targeted scan: ${cves.length} CVE(s), ${secretRules.length} secret rule(s)`,
    });
    input.onProgress?.({ pct: 60, message: "Scaffold: real Gitleaks + Grype deferred" });

    const finding: NormalizedFinding = {
      fingerprint: fingerprint({
        providerName: this.name,
        ruleId: "scaffold.pending",
        file: input.repoLocalPath,
      }),
      ruleId: "scaffold.pending",
      title: "Incident-response scaffold — real Gitleaks/Grype integration pending",
      description:
        `This is a Wave 2 scaffold of the ${this.name} provider for the ${this.stage} stage. ` +
        `Targeted request: cves=[${cves.join(",")}], secretRules=[${secretRules.join(",")}]. ` +
        `The real implementation will run pinned Gitleaks (${GITLEAKS_VERSION}) and Grype (${GRYPE_VERSION}) ` +
        `restricted to the requested subset for sub-60s triage and merge their findings.`,
      severity: "info",
      category: "policy",
      rawProviderRef: "scaffold",
    };

    const evidence: ScanEvidenceArtifact[] = [];

    input.onProgress?.({ pct: 100, message: "Scaffold run complete" });

    return {
      runId: input.runId,
      status: "succeeded",
      findings: [finding],
      evidence,
      durationMs: Date.now() - startedAt,
      summary: summarize([finding]),
    };
  }

  async cancel(_runId: string): Promise<void> {
    // No subprocess in the scaffold yet — nothing to cancel.
  }

  metadata(): SecurityProviderMetadata {
    return {
      stage: this.stage,
      supportedProfiles: [
        "backend",
        "frontend",
        "cli",
        "sdk",
        "mcp",
        "chrome-extension",
        "vscode-extension",
        "container",
        "iac",
      ],
      toolVersion: this.toolVersion,
      description:
        "Targeted incident-response provider — pinned Gitleaks + Grype restricted to input.config.cves[] + input.config.secretRules[] (Wave 2 scaffold).",
    };
  }
}

function summarize(findings: NormalizedFinding[]): SecurityScanSummary {
  const s: SecurityScanSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) s[f.severity]++;
  return s;
}
