/**
 * CveSecretBlastRadiusProvider — implements SecurityProvider for stage
 * `incident.response`. Runs pinned Gitleaks for secret-rule triage and
 * pinned Grype for CVE triage, both filtered against the requested
 * subset in `input.config`. Targeted incident scans complete in well
 * under 60 seconds.
 *
 *   - secretRules[]: only Gitleaks findings whose rule id matches one
 *     of the entries are kept (case-insensitive substring match).
 *   - cves[]: only Grype findings whose vulnerability id is in the
 *     list are kept.
 *
 * Both tools auto-install via the shared tool-installer using the
 * pinned binaries + sha256s declared in ./tools-manifest.ts.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import * as path from "node:path";

import type { HostServices } from "@vibecontrols/plugin-sdk/contract";
import { fingerprint } from "@vibecontrols/vibe-plugin-security/fingerprint";
import { normalizeGrype, normalizeSarif } from "@vibecontrols/vibe-plugin-security/normalizer";
import { resolveToolPath } from "@vibecontrols/vibe-plugin-security/tool-installer";
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

import { GITLEAKS_VERSION, GRYPE_VERSION, TOOLS_MANIFEST } from "./tools-manifest.js";

interface IncidentConfig {
  cves?: string[];
  secretRules?: string[];
  timeoutMs?: number;
  gitleaksConfig?: string;
}

const DEFAULT_TOOL_TIMEOUT_MS = 60 * 1000;
const LOG_NAMESPACE = "security-incident-provider";

export class CveSecretBlastRadiusProvider implements SecurityProvider {
  readonly name = "cve-secret-blast-radius";
  readonly stage: SecurityStage = "incident.response";
  readonly toolVersion = `gitleaks@${GITLEAKS_VERSION}+grype@${GRYPE_VERSION}`;

  private host?: HostServices;
  private gitleaksPath?: string;
  private grypePath?: string;
  private active = new Map<string, ChildProcess>();

  async init(host: HostServices): Promise<void> {
    this.host = host;
  }

  async ensureToolInstalled(): Promise<void> {
    const dataDir =
      this.host?.getDataDir?.() ?? path.join(process.env.HOME ?? ".", ".boff/vibecontrols");
    const ctx = {
      dataDir,
      log: {
        info: (m: string) => this.host?.logger?.info?.(LOG_NAMESPACE, m),
        warn: (m: string) => this.host?.logger?.warn?.(LOG_NAMESPACE, m),
        error: (m: string) => this.host?.logger?.error?.(LOG_NAMESPACE, m),
      },
    };
    this.gitleaksPath = await resolveToolPath(ctx, "gitleaks", TOOLS_MANIFEST.gitleaks);
    this.grypePath = await resolveToolPath(ctx, "grype", TOOLS_MANIFEST.grype);
  }

  async run(input: SecurityScanInput): Promise<SecurityScanResult> {
    const startedAt = Date.now();
    const cfg = (input.config as IncidentConfig) ?? {};
    const cves = Array.isArray(cfg.cves) ? cfg.cves.filter((c) => typeof c === "string") : [];
    const secretRules = Array.isArray(cfg.secretRules)
      ? cfg.secretRules.filter((r) => typeof r === "string")
      : [];
    const timeoutMs =
      typeof cfg.timeoutMs === "number" && cfg.timeoutMs > 0
        ? cfg.timeoutMs
        : DEFAULT_TOOL_TIMEOUT_MS;

    // No targets — short-circuit with one info finding rather than
    // running full scans against the entire repo.
    if (cves.length === 0 && secretRules.length === 0) {
      const finding: NormalizedFinding = {
        fingerprint: fingerprint({
          providerName: this.name,
          ruleId: "incident.no-targets",
          file: input.repoLocalPath,
        }),
        ruleId: "incident.no-targets",
        title: "Incident response invoked with no targets",
        description:
          "input.config.cves[] and input.config.secretRules[] were both empty. " +
          "Provide at least one CVE id (for Grype) or secret rule id (for Gitleaks) to enable a targeted scan.",
        severity: "info",
        category: "policy",
        rawProviderRef: JSON.stringify({ cves, secretRules }),
      };
      return {
        runId: input.runId,
        status: "succeeded",
        findings: [finding],
        evidence: [],
        durationMs: Date.now() - startedAt,
        summary: summarize([finding]),
      };
    }

    try {
      if (!this.gitleaksPath || !this.grypePath) {
        await this.ensureToolInstalled();
      }
    } catch (err) {
      return {
        runId: input.runId,
        status: "errored",
        findings: [],
        evidence: [],
        durationMs: Date.now() - startedAt,
        summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        errorReason: `incident: tool resolution failed: ${String(err)}`,
      };
    }

    const findings: NormalizedFinding[] = [];
    const evidence: ScanEvidenceArtifact[] = [];
    let lastError: string | undefined;

    input.onProgress?.({
      pct: 10,
      message: `Targeted scan: ${cves.length} CVE(s), ${secretRules.length} secret rule(s)`,
    });

    // ---- Gitleaks (secrets) ----
    if (secretRules.length > 0) {
      try {
        const gitleaksSarif = path.join(input.workdir, "gitleaks.sarif");
        const args = [
          "detect",
          "--source",
          input.repoLocalPath,
          "--report-format",
          "sarif",
          "--report-path",
          gitleaksSarif,
          "--no-banner",
          "--exit-code",
          "0",
        ];
        if (cfg.gitleaksConfig) args.push("--config", cfg.gitleaksConfig);

        input.onProgress?.({ pct: 25, message: "Running Gitleaks (secrets)" });

        const res = await this.spawnAndWait(input.runId, this.gitleaksPath!, args, { timeoutMs });
        if (res.code !== 0 && res.code !== 1) {
          const msg = `gitleaks exited ${res.code}: ${res.stderr.slice(0, 500)}`;
          this.host?.logger?.warn?.(LOG_NAMESPACE, msg);
          if (!lastError) lastError = msg;
        } else {
          input.onProgress?.({ pct: 45, message: "Filtering Gitleaks findings" });
          try {
            const raw = await fs.readFile(gitleaksSarif, "utf-8");
            const all = normalizeSarif(raw, "gitleaks", "secret");
            const wanted = secretRules.map((r) => r.toLowerCase());
            const filtered = all.filter((f) => {
              const rid = f.ruleId.toLowerCase();
              return wanted.some((w) => rid.includes(w));
            });
            for (const f of filtered) findings.push(f);
            const sha256 = createHash("sha256").update(raw).digest("hex");
            const stat = await fs.stat(gitleaksSarif);
            evidence.push({
              type: "sarif",
              localPath: gitleaksSarif,
              sha256,
              sizeBytes: stat.size,
            });
          } catch (err) {
            this.host?.logger?.warn?.(LOG_NAMESPACE, `no gitleaks SARIF produced: ${String(err)}`);
          }
        }
      } catch (err) {
        const msg = `gitleaks step failed: ${String(err)}`;
        this.host?.logger?.error?.(LOG_NAMESPACE, msg);
        if (!lastError) lastError = msg;
      }
    }

    // ---- Grype (CVEs) ----
    if (cves.length > 0) {
      try {
        const grypeJsonPath = path.join(input.workdir, "grype.json");
        // Scan the working tree directly; --only-fixed=false to include
        // matches without an upstream fix, --quiet to keep stdout clean.
        const args = [
          `dir:${input.repoLocalPath}`,
          "--output",
          "json",
          "--file",
          grypeJsonPath,
          "--quiet",
          "--only-fixed=false",
        ];

        input.onProgress?.({ pct: 65, message: "Running Grype (CVEs)" });

        const res = await this.spawnAndWait(input.runId, this.grypePath!, args, { timeoutMs });
        // grype exit codes: 0 = success (regardless of findings). Any
        // non-zero is a real error for our purposes.
        if (res.code !== 0) {
          const msg = `grype exited ${res.code}: ${res.stderr.slice(0, 500)}`;
          this.host?.logger?.warn?.(LOG_NAMESPACE, msg);
          if (!lastError) lastError = msg;
        } else {
          input.onProgress?.({ pct: 85, message: "Filtering Grype findings" });
          try {
            const raw = await fs.readFile(grypeJsonPath, "utf-8");
            const all = normalizeGrype(raw, "grype");
            const wanted = new Set(cves.map((c) => c.toUpperCase()));
            const filtered = all.filter((f) => {
              const cve = (f.cve ?? f.ruleId ?? "").toUpperCase();
              return wanted.has(cve);
            });
            for (const f of filtered) findings.push(f);
            const sha256 = createHash("sha256").update(raw).digest("hex");
            const stat = await fs.stat(grypeJsonPath);
            evidence.push({
              type: "grype-json",
              localPath: grypeJsonPath,
              sha256,
              sizeBytes: stat.size,
            });
          } catch (err) {
            this.host?.logger?.warn?.(LOG_NAMESPACE, `no grype JSON produced: ${String(err)}`);
          }
        }
      } catch (err) {
        const msg = `grype step failed: ${String(err)}`;
        this.host?.logger?.error?.(LOG_NAMESPACE, msg);
        if (!lastError) lastError = msg;
      }
    }

    input.onProgress?.({ pct: 100, message: "Incident scan complete" });

    const summary = summarize(findings);
    const status =
      findings.length === 0 && lastError ? ("errored" as const) : ("succeeded" as const);

    return {
      runId: input.runId,
      status,
      findings,
      evidence,
      durationMs: Date.now() - startedAt,
      summary,
      errorReason: status === "errored" ? lastError : undefined,
    };
  }

  async cancel(runId: string): Promise<void> {
    const child = this.active.get(runId);
    if (!child) return;
    try {
      child.kill("SIGTERM");
      setTimeout(() => {
        try {
          child.kill("SIGKILL");
        } catch {
          /* already gone */
        }
      }, 5000);
    } finally {
      this.active.delete(runId);
    }
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
        "Targeted incident-response provider — pinned Gitleaks + Grype restricted to input.config.cves[] + input.config.secretRules[].",
    };
  }

  private spawnAndWait(
    runId: string,
    bin: string,
    args: string[],
    opts: { timeoutMs: number },
  ): Promise<{ code: number | null; stdout: string; stderr: string }> {
    return new Promise((resolve) => {
      const child = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"] });
      this.active.set(runId, child);
      let stdout = "";
      let stderr = "";
      const timer = setTimeout(() => {
        try {
          child.kill("SIGTERM");
        } catch {
          /* already gone */
        }
        setTimeout(() => {
          try {
            child.kill("SIGKILL");
          } catch {
            /* already gone */
          }
        }, 5000);
      }, opts.timeoutMs);
      child.stdout?.on("data", (b: Buffer) => (stdout += b.toString()));
      child.stderr?.on("data", (b: Buffer) => (stderr += b.toString()));
      child.on("close", (code) => {
        clearTimeout(timer);
        this.active.delete(runId);
        resolve({ code, stdout, stderr });
      });
      child.on("error", (err) => {
        clearTimeout(timer);
        this.active.delete(runId);
        resolve({ code: -1, stdout, stderr: err.message });
      });
    });
  }
}

function summarize(findings: NormalizedFinding[]): SecurityScanSummary {
  const s: SecurityScanSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) s[f.severity]++;
  return s;
}
