import { beforeAll, afterAll, describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { CveSecretBlastRadiusProvider } from "../src/provider.js";
import { GITLEAKS_VERSION, GRYPE_VERSION } from "../src/tools-manifest.js";

const SAMPLE_GITLEAKS_SARIF = JSON.stringify({
  $schema: "https://json.schemastore.org/sarif-2.1.0.json",
  version: "2.1.0",
  runs: [
    {
      tool: { driver: { name: "gitleaks", version: GITLEAKS_VERSION } },
      results: [
        {
          ruleId: "stripe-access-token",
          level: "error",
          message: { text: "Stripe access token detected" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/config.js" },
                region: { startLine: 3, snippet: { text: "sk_live_redacted" } },
              },
            },
          ],
        },
        {
          ruleId: "aws-secret-key",
          level: "error",
          message: { text: "AWS secret key detected" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/aws.js" },
                region: { startLine: 7, snippet: { text: "redacted" } },
              },
            },
          ],
        },
        {
          ruleId: "github-pat",
          level: "warning",
          message: { text: "GitHub PAT detected" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/gh.js" },
                region: { startLine: 9 },
              },
            },
          ],
        },
      ],
    },
  ],
});

const SAMPLE_GRYPE_JSON = JSON.stringify({
  matches: [
    {
      vulnerability: {
        id: "CVE-2026-1234",
        severity: "High",
        description: "remote code execution in libfoo",
        fix: { versions: ["1.0.1"] },
      },
      artifact: {
        name: "libfoo",
        version: "1.0.0",
        locations: [{ path: "package.json" }],
      },
    },
    {
      vulnerability: {
        id: "CVE-2026-9999",
        severity: "Critical",
        description: "auth bypass in libbar",
        fix: { versions: [] },
      },
      artifact: {
        name: "libbar",
        version: "2.0.0",
        locations: [{ path: "package.json" }],
      },
    },
    {
      vulnerability: {
        id: "CVE-2026-5678",
        severity: "Medium",
        description: "DoS in libbaz",
        fix: { versions: ["3.0.1"] },
      },
      artifact: {
        name: "libbaz",
        version: "3.0.0",
        locations: [{ path: "package.json" }],
      },
    },
  ],
});

describe("CveSecretBlastRadiusProvider (static metadata)", () => {
  test("name + stage are immutable identifiers", () => {
    const p = new CveSecretBlastRadiusProvider();
    expect(p.name).toBe("cve-secret-blast-radius");
    expect(p.stage).toBe("incident.response");
  });

  test("toolVersion encodes both Gitleaks + Grype pins", () => {
    const p = new CveSecretBlastRadiusProvider();
    expect(p.toolVersion).toContain(GITLEAKS_VERSION);
    expect(p.toolVersion).toContain(GRYPE_VERSION);
  });

  test("metadata supports backend + container + iac profiles", () => {
    const p = new CveSecretBlastRadiusProvider();
    const m = p.metadata();
    expect(m.stage).toBe("incident.response");
    expect(m.supportedProfiles).toContain("backend");
    expect(m.supportedProfiles).toContain("container");
    expect(m.supportedProfiles).toContain("iac");
  });

  test("cancel() on unknown run is a no-op", async () => {
    const p = new CveSecretBlastRadiusProvider();
    await expect(p.cancel("nope")).resolves.toBeUndefined();
  });

  test("run() with empty targets returns the no-targets info finding", async () => {
    const p = new CveSecretBlastRadiusProvider();
    const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "incident-empty-"));
    const workdir = path.join(dataDir, "work");
    await fs.mkdir(workdir, { recursive: true });
    try {
      await p.init({
        getDataDir: () => dataDir,
        logger: { info: () => {}, warn: () => {}, error: () => {} },
      } as unknown as Parameters<CveSecretBlastRadiusProvider["init"]>[0]);
      const res = await p.run({
        runId: "empty-1",
        vibeId: "v",
        workspaceId: "ws",
        repoUrl: "git://x",
        repoLocalPath: dataDir,
        commit: "0",
        stage: "incident.response",
        profile: { kind: "backend", languages: [], runtimes: [] },
        policyLevel: "advisory",
        config: {},
        workdir,
      });
      expect(res.status).toBe("succeeded");
      expect(res.findings.length).toBe(1);
      expect(res.findings[0].ruleId).toBe("incident.no-targets");
      expect(res.findings[0].severity).toBe("info");
      expect(res.evidence.length).toBe(0);
    } finally {
      await fs.rm(dataDir, { recursive: true, force: true });
    }
  });
});

describe("CveSecretBlastRadiusProvider (fixture run)", () => {
  let tmpRoot: string;
  let fakeBinDir: string;
  let originalPath: string | undefined;

  beforeAll(async () => {
    tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), "incident-test-"));
    fakeBinDir = path.join(tmpRoot, "bin");
    await fs.mkdir(fakeBinDir, { recursive: true });

    const gitleaksFixture = path.join(tmpRoot, "gitleaks.sarif.fixture");
    const grypeFixture = path.join(tmpRoot, "grype.json.fixture");
    await fs.writeFile(gitleaksFixture, SAMPLE_GITLEAKS_SARIF);
    await fs.writeFile(grypeFixture, SAMPLE_GRYPE_JSON);

    // Fake gitleaks: when called with `detect --report-path X`, copy
    // the SARIF fixture to X. --version prints the pinned version.
    const fakeGitleaks = path.join(fakeBinDir, "gitleaks");
    await fs.writeFile(
      fakeGitleaks,
      `#!/usr/bin/env bash
set -e
i=0
args=("$@")
out=""
while [ $i -lt \${#args[@]} ]; do
  if [ "\${args[$i]}" = "--report-path" ]; then
    j=$((i+1))
    out="\${args[$j]}"
    break
  fi
  if [ "\${args[$i]}" = "--version" ]; then
    echo "${GITLEAKS_VERSION}"
    exit 0
  fi
  i=$((i+1))
done
if [ -n "$out" ]; then
  cp "${gitleaksFixture}" "$out"
fi
exit 0
`,
    );
    await fs.chmod(fakeGitleaks, 0o755);

    // Fake grype: writes JSON to --file. --version prints the pinned version.
    const fakeGrype = path.join(fakeBinDir, "grype");
    await fs.writeFile(
      fakeGrype,
      `#!/usr/bin/env bash
set -e
i=0
args=("$@")
out=""
while [ $i -lt \${#args[@]} ]; do
  if [ "\${args[$i]}" = "--file" ]; then
    j=$((i+1))
    out="\${args[$j]}"
    break
  fi
  if [ "\${args[$i]}" = "--version" ]; then
    echo "grype ${GRYPE_VERSION}"
    exit 0
  fi
  i=$((i+1))
done
if [ -n "$out" ]; then
  cp "${grypeFixture}" "$out"
fi
exit 0
`,
    );
    await fs.chmod(fakeGrype, 0o755);

    originalPath = process.env.PATH;
    process.env.PATH = `${fakeBinDir}:${originalPath ?? ""}`;
  });

  afterAll(async () => {
    if (originalPath !== undefined) process.env.PATH = originalPath;
    await fs.rm(tmpRoot, { recursive: true, force: true });
  });

  test("run() filters Gitleaks findings by secretRules[] (case-insensitive substring)", async () => {
    const provider = new CveSecretBlastRadiusProvider();
    const dataDir = path.join(tmpRoot, "agent-data-secrets");
    await fs.mkdir(dataDir, { recursive: true });
    await provider.init({
      getDataDir: () => dataDir,
      logger: { info: () => {}, warn: () => {}, error: () => {} },
    } as unknown as Parameters<CveSecretBlastRadiusProvider["init"]>[0]);

    const workdir = path.join(tmpRoot, "work-secrets");
    await fs.mkdir(workdir, { recursive: true });

    const result = await provider.run({
      runId: "secrets-only",
      vibeId: "v",
      workspaceId: "ws",
      repoUrl: "git://x",
      repoLocalPath: tmpRoot,
      commit: "0",
      stage: "incident.response",
      profile: { kind: "backend", languages: [], runtimes: [] },
      policyLevel: "advisory",
      config: {
        // Match stripe-access-token + aws-secret-key but NOT github-pat.
        secretRules: ["stripe-access-token", "aws-secret-key"],
      },
      workdir,
    });

    expect(result.status).toBe("succeeded");
    const ruleIds = result.findings.map((f) => f.ruleId).sort();
    expect(ruleIds).toEqual(["aws-secret-key", "stripe-access-token"]);
    expect(result.findings.every((f) => f.category === "secret")).toBe(true);
    expect(result.evidence.length).toBe(1);
    expect(result.evidence[0].type).toBe("sarif");
  });

  test("run() filters Grype findings by cves[]", async () => {
    const provider = new CveSecretBlastRadiusProvider();
    const dataDir = path.join(tmpRoot, "agent-data-cves");
    await fs.mkdir(dataDir, { recursive: true });
    await provider.init({
      getDataDir: () => dataDir,
      logger: { info: () => {}, warn: () => {}, error: () => {} },
    } as unknown as Parameters<CveSecretBlastRadiusProvider["init"]>[0]);

    const workdir = path.join(tmpRoot, "work-cves");
    await fs.mkdir(workdir, { recursive: true });

    const result = await provider.run({
      runId: "cves-only",
      vibeId: "v",
      workspaceId: "ws",
      repoUrl: "git://x",
      repoLocalPath: tmpRoot,
      commit: "0",
      stage: "incident.response",
      profile: { kind: "backend", languages: [], runtimes: [] },
      policyLevel: "advisory",
      config: { cves: ["CVE-2026-1234", "CVE-2026-5678"] },
      workdir,
    });

    expect(result.status).toBe("succeeded");
    const cveIds = result.findings.map((f) => f.cve).sort();
    expect(cveIds).toEqual(["CVE-2026-1234", "CVE-2026-5678"]);
    expect(result.findings.every((f) => f.category === "vuln")).toBe(true);
    expect(result.evidence.length).toBe(1);
    expect(result.evidence[0].type).toBe("grype-json");
  });

  test("run() combines secretRules + cves filtering when both are present", async () => {
    const provider = new CveSecretBlastRadiusProvider();
    const dataDir = path.join(tmpRoot, "agent-data-both");
    await fs.mkdir(dataDir, { recursive: true });
    await provider.init({
      getDataDir: () => dataDir,
      logger: { info: () => {}, warn: () => {}, error: () => {} },
    } as unknown as Parameters<CveSecretBlastRadiusProvider["init"]>[0]);

    const workdir = path.join(tmpRoot, "work-both");
    await fs.mkdir(workdir, { recursive: true });

    const result = await provider.run({
      runId: "both",
      vibeId: "v",
      workspaceId: "ws",
      repoUrl: "git://x",
      repoLocalPath: tmpRoot,
      commit: "0",
      stage: "incident.response",
      profile: { kind: "backend", languages: [], runtimes: [] },
      policyLevel: "advisory",
      config: {
        secretRules: ["stripe-access-token"],
        cves: ["CVE-2026-9999"],
      },
      workdir,
    });

    expect(result.status).toBe("succeeded");
    expect(result.findings.length).toBe(2);
    expect(result.findings.some((f) => f.ruleId === "stripe-access-token")).toBe(true);
    expect(result.findings.some((f) => f.cve === "CVE-2026-9999")).toBe(true);
    expect(result.evidence.length).toBe(2);
  });
});
