import { describe, expect, test } from "bun:test";

import { CveSecretBlastRadiusProvider } from "../src/provider.js";
import { GITLEAKS_VERSION, GRYPE_VERSION } from "../src/tools-manifest.js";

describe("CveSecretBlastRadiusProvider", () => {
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
});
