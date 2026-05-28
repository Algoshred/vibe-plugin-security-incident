/**
 * Gitleaks + Grype binary manifest for the incident-response provider.
 *
 * Gitleaks 8.21.2 is the same pin used by `vibe-plugin-security-secrets-pr`
 * so the agent can hard-link to a single shared cache entry.
 * Grype 0.83.0 is the same pin used by `vibe-plugin-security-rescan`.
 *
 * Bumping either version is a deliberate, audited operation: update the
 * version + sha256 here, re-run sanity, publish a new CalVer release.
 * Agents pick up the new pin via the new plugin version.
 */
import type { ToolManifest } from "@vibecontrols/vibe-plugin-security/tool-installer";

export const GITLEAKS_VERSION = "8.21.2";
export const GRYPE_VERSION = "0.83.0";

export const TOOLS_MANIFEST: ToolManifest = {
  gitleaks: {
    version: GITLEAKS_VERSION,
    binaryName: "gitleaks",
    versionMatcher: GITLEAKS_VERSION.replace(/\./g, "\\."),
    downloads: {
      "linux-x64": {
        url: `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz`,
        sha256: "5bc41815076e6ed6ef8fbecc9d9b75bcae31f39029ceb55da08086315316e3ba",
        binaryWithinArchive: "gitleaks",
        archive: "tar.gz",
      },
      "linux-arm64": {
        url: `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_arm64.tar.gz`,
        sha256: "654c935542c89f565aabe7bf7c6c500830f116c114f0aeb509d2460c1ac2e6da",
        binaryWithinArchive: "gitleaks",
        archive: "tar.gz",
      },
      "darwin-x64": {
        url: `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_darwin_x64.tar.gz`,
        sha256: "5b42c6e4b1fd693eaeb2b5b7faa5f17a1434299d4deb2de63d4b2efd7c753128",
        binaryWithinArchive: "gitleaks",
        archive: "tar.gz",
      },
      "darwin-arm64": {
        url: `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_darwin_arm64.tar.gz`,
        sha256: "cad3de5dc9a4d5447d967a70a4d49499c557f04db028274cc324f9ff983f6502",
        binaryWithinArchive: "gitleaks",
        archive: "tar.gz",
      },
    },
  },
  grype: {
    version: GRYPE_VERSION,
    binaryName: "grype",
    versionMatcher: GRYPE_VERSION.replace(/\./g, "\\."),
    downloads: {
      "linux-x64": {
        url: `https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz`,
        sha256: "d7e333b549a9f989948c4efe65ca9101fcd9cdd7ca39af78b7445abd7bfe4f26",
        binaryWithinArchive: "grype",
        archive: "tar.gz",
      },
      "linux-arm64": {
        url: `https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_arm64.tar.gz`,
        sha256: "80f13f7da2fe6afa684a236611eb9a49af0c05bdc532f41a39907766c841aad8",
        binaryWithinArchive: "grype",
        archive: "tar.gz",
      },
      "darwin-x64": {
        url: `https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_darwin_amd64.tar.gz`,
        sha256: "fc46f9ee5e76262f990834f120af63ab4952180a0d416228ad4fdf38bf02e1a3",
        binaryWithinArchive: "grype",
        archive: "tar.gz",
      },
      "darwin-arm64": {
        url: `https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_darwin_arm64.tar.gz`,
        sha256: "c9b2130a8312341476f4c624f95c58b5edf0a51b1d16263a96d6c985d74ba893",
        binaryWithinArchive: "grype",
        archive: "tar.gz",
      },
    },
  },
};
