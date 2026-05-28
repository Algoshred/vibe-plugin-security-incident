/**
 * @vibecontrols/vibe-plugin-security-incident
 *
 * Targeted incident-response provider. Registers as a `security.incident`
 * provider with @vibecontrols/vibe-plugin-security on the host's
 * ServiceRegistry. The user picks "cve-secret-blast-radius" as their
 * default provider for the `incident.response` stage and the meta
 * plugin dispatches.
 *
 * Wave 2 scaffold — real Gitleaks + Grype invocation pending.
 */
import { ProviderRegistry, TelemetryEmitter, createLifecycleHooks } from "@vibecontrols/plugin-sdk";
import type {
  HostServices,
  ProfileContext,
  VibePlugin,
  VibePluginFactory,
} from "@vibecontrols/plugin-sdk/contract";

import { CveSecretBlastRadiusProvider } from "./provider.js";

const PLUGIN_NAME = "security-incident";
const PLUGIN_VERSION = "2026.528.2";

export const createPlugin: VibePluginFactory = (_ctx: ProfileContext): VibePlugin => {
  const provider = new CveSecretBlastRadiusProvider();
  const telemetry = new TelemetryEmitter(PLUGIN_NAME, PLUGIN_VERSION);

  const lifecycle = createLifecycleHooks({
    name: PLUGIN_NAME,
    telemetryEventName: "security.incident.ready",
    onInit: async (host: HostServices) => {
      await provider.init(host);
      const registry = new ProviderRegistry(host);
      registry.registerProvider("security.incident", "cve-secret-blast-radius", provider);
      telemetry.emit("security.incident.registered", {
        provider: "cve-secret-blast-radius",
        toolVersion: provider.toolVersion,
      });
    },
  });

  return {
    name: PLUGIN_NAME,
    version: PLUGIN_VERSION,
    description:
      "Targeted incident-response scanner for the incident.response lifecycle stage (pinned Gitleaks + Grype).",
    tags: ["backend", "provider", "integration"],
    capabilities: {
      storage: "rw",
      subprocess: true,
      audit: true,
      telemetry: true,
    },
    onServerStart: lifecycle.onServerStart,
    onServerStop: lifecycle.onServerStop,
  };
};

export default createPlugin;
export { CveSecretBlastRadiusProvider } from "./provider.js";
