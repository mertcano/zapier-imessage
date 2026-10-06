import type {
  Authentication,
  BeforeRequestMiddleware,
  ZObject,
  Bundle,
} from "zapier-platform-core";

/** @see https://webhook.photon.codes/ */
export const WEBHOOK_BRIDGE_URL = "https://webhook.photon.codes";

/**
 * Strips trailing slashes and collapses double slashes in the path portion,
 * leaving the protocol double-slash intact.
 */
export const normalizeUrl = (url: string): string =>
  (url || "")
    .replace(/\/+$/, "")
    .replace(/(https?:\/\/)\/+/g, "$1")
    .replace(/([^:])\/\/+/g, "$1/");

/**
 * Adds X-API-Key and normalizes the URL only for requests aimed at the
 * user's Photon server. External URLs (file downloads, bridge calls) are
 * left untouched so we don't mangle signed URLs or inject extra headers.
 */
export const addApiKeyToHeader: BeforeRequestMiddleware = (
  request,
  _z,
  bundle,
) => {
  const url = normalizeUrl(request.url ?? "");
  const serverUrl = normalizeUrl(bundle.authData.serverUrl as string);
  const isBridge = url.startsWith(WEBHOOK_BRIDGE_URL);
  // Use proper origin comparison to prevent prefix-match attacks.
  // e.g., attacker.tld/https://server.photon.codes should NOT match.
  let isServerRequest = false;
  try {
    const urlOrigin = new URL(url).origin;
    const serverOrigin = new URL(serverUrl).origin;
    isServerRequest = urlOrigin === serverOrigin;
  } catch {
    // Malformed URL: treat as not matching for safety
    isServerRequest = false;
  }

  if (isServerRequest || isBridge) {
    request.url = url;
  }
  if (isServerRequest) {
    request.headers = {
      ...request.headers,
      "X-API-Key": bundle.authData.apiKey as string,
    };
  }

  return request;
};

/**
 * Auth test: validate Endpoint + API Key against the Photon server.
 */
const requireHttps = (url: string, z: ZObject): void => {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:") {
    throw new z.errors.Error(
      "Endpoint must use HTTPS (e.g. https://yourserver.imsgd.photon.codes).",
      "InvalidData",
      400,
    );
  }
};

const authTest = async (z: ZObject, bundle: Bundle) => {
  const baseUrl = normalizeUrl(bundle.authData.serverUrl as string);
  requireHttps(baseUrl, z);

  const response = await z.request({
    url: `${baseUrl}/api/v1/server/info`,
    method: "GET",
    skipThrowForStatus: true,
  });

  if (response.status === 401 || response.status === 403) {
    throw new z.errors.Error(
      "Invalid API key.",
      "AuthenticationError",
      response.status,
    );
  }

  if (response.status === 404) {
    throw new z.errors.Error(
      `Cannot reach Photon server at "${baseUrl}". Check the Endpoint URL and that the server is running.`,
      "NotFoundError",
      response.status,
    );
  }

  if (response.status >= 400) {
    throw new z.errors.Error(
      `Server error (HTTP ${response.status}). Verify Endpoint and API Key.`,
      "ApiError",
      response.status,
    );
  }

  const body = response.data;
  const bodyStr = typeof body === "string" ? body : JSON.stringify(body ?? "");
  if (
    bodyStr.toLowerCase().includes("github") ||
    (typeof body === "string" && body.trimStart().startsWith("<!"))
  ) {
    throw new z.errors.Error(
      "Endpoint URL looks wrong (got a web page). Use your Photon iMessage server URL only (e.g. https://yourserver.imsgd.photon.codes).",
      "ApiError",
      400,
    );
  }

  return { serverUrl: baseUrl };
};

const authentication: Authentication = {
  type: "custom",
  fields: [
    {
      key: "serverUrl",
      label: "Endpoint",
      type: "string",
      required: true,
      default: "https://example.imsgd.photon.codes",
      helpText:
        "Your Photon iMessage server URL (e.g. https://yourserver.imsgd.photon.codes).",
    },
    {
      key: "apiKey",
      label: "API Key",
      type: "string",
      required: true,
      computed: false,
      helpText:
        "API key for your Photon server. When you turn on a Zap, the webhook is registered automatically and events flow in real-time.",
    },
  ],
  test: authTest,
  connectionLabel: "{{bundle.authData.serverUrl}}",
};

export default authentication;
