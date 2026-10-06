import {
  defineCreate,
  defineInputFields,
  type CreatePerform,
} from "zapier-platform-core";
import { randomUUID } from "node:crypto";
import FormData from "form-data";
import { requireInboundMessage, normalizeChatGuid } from "./inboundCheck.js";

// Helper to detect private/internal IP addresses and hostnames (SSRF protection)
function isPrivateOrInternalHost(hostname: string): boolean {
  // Block localhost
  if (hostname === "localhost" || hostname === "localhost.localdomain") {
    return true;
  }
  // Block IPv4 loopback
  if (hostname === "127.0.0.1" || hostname.startsWith("127.")) {
    return true;
  }
  // Block IPv6 loopback
  if (hostname === "::1" || hostname === "::ffff:127.0.0.1") {
    return true;
  }
  // Block link-local (IPv4 and IPv6)
  if (hostname === "169.254.169.254" || hostname.startsWith("169.254.")) {
    return true;
  }
  if (hostname.startsWith("fe80:")) {
    return true;
  }
  // Block private IPv4 ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
  const ipv4Match = hostname.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (ipv4Match) {
    const o1 = Number(ipv4Match[1] ?? 0);
    const o2 = Number(ipv4Match[2] ?? 0);
    if (o1 === 10) return true;
    if (o1 === 172 && o2 >= 16 && o2 <= 31) return true;
    if (o1 === 192 && o2 === 168) return true;
    if (o1 === 0) return true; // 0.0.0.0/8
  }
  // Block private IPv6 ranges (fc00::/7 - ULA)
  if (hostname.startsWith("fc") || hostname.startsWith("fd")) {
    return true;
  }
  return false;
}

const inputFields = defineInputFields([
  {
    key: "chatGuid",
    label: "Chat",
    type: "string",
    required: true,
    helpText:
      "Phone number, email, or group chat ID. Usually mapped from a trigger step (e.g. +1234567890 or a Chat GUID).",
  },
  {
    key: "fileUrl",
    label: "File URL",
    type: "string",
    required: true,
    helpText: "A public URL to the file to send (image, video, PDF, etc.). Map from a previous step or paste a link.",
  },
  {
    key: "fileName",
    label: "Custom File Name",
    type: "string",
    required: false,
    helpText: "Override the file name (e.g. photo.jpg). Auto-detected if left blank.",
  },
  {
    key: "isAudioMessage",
    label: "Send as Voice Message",
    type: "boolean",
    required: false,
    default: "false",
    helpText: "Send as a playable voice message instead of a file. The file must be .caf or .m4a audio.",
  },
]);

const perform = (async (z, bundle) => {
  const chatGuid = normalizeChatGuid(bundle.inputData.chatGuid as string);
  await requireInboundMessage(z, bundle, chatGuid);
  const fileUrl = bundle.inputData.fileUrl as string;

  // SSRF protection: validate URL scheme and host
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(fileUrl);
  } catch {
    throw new z.errors.Error(
      "Invalid File URL. Must be a valid HTTP/HTTPS URL.",
      "InvalidData",
    );
  }
  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    throw new z.errors.Error(
      "File URL must use HTTP or HTTPS.",
      "InvalidData",
    );
  }
  // Block private/internal addresses
  const hostname = parsedUrl.hostname;
  const isPrivate = isPrivateOrInternalHost(hostname);
  if (isPrivate) {
    throw new z.errors.Error(
      "File URL host is not allowed (private/internal address).",
      "InvalidData",
    );
  }

  let fileResponse: { content?: string; buffer?: () => Promise<Buffer>; status?: number };
  try {
    // Add timeout (30 seconds) to prevent resource exhaustion
    fileResponse = await z.request({
      url: fileUrl,
      raw: true,
      redirect: "follow",
      timeout: 30000, // 30 seconds
    }) as unknown as { content?: string; buffer?: () => Promise<Buffer>; status?: number };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new z.errors.Error(
      `Could not fetch file from URL: ${msg}. Use a direct, publicly accessible link to the file.`,
      "FetchError",
    );
  }
  let buffer: Buffer;
  if (typeof fileResponse.buffer === "function") {
    buffer = await fileResponse.buffer();
  } else if (fileResponse.content != null) {
    buffer = Buffer.isBuffer(fileResponse.content)
      ? fileResponse.content
      : Buffer.from(fileResponse.content, typeof fileResponse.content === "string" ? "utf8" : undefined);
  } else {
    const raw = fileResponse as unknown as { arrayBuffer?: () => Promise<ArrayBuffer> };
    if (typeof raw.arrayBuffer === "function") {
      buffer = Buffer.from(await raw.arrayBuffer());
    } else {
      throw new z.errors.Error(
        "Could not read file data from URL. Use a direct link to an image or file (no redirects or HTML pages).",
        "InvalidAttachment",
      );
    }
  }
  if (!buffer || buffer.length === 0) {
    throw new z.errors.Error(
      "Attachment was empty or could not be downloaded. Use a direct URL to a non-empty file.",
      "EmptyAttachment",
    );
  }

  const fileName =
    bundle.inputData.fileName ||
    fileUrl.split("/").pop()?.split("?")[0] ||
    "attachment";

  const form = new FormData();
  form.append("chatGuid", chatGuid);
  form.append("attachment", buffer, { filename: fileName });
  form.append("name", fileName);
  form.append("tempGuid", randomUUID());
  form.append("isAudioMessage", String(bundle.inputData.isAudioMessage === true));
  if (bundle.inputData.isAudioMessage === true) {
    form.append("method", "private-api");
  }

  const response = await z.request({
    url: `${bundle.authData.serverUrl}/api/v1/message/attachment`,
    method: "POST",
    headers: form.getHeaders(),
    body: form,
  });

  const data = response.data as Record<string, unknown>;
  const out = data?.data ?? data;
  const result = (typeof out === "object" && out !== null ? out : {}) as Record<string, unknown>;
  return {
    id: result.guid ?? result.id ?? `${chatGuid}-attachment`,
    ...result,
  };
}) satisfies CreatePerform<typeof inputFields>;

export default defineCreate({
  key: "send_attachment",
  noun: "Attachment",

  display: {
    label: "Send Attachment",
    description:
      "Send a file, image, or audio message via iMessage. Provide a public URL to the file.",
  },

  operation: {
    inputFields,
    perform,
    sample: {
      id: "attachment-1234",
      status: 200,
      message: "Attachment sent successfully",
    },
    outputFields: [
      { key: "id", label: "ID" },
      { key: "status", label: "Status", type: "integer" },
      { key: "message", label: "Message" },
    ],
  },
});
