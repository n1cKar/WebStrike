/**
 * Minimal multipart/form-data builder.
 *
 * The transport carries string bodies, which is sufficient for harmless,
 * text-based upload probes. No binary payloads are sent.
 */
export interface MultipartField {
  name: string;
  value: string;
}

export interface MultipartFile {
  fieldName: string;
  filename: string;
  contentType: string;
  content: string;
}

export interface MultipartBody {
  body: string;
  contentType: string;
}

export function buildMultipart(
  fields: MultipartField[],
  files: MultipartFile[],
  boundary = `----webstrike${globalThis.crypto.randomUUID().replace(/-/g, "")}`,
): MultipartBody {
  const parts: string[] = [];

  for (const field of fields) {
    parts.push(
      `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="${escapeQuotes(field.name)}"\r\n\r\n` +
        `${field.value}\r\n`,
    );
  }

  for (const file of files) {
    parts.push(
      `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="${escapeQuotes(file.fieldName)}"; filename="${escapeQuotes(file.filename)}"\r\n` +
        `Content-Type: ${file.contentType}\r\n\r\n` +
        `${file.content}\r\n`,
    );
  }

  parts.push(`--${boundary}--\r\n`);

  return {
    body: parts.join(""),
    contentType: `multipart/form-data; boundary=${boundary}`,
  };
}

function escapeQuotes(value: string): string {
  return value.replace(/"/g, "%22").replace(/[\r\n]/g, "");
}

export function formUrlEncoded(fields: MultipartField[]): string {
  return fields
    .map((f) => `${encodeURIComponent(f.name)}=${encodeURIComponent(f.value)}`)
    .join("&");
}
