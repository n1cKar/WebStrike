"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import {
  Clipboard,
  Eraser,
  Loader2,
  PlusCircle,
  RotateCcw,
  Send,
  ShieldAlert,
  Square,
} from "lucide-react";
import type { RequestMethod, ScopedHttpResult } from "@webstrike/types";
import type { RequestSpecInput } from "@webstrike/validation";
import { Button } from "@/components/ui/button";
import { Input, Label, Textarea } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { KeyValueEditor, type KeyValueRow } from "./key-value-editor";
import { ResponsePanel } from "./response-panel";
import { useTestingSession } from "@/lib/hooks/use-session";
import { useEphemeralResults } from "@/lib/results/store";
import { apiFetch, ApiClientError } from "@/lib/api/client";
import { redactHeaderValue } from "@/lib/http/format";

const METHODS: RequestMethod[] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

function rowsToRecord(rows: KeyValueRow[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const row of rows) {
    if (row.name.trim()) out[row.name.trim()] = row.value;
  }
  return out;
}

interface RequestApiResponse {
  result: ScopedHttpResult;
  analysis: import("@/lib/analysis").ResponseAnalysis;
}

export function RepeaterView() {
  const { data } = useTestingSession();
  const session = data?.session ?? null;
  const { entries, markPending, resolve, fail, recordTests, discard } = useEphemeralResults();

  const [method, setMethod] = useState<RequestMethod>("GET");
  const [url, setUrl] = useState("");
  const [query, setQuery] = useState<KeyValueRow[]>([]);
  const [headers, setHeaders] = useState<KeyValueRow[]>([
    { name: "Accept", value: "application/json" },
  ]);
  const [cookies, setCookies] = useState<KeyValueRow[]>([]);
  const [body, setBody] = useState("");
  const [contentType, setContentType] = useState("application/json");
  const [activeId, setActiveId] = useState<string | null>(null);
  const [responseTab, setResponseTab] = useState("body");
  const [localError, setLocalError] = useState<string | null>(null);

  const abortRef = useRef<AbortController | null>(null);
  const seededFor = useRef<string | null>(null);

  useEffect(() => {
    if (session && seededFor.current !== session.id) {
      seededFor.current = session.id;
      setUrl(session.targetUrl);
    }
  }, [session]);

  const activeEntry = useMemo(
    () => entries.find((e) => e.id === activeId) ?? entries[0] ?? null,
    [entries, activeId],
  );

  const previousResult = useMemo(() => {
    if (!activeEntry) return null;
    const index = entries.findIndex((e) => e.id === activeEntry.id);
    for (let i = index + 1; i < entries.length; i += 1) {
      const candidate = entries[i];
      if (candidate?.result) return candidate.result;
    }
    return null;
  }, [entries, activeEntry]);

  const inactive = !session || session.status !== "active" || Date.now() >= session.expiresAt;

  function buildSpec(): RequestSpecInput | null {
    setLocalError(null);
    if (!url.trim()) {
      setLocalError("enter a target URL");
      return null;
    }
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      setLocalError("target URL is malformed");
      return null;
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      setLocalError("only http and https URLs are supported");
      return null;
    }

    return {
      id: crypto.randomUUID(),
      method,
      url,
      query: rowsToRecord(query),
      headers: headers.filter((h) => h.name.trim()),
      cookies: cookies.filter((c) => c.name.trim()),
      body: body.length ? body : null,
      contentType: contentType.trim() || null,
    };
  }

  async function send(options: { analysis?: boolean } = {}) {
    if (inactive) {
      setLocalError("no active testing session — create one first");
      return;
    }
    const spec = buildSpec();
    if (!spec) return;

    markPending(spec);
    setActiveId(spec.id);
    setResponseTab("body");

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const payload = await apiFetch<RequestApiResponse>("/api/request", {
        method: "POST",
        body: JSON.stringify(spec),
        signal: controller.signal,
      });
      resolve(spec.id, payload.result, payload.analysis);
      recordTests(payload.analysis.headers.length + payload.analysis.cookies.length);
      if (options.analysis) setResponseTab("analysis");
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        fail(spec.id, "request cancelled by operator");
      } else if (err instanceof ApiClientError) {
        fail(
          spec.id,
          err.detail ? `${err.message} — ${String(err.detail)}` : err.message,
        );
      } else {
        fail(spec.id, "request failed before reaching the network");
      }
    } finally {
      abortRef.current = null;
    }
  }

  function cancel() {
    abortRef.current?.abort();
  }

  function duplicate() {
    void send();
  }

  function reset() {
    setMethod("GET");
    setUrl(session?.targetUrl ?? "");
    setQuery([]);
    setHeaders([{ name: "Accept", value: "application/json" }]);
    setCookies([]);
    setBody("");
    setContentType("application/json");
    setLocalError(null);
  }

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
        event.preventDefault();
        void send();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [method, url, query, headers, cookies, body, contentType, inactive]);

  const rawPreview = useMemo(() => {
    const lines: string[] = [];
    let path = "/";
    let host = "";
    try {
      const parsed = new URL(url);
      path = parsed.pathname + (parsed.search || "");
      host = parsed.host;
    } catch {
      /* leave defaults */
    }
    lines.push(`${method} ${path} HTTP/1.1`);
    lines.push(`Host: ${host || "(invalid target)"}`);
    for (const header of headers) {
      if (!header.name.trim()) continue;
      lines.push(`${header.name}: ${redactHeaderValue(header.name, header.value)}`);
    }
    if (contentType.trim()) lines.push(`Content-Type: ${contentType}`);
    if (cookies.length) {
      lines.push(
        `Cookie: ${cookies.map((c) => `${c.name}=[REDACTED]`).join("; ")}`,
      );
    }
    if (body) {
      lines.push("");
      lines.push(body.length > 2000 ? `${body.slice(0, 2000)}\n… (${body.length} bytes)` : body);
    }
    return lines.join("\n");
  }, [method, url, headers, cookies, contentType, body]);

  return (
    <div className="mx-auto max-w-7xl space-y-4 p-4 sm:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight">Repeater</h1>
          <p className="mt-0.5 text-xs text-muted-foreground">
            Compose, send and inspect a single request. Every send is
            scope-validated and SSRF-filtered server-side.
          </p>
        </div>
        {session ? (
          <Badge variant={inactive ? "danger" : "success"} className="mono">
            {inactive ? "session inactive" : new URL(session.targetUrl).host}
          </Badge>
        ) : (
          <Button asChild size="sm">
            <Link href="/new-session">
              <PlusCircle className="size-3.5" /> Create session
            </Link>
          </Button>
        )}
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card className="min-w-0">
          <CardHeader>
            <CardTitle>Request</CardTitle>
            <span className="mono text-[10px] text-muted-foreground">
              ⌘/Ctrl + Enter to send
            </span>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center gap-2">
              <Select
                value={method}
                onChange={(e) => setMethod(e.target.value as RequestMethod)}
                className="mono w-28"
              >
                {METHODS.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </Select>
              <Input
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://app.example.com/api/resource"
                className="mono flex-1"
                autoComplete="off"
                spellCheck={false}
              />
            </div>

            <Section title="Query parameters">
              <KeyValueEditor
                rows={query}
                onChange={setQuery}
                namePlaceholder="param"
                valuePlaceholder="value"
                addLabel="Add parameter"
              />
            </Section>

            <Section title="Headers">
              <KeyValueEditor
                rows={headers}
                onChange={setHeaders}
                namePlaceholder="Header-Name"
                valuePlaceholder="value"
                addLabel="Add header"
              />
            </Section>

            <Section title="Cookies">
              <KeyValueEditor
                rows={cookies}
                onChange={setCookies}
                namePlaceholder="cookie"
                valuePlaceholder="value"
                addLabel="Add cookie"
              />
            </Section>

            <Section title="Body">
              <div className="space-y-2">
                <Input
                  value={contentType}
                  onChange={(e) => setContentType(e.target.value)}
                  placeholder="Content-Type"
                  className="mono h-8 text-xs"
                />
                <Textarea
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  placeholder='{"name":"Test User"}'
                  className="mono min-h-[120px] text-xs"
                  spellCheck={false}
                />
              </div>
            </Section>

            <details className="rounded-md border border-border bg-panel-2/40">
              <summary className="cursor-pointer px-3 py-2 text-xs text-muted-foreground">
                Parsed request preview
              </summary>
              <pre className="mono overflow-x-auto whitespace-pre-wrap border-t border-border p-3 text-[11px] leading-relaxed text-foreground/80">
                {rawPreview}
              </pre>
            </details>

            {localError && (
              <p className="rounded-md border border-warning/40 bg-warning/5 px-3 py-2 text-xs text-warning">
                {localError}
              </p>
            )}

            <div className="flex flex-wrap gap-2">
              <Button onClick={() => void send()} disabled={inactive}>
                <Send className="size-3.5" /> Send
              </Button>
              <Button variant="secondary" onClick={cancel}>
                <Square className="size-3.5" /> Cancel
              </Button>
              <Button variant="ghost" onClick={duplicate} disabled={inactive}>
                <Clipboard className="size-3.5" /> Duplicate
              </Button>
              <Button variant="ghost" onClick={reset}>
                <RotateCcw className="size-3.5" /> Reset
              </Button>
              <Button
                variant="ghost"
                onClick={() => setResponseTab("compare")}
                disabled={!activeEntry?.result}
              >
                Compare
              </Button>
              <Button
                variant="secondary"
                onClick={() => void send({ analysis: true })}
                disabled={inactive}
              >
                <ShieldAlert className="size-3.5" /> Run security checks
              </Button>
              {abortRef.current && <Loader2 className="size-4 animate-spin" />}
            </div>
          </CardContent>
        </Card>

        <Card className="min-w-0 overflow-hidden">
          <CardHeader>
            <CardTitle>Response</CardTitle>
            {activeEntry?.result && (
              <button
                type="button"
                onClick={() => discard(activeEntry.id)}
                className="flex items-center gap-1 text-[10px] text-muted-foreground hover:text-danger"
              >
                <Eraser className="size-3" /> discard
              </button>
            )}
          </CardHeader>
          <CardContent className="p-0">
            <ResponsePanel
              result={activeEntry?.result ?? null}
              analysis={activeEntry?.analysis ?? null}
              previous={previousResult}
              pending={activeEntry?.status === "pending"}
              error={activeEntry?.status === "error" ? activeEntry.error : undefined}
              tab={responseTab}
              onTabChange={setResponseTab}
            />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-2">
      <Label>{title}</Label>
      {children}
    </div>
  );
}