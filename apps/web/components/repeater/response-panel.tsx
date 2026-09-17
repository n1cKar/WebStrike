"use client";

import { useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowRightLeft,
  CheckCircle2,
  Clock,
  FileText,
  Info,
  Search,
} from "lucide-react";
import type { ScopedHttpResult } from "@webstrike/types";
import type { ResponseAnalysis } from "@/lib/analysis";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { StatusBadge } from "@/components/security/method-badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cn, formatBytes, formatDuration } from "@/lib/utils";
import { countDiff, lineDiff, looksLikeJson, tryFormatJson } from "@/lib/http/format";

const MAX_DISPLAY_CHARS = 200_000;

function Highlight({ text, query }: { text: string; query: string }) {
  if (!query) return <>{text}</>;
  const parts = text.split(query);
  return (
    <>
      {parts.map((part, index) => (
        <span key={index}>
          {part}
          {index < parts.length - 1 && (
            <mark className="rounded bg-warning/30 text-warning">{query}</mark>
          )}
        </span>
      ))}
    </>
  );
}

function BodyView({ result, query }: { result: ScopedHttpResult; query: string }) {
  const [pretty, setPretty] = useState(true);
  const display = result.body.slice(0, MAX_DISPLAY_CHARS);
  const isJson = looksLikeJson(result.headers["content-type"], result.body);
  const formatted = useMemo(
    () => (isJson && pretty ? tryFormatJson(display) : { ok: false, text: display }),
    [display, isJson, pretty],
  );

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 border-b border-border px-3 py-2">
        {isJson && (
          <button
            type="button"
            onClick={() => setPretty((v) => !v)}
            className="mono rounded border border-border px-2 py-0.5 text-[11px] text-muted-foreground hover:text-foreground"
          >
            {pretty ? "pretty" : "raw"}
          </button>
        )}
        <span className="mono text-[11px] text-muted-foreground">
          {formatBytes(result.bodyBytes)}
          {result.bodyTruncated && " (truncated at cap)"}
        </span>
        {display.length < result.body.length && (
          <span className="text-[11px] text-warning">
            showing first {formatBytes(MAX_DISPLAY_CHARS)}
          </span>
        )}
      </div>
      <pre className="mono max-h-[52vh] flex-1 overflow-auto whitespace-pre-wrap break-all p-3 text-xs leading-relaxed text-foreground/90">
        <Highlight text={formatted.text || "(empty body)"} query={query} />
      </pre>
    </div>
  );
}

function HeadersView({
  result,
  query,
}: {
  result: ScopedHttpResult;
  query: string;
}) {
  const rows = Object.entries(result.headers).filter(([k, v]) =>
    query ? `${k}: ${v}`.toLowerCase().includes(query.toLowerCase()) : true,
  );

  if (rows.length === 0) {
    return <p className="p-4 text-xs text-muted-foreground">No headers to show.</p>;
  }

  return (
    <div className="max-h-[52vh] overflow-auto p-2">
      <table className="w-full text-left text-xs">
        <tbody>
          {rows.map(([name, value]) => (
            <tr key={name} className="border-b border-border/60 last:border-0">
              <td className="mono whitespace-nowrap py-1.5 pr-3 align-top text-accent">
                {name}
              </td>
              <td className="mono break-all py-1.5 text-foreground/90">
                <Highlight text={value} query={query} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CookiesView({ result }: { result: ScopedHttpResult }) {
  if (result.cookies.length === 0) {
    return (
      <p className="p-4 text-xs text-muted-foreground">
        No Set-Cookie headers in this response.
      </p>
    );
  }
  return (
    <div className="max-h-[52vh] space-y-2 overflow-auto p-3">
      {result.cookies.map((cookie) => (
        <div
          key={cookie.name + cookie.raw}
          className="rounded-md border border-border bg-panel-2/50 p-3"
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="mono text-xs font-semibold text-foreground">
              {cookie.name}
            </span>
            <span className="mono break-all text-[11px] text-muted-foreground">
              {cookie.value.slice(0, 80)}
              {cookie.value.length > 80 ? "…" : ""}
            </span>
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            <Badge variant={cookie.secure ? "success" : "danger"}>
              {cookie.secure ? "Secure" : "no Secure"}
            </Badge>
            <Badge variant={cookie.httpOnly ? "success" : "warning"}>
              {cookie.httpOnly ? "HttpOnly" : "no HttpOnly"}
            </Badge>
            <Badge variant={cookie.sameSite ? "info" : "warning"}>
              {cookie.sameSite ? `SameSite=${cookie.sameSite}` : "no SameSite"}
            </Badge>
            {cookie.domain && (
              <Badge variant="muted" className="mono">
                domain={cookie.domain}
              </Badge>
            )}
            {cookie.path && (
              <Badge variant="muted" className="mono">
                path={cookie.path}
              </Badge>
            )}
            {cookie.expires && (
              <Badge variant="muted" className="mono">
                expires={new Date(cookie.expires).toISOString().slice(0, 10)}
              </Badge>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

function AnalysisView({ analysis }: { analysis: ResponseAnalysis }) {
  const headers = analysis.headers.filter((h) => h.present);
  const missing = analysis.headers.filter((h) => !h.present);

  return (
    <div className="max-h-[52vh] space-y-4 overflow-auto p-3 text-xs">
      {analysis.notes.length > 0 && (
        <div className="space-y-1.5">
          {analysis.notes.map((note) => (
            <div
              key={note}
              className="flex items-start gap-2 rounded-md border border-warning/30 bg-warning/5 p-2 text-warning"
            >
              <Info className="mt-0.5 size-3.5 shrink-0" />
              <span>{note}</span>
            </div>
          ))}
        </div>
      )}

      {headers.length > 0 && (
        <section>
          <h4 className="mb-2 text-[10px] uppercase tracking-widest text-muted-foreground">
            Observed security headers
          </h4>
          <div className="space-y-1.5">
            {headers.map((h) => (
              <div
                key={h.header}
                className="rounded-md border border-border bg-panel-2/40 p-2"
              >
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="size-3.5 text-success" />
                  <span className="mono text-[11px] text-foreground">{h.header}</span>
                </div>
                <p className="mt-1 leading-relaxed text-muted-foreground">
                  {h.message}
                </p>
              </div>
            ))}
          </div>
        </section>
      )}

      {analysis.cookies.length > 0 && (
        <section>
          <h4 className="mb-2 text-[10px] uppercase tracking-widest text-muted-foreground">
            Cookie attributes
          </h4>
          <div className="space-y-1.5">
            {analysis.cookies.map((c) => (
              <div
                key={c.cookie}
                className="rounded-md border border-border bg-panel-2/40 p-2"
              >
                <span className="mono text-[11px] text-foreground">{c.cookie}</span>
                {c.observations.length === 0 ? (
                  <p className="mt-1 text-success">Secure, HttpOnly and SameSite set.</p>
                ) : (
                  <ul className="mt-1 list-inside list-disc space-y-0.5 text-muted-foreground">
                    {c.observations.map((o) => (
                      <li key={o}>{o}</li>
                    ))}
                  </ul>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      <section>
        <h4 className="mb-2 text-[10px] uppercase tracking-widest text-muted-foreground">
          Not observed ({missing.length})
        </h4>
        <div className="flex flex-wrap gap-1.5">
          {missing.map((h) => (
            <Badge key={h.header} variant="muted" className="mono">
              {h.header}
            </Badge>
          ))}
        </div>
        <p className="mt-2 leading-relaxed text-muted-foreground">
          Absence is reported as an observation only. A missing header is not by
          itself a vulnerability — it depends on the response and the threat
          model. Confidence: low.
        </p>
      </section>
    </div>
  );
}

function DiffView({
  result,
  previous,
}: {
  result: ScopedHttpResult;
  previous: ScopedHttpResult | null;
}) {
  const lines = useMemo(
    () => (previous ? lineDiff(previous.body, result.body) : []),
    [previous, result.body],
  );
  const { added, removed } = useMemo(() => countDiff(lines), [lines]);

  if (!previous) {
    return (
      <p className="p-4 text-xs text-muted-foreground">
        No previous response to compare against. Send a second request to diff.
      </p>
    );
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-3 border-b border-border px-3 py-2 text-[11px]">
        <Badge variant="success">+{added}</Badge>
        <Badge variant="danger">-{removed}</Badge>
        <span className="text-muted-foreground">
          against previous response ({previous.status} → {result.status})
        </span>
      </div>
      <pre className="mono max-h-[48vh] flex-1 overflow-auto p-3 text-xs leading-relaxed">
        {lines.map((line, index) => (
          <div
            key={index}
            className={cn(
              "whitespace-pre-wrap break-all",
              line.type === "add" && "bg-success/10 text-success",
              line.type === "del" && "bg-danger/10 text-danger",
              line.type === "same" && "text-muted-foreground",
            )}
          >
            {line.type === "add" ? "+" : line.type === "del" ? "-" : " "}
            {line.text}
          </div>
        ))}
      </pre>
    </div>
  );
}

export function ResponsePanel({
  result,
  analysis,
  previous,
  pending,
  error,
  tab: controlledTab,
  onTabChange,
}: {
  result: ScopedHttpResult | null;
  analysis: ResponseAnalysis | null;
  previous: ScopedHttpResult | null;
  pending: boolean;
  error?: string;
  tab?: string;
  onTabChange?: (tab: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [internalTab, setInternalTab] = useState("body");
  const tab = controlledTab ?? internalTab;
  const setTab = (next: string) => {
    setInternalTab(next);
    onTabChange?.(next);
  };

  if (error) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-2 p-6 text-center">
        <AlertTriangle className="size-6 text-danger" />
        <p className="text-sm font-medium text-danger">Request refused</p>
        <p className="max-w-md text-xs text-muted-foreground">{error}</p>
      </div>
    );
  }

  if (pending) {
    return (
      <div className="relative flex h-full items-center justify-center overflow-hidden p-6">
        <div className="ws-sweep absolute inset-x-0 top-0 h-px overflow-hidden opacity-60" />
        <p className="mono text-xs text-muted-foreground">sending request…</p>
      </div>
    );
  }

  if (!result) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-2 p-6 text-center">
        <FileText className="size-6 text-muted-foreground" />
        <p className="text-sm text-muted-foreground">
          No response yet. Compose a request and press Send.
        </p>
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <StatusBadge status={result.status} />
        <span className="text-xs text-muted-foreground">{result.statusText}</span>
        <span className="mono flex items-center gap-1 text-[11px] text-muted-foreground">
          <Clock className="size-3" /> {formatDuration(result.timingMs)}
        </span>
        <span className="mono text-[11px] text-muted-foreground">
          {formatBytes(result.bodyBytes)}
        </span>
        {result.redirected && <Badge variant="info">redirected</Badge>}
      </div>

      {(result.redirected || result.redirectChain.length > 0) && (
        <div className="border-b border-border bg-panel-2/40 px-3 py-2">
          {result.redirectChain.map((hop, index) => (
            <div
              key={index}
              className="mono flex items-center gap-1.5 text-[11px] text-muted-foreground"
            >
              <ArrowRightLeft className="size-3 text-info" />
              <span>{hop.status}</span>
              <span className="truncate">{hop.to || "(no location)"}</span>
              <span className="truncate text-muted-foreground/70">
                — {hop.reason}
              </span>
            </div>
          ))}
        </div>
      )}

      <Tabs
        value={tab}
        onValueChange={setTab}
        className="flex min-h-0 flex-1 flex-col"
      >
        <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
          <TabsList className="flex-1">
            <TabsTrigger value="body">Body</TabsTrigger>
            <TabsTrigger value="headers">
              Headers ({Object.keys(result.headers).length})
            </TabsTrigger>
            <TabsTrigger value="cookies">
              Cookies ({result.cookies.length})
            </TabsTrigger>
            <TabsTrigger value="analysis">Analysis</TabsTrigger>
            <TabsTrigger value="compare">Diff</TabsTrigger>
          </TabsList>
          <div className="relative">
            <Search className="absolute left-2 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="search response"
              className="mono h-8 w-44 pl-7 text-xs"
            />
          </div>
        </div>

        <div className="min-h-0 flex-1">
          <TabsContent value="body">
            <BodyView result={result} query={query} />
          </TabsContent>
          <TabsContent value="headers">
            <HeadersView result={result} query={query} />
          </TabsContent>
          <TabsContent value="cookies">
            <CookiesView result={result} />
          </TabsContent>
          <TabsContent value="analysis">
            {analysis ? (
              <AnalysisView analysis={analysis} />
            ) : (
              <p className="p-4 text-xs text-muted-foreground">
                Run security checks to see analysis.
              </p>
            )}
          </TabsContent>
          <TabsContent value="compare">
            <DiffView result={result} previous={previous} />
          </TabsContent>
        </div>
      </Tabs>
    </div>
  );
}