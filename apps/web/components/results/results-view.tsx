"use client";

import { useState } from "react";
import Link from "next/link";
import {
  ChevronDown,
  Inbox,
  PlusCircle,
  Trash2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { MethodBadge, StatusBadge } from "@/components/security/method-badge";
import { useEphemeralResults, type EphemeralEntry } from "@/lib/results/store";
import { formatBytes, formatDuration, relativeTime } from "@/lib/utils";
import { useNow } from "@/lib/hooks/use-now";
import { redactHeaderValue } from "@/lib/http/format";

/**
 * The vocabulary WebStrike uses for anything that might become a finding.
 * Nothing is called a "vulnerability" automatically; each state requires the
 * evidence shown alongside it.
 */
export const RESULT_STATES = [
  "Observation",
  "Potential Issue",
  "Needs Verification",
  "Verified",
  "Not Reproducible",
] as const;

function EntryCard({ entry, now }: { entry: EphemeralEntry; now: number }) {
  const [open, setOpen] = useState(false);
  const result = entry.result;

  return (
    <div className="rounded-lg border border-border bg-panel/70">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-3 px-3 py-2.5 text-left"
      >
        <MethodBadge method={entry.request.method} />
        <span className="mono min-w-0 flex-1 truncate text-xs text-foreground/90">
          {result?.finalUrl ?? entry.request.url}
        </span>
        {entry.status === "pending" && <Badge variant="info">sending…</Badge>}
        {entry.status === "error" && <Badge variant="danger">refused</Badge>}
        {result && <StatusBadge status={result.status} />}
        {result && (
          <span className="mono hidden text-[11px] text-muted-foreground sm:inline">
            {formatDuration(result.timingMs)} · {formatBytes(result.bodyBytes)}
          </span>
        )}
        <span className="hidden text-[11px] text-muted-foreground md:inline">
          {relativeTime(entry.createdAt, now)}
        </span>
        <ChevronDown
          className={`size-3.5 text-muted-foreground transition-transform ${open ? "rotate-180" : ""}`}
        />
      </button>

      {open && (
        <div className="border-t border-border p-3">
          {entry.status === "error" ? (
            <p className="text-xs text-danger">{entry.error}</p>
          ) : result ? (
            <div className="grid gap-3 lg:grid-cols-2">
              <div>
                <p className="mb-1.5 text-[10px] uppercase tracking-widest text-muted-foreground">
                  Request
                </p>
                <pre className="mono max-h-56 overflow-auto whitespace-pre-wrap rounded border border-border bg-background p-2 text-[11px] text-muted-foreground">
                  {[
                    `${entry.request.method} ${entry.request.url}`,
                    ...entry.request.headers.map(
                      (h) => `${h.name}: ${redactHeaderValue(h.name, h.value)}`,
                    ),
                    entry.request.contentType
                      ? `Content-Type: ${entry.request.contentType}`
                      : "",
                    entry.request.body ? `\n${entry.request.body}` : "",
                  ]
                    .filter(Boolean)
                    .join("\n")}
                </pre>
              </div>
              <div>
                <p className="mb-1.5 text-[10px] uppercase tracking-widest text-muted-foreground">
                  Response
                </p>
                <pre className="mono max-h-56 overflow-auto whitespace-pre-wrap rounded border border-border bg-background p-2 text-[11px] text-muted-foreground">
                  {`HTTP ${result.status} ${result.statusText}\n` +
                    Object.entries(result.headers)
                      .map(([k, v]) => `${k}: ${v}`)
                      .join("\n") +
                    "\n\n" +
                    result.body.slice(0, 4000)}
                </pre>
              </div>
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">No response captured.</p>
          )}
        </div>
      )}
    </div>
  );
}

export function ResultsView() {
  const { entries, clearAll, requestCount, testCount } = useEphemeralResults();
  const now = useNow();

  return (
    <div className="mx-auto max-w-5xl space-y-4 p-4 sm:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight">Current results</h1>
          <p className="mt-0.5 text-xs text-muted-foreground">
            In-memory only. {requestCount} requests · {testCount} checks this
            session. Discarded when the session ends or the page reloads.
          </p>
        </div>
        {entries.length > 0 && (
          <Button variant="danger" size="sm" onClick={clearAll}>
            <Trash2 className="size-3.5" /> Discard all
          </Button>
        )}
      </div>

      <div className="flex flex-wrap gap-1.5">
        {RESULT_STATES.map((state) => (
          <Badge
            key={state}
            variant={
              state === "Verified"
                ? "success"
                : state === "Potential Issue"
                  ? "warning"
                  : state === "Needs Verification"
                    ? "info"
                    : "muted"
            }
          >
            {state}
          </Badge>
        ))}
      </div>

      {entries.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center gap-3 py-14 text-center">
            <Inbox className="size-7 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">
              No results in memory yet.
            </p>
            <Button asChild size="sm" variant="secondary">
              <Link href="/repeater">
                <PlusCircle className="size-3.5" /> Send a request
              </Link>
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {entries.map((entry) => (
            <EntryCard key={entry.id} entry={entry} now={now} />
          ))}
        </div>
      )}
    </div>
  );
}