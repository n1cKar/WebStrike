"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import {
  Globe,
  Loader2,
  MonitorSmartphone,
  Play,
  PlusCircle,
  ServerOff,
  Trash2,
} from "lucide-react";
import type { BrowserRunOutcome, TestObservation } from "@webstrike/testing";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ObservationCard } from "@/components/automated/observation-card";
import { useTestingSession } from "@/lib/hooks/use-session";
import { useNow } from "@/lib/hooks/use-now";
import { ApiClientError } from "@/lib/api/client";
import { fetchBrowserStatus, runBrowser, type BrowserStatus } from "@/lib/browser/client";

const STATE_ORDER: TestObservation["state"][] = [
  "Verified Security Issue",
  "Potential Issue",
  "Needs Verification",
  "Observation",
  "Informational",
  "Not Reproducible",
];

export function BrowserView() {
  const { data } = useTestingSession();
  const session = data?.session ?? null;
  const now = useNow();

  const status = useQuery<BrowserStatus>({
    queryKey: ["browser-status"],
    queryFn: fetchBrowserStatus,
    staleTime: 30_000,
  });

  const [maxPages, setMaxPages] = useState(1);
  const [timeoutMs, setTimeoutMs] = useState(12_000);
  const [screenshot, setScreenshot] = useState(true);
  const [running, setRunning] = useState(false);
  const [outcome, setOutcome] = useState<BrowserRunOutcome | null>(null);
  const [error, setError] = useState<string | null>(null);

  const inactive = !session || session.status !== "active" || now >= session.expiresAt;
  const configured = status.data?.configured ?? false;

  const grouped = useMemo(() => {
    if (!outcome) return [];
    return STATE_ORDER.map((state) => ({
      state,
      items: outcome.observations.filter((o) => o.state === state),
    })).filter((group) => group.items.length > 0);
  }, [outcome]);

  async function run() {
    setError(null);
    setOutcome(null);
    setRunning(true);
    try {
      const payload = await runBrowser({ maxPages, timeoutMs, screenshot });
      setOutcome(payload.outcome);
    } catch (err) {
      setError(
        err instanceof ApiClientError
          ? err.detail
            ? `${err.message} — ${String(err.detail)}`
            : err.message
          : err instanceof Error
            ? err.message
            : "browser run failed",
      );
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="mx-auto max-w-6xl space-y-4 p-4 sm:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight">Browser checks</h1>
          <p className="mt-0.5 text-xs text-muted-foreground">
            Renders authorised pages in a remote browser and reviews console
            output, mixed content, storage and cookie exposure. Opt-in and gated.
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

      {status.isLoading ? (
        <Card>
          <CardContent className="flex items-center gap-2 py-8 text-sm text-muted-foreground">
            <Loader2 className="size-4 animate-spin" /> Checking browser endpoint…
          </CardContent>
        </Card>
      ) : !configured ? (
        <Card className="border-warning/30 bg-warning/5">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ServerOff className="size-4 text-warning" /> Not configured
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm text-muted-foreground">
            <p>
              Browser checks require an operator-provisioned, CDP-compatible
              browser. Nothing is launched on the server; no browsing happens
              until an endpoint is set.
            </p>
            <div className="mono rounded-md border border-border bg-panel p-3 text-[11px] text-foreground/80">
              BROWSER_WS_ENDPOINT=wss://your-browser.example/devtools/browser/&lt;id&gt;
              <br />
              BROWSER_API_TOKEN=… <span className="text-muted-foreground">(optional)</span>
            </div>
            <p className="text-xs">
              Set both in the deployment environment (see .env.example), then
              reload this page.
            </p>
          </CardContent>
        </Card>
      ) : (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <MonitorSmartphone className="size-4 text-primary" /> Run options
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex flex-wrap items-end gap-4">
                <div className="space-y-1.5">
                  <Label>Pages to visit</Label>
                  <Select
                    value={String(maxPages)}
                    onChange={(e) => setMaxPages(Number(e.target.value))}
                    className="w-24"
                  >
                    {[1, 2, 3, 4, 5].map((value) => (
                      <option key={value} value={value}>
                        {value}
                      </option>
                    ))}
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label>Per-page timeout</Label>
                  <Select
                    value={String(timeoutMs)}
                    onChange={(e) => setTimeoutMs(Number(e.target.value))}
                    className="w-32"
                  >
                    <option value={8000}>8 seconds</option>
                    <option value={12000}>12 seconds</option>
                    <option value={20000}>20 seconds</option>
                  </Select>
                </div>
                <label className="flex items-center gap-2 text-xs text-muted-foreground">
                  <input
                    type="checkbox"
                    checked={screenshot}
                    onChange={(e) => setScreenshot(e.target.checked)}
                    className="size-3.5 accent-[var(--color-primary)]"
                  />
                  Capture a screenshot
                </label>
              </div>

              {error && (
                <p className="rounded-md border border-danger/40 bg-danger/5 px-3 py-2 text-xs text-danger">
                  {error}
                </p>
              )}

              <div className="flex flex-wrap gap-2">
                <Button onClick={() => void run()} disabled={inactive || running}>
                  {running ? (
                    <Loader2 className="size-3.5 animate-spin" />
                  ) : (
                    <Play className="size-3.5" />
                  )}
                  {running ? "Running…" : "Run browser checks"}
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => {
                    setOutcome(null);
                    setError(null);
                  }}
                  disabled={running || (!outcome && !error)}
                >
                  <Trash2 className="size-3.5" /> Discard
                </Button>
              </div>
            </CardContent>
          </Card>

          {outcome && (
            <>
              <Card>
                <CardContent className="flex flex-wrap items-center gap-4 py-4 text-xs">
                  <Stat label="pages" value={outcome.stats.pages} />
                  <Stat label="observations" value={outcome.observations.length} />
                  <Stat label="duration" value={`${(outcome.stats.durationMs / 1000).toFixed(1)}s`} />
                  <Stat label="errors" value={outcome.stats.errors} />
                  {outcome.stats.truncated && <Badge variant="warning">truncated by page limit</Badge>}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Globe className="size-4 text-muted-foreground" /> Pages
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-1 text-xs">
                  {outcome.pages.map((page) => (
                    <div key={page.url} className="flex flex-wrap items-center gap-3">
                      <span className="mono truncate text-foreground/90">{page.title || "(untitled)"}</span>
                      <span className="mono truncate text-muted-foreground">{page.url}</span>
                      <span className="ml-auto text-muted-foreground">
                        {page.requests} req · {page.consoleErrors} console error(s) · {page.cookies} cookie(s)
                      </span>
                    </div>
                  ))}
                </CardContent>
              </Card>

              {outcome.screenshot && (
                <Card>
                  <CardHeader>
                    <CardTitle>Screenshot</CardTitle>
                    <span className="text-[10px] text-muted-foreground">discarded with the session</span>
                  </CardHeader>
                  <CardContent>
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img
                      src={`data:image/png;base64,${outcome.screenshot}`}
                      alt="Captured page"
                      className="max-h-[420px] w-auto rounded border border-border"
                    />
                  </CardContent>
                </Card>
              )}

              {outcome.observations.length === 0 && (
                <Card>
                  <CardContent className="py-8 text-center text-sm text-muted-foreground">
                    No observations were produced for this run.
                  </CardContent>
                </Card>
              )}

              {grouped.map((group) => (
                <div key={group.state} className="space-y-2">
                  <div className="flex items-center gap-2">
                    <h2 className="text-sm font-semibold">{group.state}</h2>
                    <Badge variant="muted">{group.items.length}</Badge>
                  </div>
                  <div className="space-y-2">
                    {group.items.map((observation) => (
                      <ObservationCard key={observation.id} observation={observation} />
                    ))}
                  </div>
                </div>
              ))}
            </>
          )}
        </>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <span className="flex flex-col">
      <span className="mono text-sm text-foreground">{value}</span>
      <span className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</span>
    </span>
  );
}
