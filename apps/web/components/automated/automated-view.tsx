"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  FileJson,
  Loader2,
  Play,
  PlusCircle,
  ShieldCheck,
  Square,
  Trash2,
} from "lucide-react";
import type { Progress, RunOutcome, TestObservation } from "@webstrike/testing";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Label, Textarea } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useTestingSession } from "@/lib/hooks/use-session";
import { useNow } from "@/lib/hooks/use-now";
import { ApiClientError } from "@/lib/api/client";
import {
  AUTOMATED_CATEGORIES,
  DEFAULT_CATEGORIES,
  type CategoryId,
} from "@/lib/automated/categories";
import { streamAutomatedRun, type AutomatedRunRequestBody } from "@/lib/automated/client";
import { IdentityEditor, emptyIdentity, type IdentityDraft } from "./identity-editor";
import { ObservationCard } from "./observation-card";

type Profile = "quick" | "standard" | "deep";

const PROFILE_HELP: Record<Profile, string> = {
  quick: "≈40 requests · 45s ceiling",
  standard: "≈120 requests · 2min ceiling",
  deep: "≈240 requests · 4min ceiling",
};

const STATE_ORDER: TestObservation["state"][] = [
  "Potential Issue",
  "Needs Verification",
  "Observation",
  "Verified",
  "Not Reproducible",
];

function rowsToPairs(rows: { name: string; value: string }[]) {
  return rows
    .filter((row) => row.name.trim())
    .map((row) => ({ name: row.name.trim(), value: row.value }));
}

export function AutomatedView() {
  const { data } = useTestingSession();
  const session = data?.session ?? null;
  const now = useNow();

  const [profile, setProfile] = useState<Profile>("quick");
  const [activeTests, setActiveTests] = useState(false);
  const [categories, setCategories] = useState<CategoryId[]>(DEFAULT_CATEGORIES);
  const [identities, setIdentities] = useState<IdentityDraft[]>([
    emptyIdentity("A", "Identity A"),
  ]);
  const [seedPaths, setSeedPaths] = useState("");
  const [openapi, setOpenapi] = useState("");
  const [workflow, setWorkflow] = useState("");
  const [advancedOpen, setAdvancedOpen] = useState(false);

  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [outcome, setOutcome] = useState<RunOutcome | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [abort, setAbort] = useState<AbortController | null>(null);

  const inactive =
    !session || session.status !== "active" || now >= session.expiresAt;

  const grouped = useMemo(() => {
    if (!outcome) return [];
    return STATE_ORDER.map((state) => ({
      state,
      items: outcome.observations.filter((o) => o.state === state),
    })).filter((group) => group.items.length > 0);
  }, [outcome]);

  function toggleCategory(id: CategoryId) {
    setCategories((current) =>
      current.includes(id) ? current.filter((c) => c !== id) : [...current, id],
    );
  }

  async function run() {
    if (inactive) {
      setError("no active testing session — create one first");
      return;
    }
    if (categories.length === 0) {
      setError("select at least one test category");
      return;
    }

    let workflowParsed: unknown[] | undefined;
    if (categories.includes("business-logic") && workflow.trim()) {
      try {
        const parsed = JSON.parse(workflow);
        if (!Array.isArray(parsed)) throw new Error("workflow must be a JSON array");
        workflowParsed = parsed;
      } catch (err) {
        setError(`workflow JSON invalid: ${err instanceof Error ? err.message : "parse error"}`);
        return;
      }
    }

    const seeds = seedPaths
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);

    const body: AutomatedRunRequestBody = {
      categories,
      profile,
      activeTests,
      identities: identities.map((identity) => ({
        id: identity.id,
        label: identity.label || identity.id,
        headers: rowsToPairs(identity.headers),
        cookies: rowsToPairs(identity.cookies),
      })),
      workflow: workflowParsed,
      openapi: openapi.trim() ? openapi : undefined,
      seedPaths: seeds,
    };

    setError(null);
    setOutcome(null);
    setProgress(null);
    setRunning(true);
    const controller = new AbortController();
    setAbort(controller);

    try {
      const result = await streamAutomatedRun(body, setProgress, controller.signal);
      setOutcome(result);
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        setError("run cancelled by operator");
      } else if (err instanceof ApiClientError) {
        setError(err.detail ? `${err.message} — ${String(err.detail)}` : err.message);
      } else {
        setError(err instanceof Error ? err.message : "run failed");
      }
    } finally {
      setRunning(false);
      setAbort(null);
    }
  }

  function cancel() {
    abort?.abort();
  }

  return (
    <div className="mx-auto max-w-7xl space-y-4 p-4 sm:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight">Automated checks</h1>
          <p className="mt-0.5 text-xs text-muted-foreground">
            Bounded, scope-validated tests run in one short-lived function. No
            workers, no stored findings — observations are discarded with the
            session.
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

      <div className="grid gap-4 xl:grid-cols-[380px_1fr]">
        <Card className="min-w-0 self-start">
          <CardHeader>
            <CardTitle>Run configuration</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center gap-2">
              <Select
                value={profile}
                onChange={(e) => setProfile(e.target.value as Profile)}
                className="w-32"
              >
                <option value="quick">Quick</option>
                <option value="standard">Standard</option>
                <option value="deep">Deep</option>
              </Select>
              <span className="text-[11px] text-muted-foreground">{PROFILE_HELP[profile]}</span>
            </div>

            <div className="space-y-1.5">
              <Label>Categories</Label>
              <div className="space-y-1">
                {AUTOMATED_CATEGORIES.map((category) => {
                  const checked = categories.includes(category.id);
                  return (
                    <label
                      key={category.id}
                      className="flex cursor-pointer items-start gap-2 rounded px-2 py-1.5 hover:bg-panel-2/60"
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() => toggleCategory(category.id)}
                        className="mt-0.5 size-3.5 accent-[var(--color-primary)]"
                      />
                      <span className="min-w-0">
                        <span className="flex items-center gap-1.5 text-xs font-medium">
                          {category.label}
                          {category.active && <Badge variant="warning">active</Badge>}
                        </span>
                        <span className="block text-[11px] text-muted-foreground">
                          {category.description}
                        </span>
                      </span>
                    </label>
                  );
                })}
              </div>
            </div>

            <label className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/5 px-3 py-2">
              <input
                type="checkbox"
                checked={activeTests}
                onChange={(e) => setActiveTests(e.target.checked)}
                className="mt-0.5 size-3.5 accent-[var(--color-warning)]"
              />
              <span className="text-[11px] text-warning">
                Allow state-changing requests (POST/PUT/PATCH/DELETE)
              </span>
            </label>

            <div className="space-y-1.5">
              <Label>Identities</Label>
              <IdentityEditor identities={identities} onChange={setIdentities} />
            </div>

            <details
              open={advancedOpen}
              onToggle={(e) => setAdvancedOpen((e.target as HTMLDetailsElement).open)}
              className="rounded-md border border-border bg-panel-2/30"
            >
              <summary className="cursor-pointer px-3 py-2 text-xs text-muted-foreground">
                Advanced — seeded paths, OpenAPI, workflow
              </summary>
              <div className="space-y-3 border-t border-border p-3">
                <div className="space-y-1.5">
                  <Label>Seed paths (one URL per line)</Label>
                  <Textarea
                    value={seedPaths}
                    onChange={(e) => setSeedPaths(e.target.value)}
                    placeholder={"https://target.test/api/items\nhttps://target.test/account"}
                    className="mono min-h-[60px] text-[11px]"
                    spellCheck={false}
                  />
                </div>

                <div className="space-y-1.5">
                  <Label className="flex items-center gap-1.5">
                    <FileJson className="size-3.5" /> OpenAPI 3.x (JSON or YAML)
                  </Label>
                  <Textarea
                    value={openapi}
                    onChange={(e) => setOpenapi(e.target.value)}
                    placeholder={'openapi: "3.0.0" …'}
                    className="mono min-h-[90px] text-[11px]"
                    spellCheck={false}
                  />
                </div>

                <div className="space-y-1.5">
                  <Label>Workflow (JSON array of steps)</Label>
                  <Textarea
                    value={workflow}
                    onChange={(e) => setWorkflow(e.target.value)}
                    placeholder='[{"id":"s1","label":"list","method":"GET","url":"https://target.test/api/items?id=1"}]'
                    className="mono min-h-[90px] text-[11px]"
                    spellCheck={false}
                  />
                </div>
              </div>
            </details>

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
                {running ? "Running…" : "Start run"}
              </Button>
              {running && (
                <Button variant="secondary" onClick={cancel}>
                  <Square className="size-3.5" /> Cancel
                </Button>
              )}
              <Button
                variant="ghost"
                onClick={() => {
                  setOutcome(null);
                  setProgress(null);
                  setError(null);
                }}
                disabled={running || (!outcome && !error)}
              >
                <Trash2 className="size-3.5" /> Discard
              </Button>
            </div>
          </CardContent>
        </Card>

        <div className="min-w-0 space-y-4">
          {progress && (
            <Card>
              <CardContent className="space-y-2 py-4">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">
                    <span className="mono uppercase">{progress.phase}</span> — {progress.message}
                  </span>
                  <span className="mono text-muted-foreground">
                    {progress.total > 0 ? `${progress.completed}/${progress.total}` : "…"}
                  </span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-panel-2">
                  <div
                    className="h-full rounded-full bg-primary transition-all"
                    style={{
                      width:
                        progress.total > 0
                          ? `${Math.round((progress.completed / progress.total) * 100)}%`
                          : "15%",
                    }}
                  />
                </div>
                <p className="text-[11px] text-muted-foreground">
                  {progress.observations} observation(s) so far
                </p>
              </CardContent>
            </Card>
          )}

          {!outcome && !progress && (
            <Card>
              <CardContent className="flex flex-col items-center gap-2 py-12 text-center">
                <ShieldCheck className="size-6 text-muted-foreground" />
                <p className="text-sm text-muted-foreground">
                  Configure a run to generate evidence-backed observations.
                </p>
              </CardContent>
            </Card>
          )}

          {outcome && (
            <>
              <Card>
                <CardContent className="flex flex-wrap items-center gap-4 py-4 text-xs">
                  <Stat label="requests" value={outcome.stats.requests} />
                  <Stat label="observations" value={outcome.observations.length} />
                  <Stat label="duration" value={`${(outcome.stats.durationMs / 1000).toFixed(1)}s`} />
                  <Stat label="errors" value={outcome.stats.errors} />
                  {outcome.stats.truncated && (
                    <Badge variant="warning">
                      <AlertTriangle className="size-3" /> truncated by budget
                    </Badge>
                  )}
                  <span className="ml-auto text-muted-foreground">
                    surface: {outcome.surface.endpoints.length} endpoint(s),{" "}
                    {outcome.surface.forms.length} form(s)
                  </span>
                </CardContent>
              </Card>

              {outcome.skipped.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle>Skipped</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-1 text-xs text-muted-foreground">
                    {outcome.skipped.map((skip, index) => (
                      <p key={index}>
                        <span className="mono text-foreground/80">{skip.category}</span> — {skip.reason}
                      </p>
                    ))}
                  </CardContent>
                </Card>
              )}

              {outcome.observations.length === 0 && (
                <Card>
                  <CardContent className="py-8 text-center text-sm text-muted-foreground">
                    No observations were produced for this configuration.
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
        </div>
      </div>
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
