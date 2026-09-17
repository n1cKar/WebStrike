"use client";

import type { TestObservation } from "@webstrike/testing";
import { Badge } from "@/components/ui/badge";

const STATE_VARIANT: Record<
  TestObservation["state"],
  "warning" | "info" | "success" | "muted" | "default" | "danger"
> = {
  "Verified Security Issue": "danger",
  "Potential Issue": "warning",
  "Needs Verification": "info",
  "Not Reproducible": "default",
  Observation: "muted",
  Informational: "muted",
};

const SEVERITY_VARIANT: Record<string, "danger" | "warning" | "info" | "muted"> = {
  critical: "danger",
  high: "danger",
  medium: "warning",
  low: "info",
  info: "muted",
};

const VERIFICATION_LABEL: Record<string, string> = {
  "not-required": "not required",
  "needs-verification": "needs verification",
  reproduced: "reproduced independently",
  unreproduced: "not reproduced",
};

export function ObservationCard({ observation }: { observation: TestObservation }) {
  const { evidence } = observation;
  const severity = observation.severity ?? "info";

  return (
    <div className="rounded-md border border-border bg-panel-2/40 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={STATE_VARIANT[observation.state]}>{observation.state}</Badge>
        {observation.tier ? <Badge variant="info">Tier {observation.tier}</Badge> : null}
        <Badge variant={SEVERITY_VARIANT[severity] ?? "muted"}>{severity}</Badge>
        <Badge variant="default" className="mono">
          {observation.category}
        </Badge>
        <Badge variant="muted">confidence: {observation.confidence}</Badge>
        {observation.verification ? (
          <Badge variant="muted">
            {VERIFICATION_LABEL[observation.verification] ?? observation.verification}
          </Badge>
        ) : null}
      </div>

      <p className="mt-2 text-sm font-medium">{observation.title}</p>
      {observation.endpoint ? (
        <p className="mono mt-0.5 text-[11px] text-muted-foreground">{observation.endpoint}</p>
      ) : null}
      <p className="mt-1 text-xs text-muted-foreground">{observation.summary}</p>

      <dl className="mt-2 space-y-1 text-[11px]">
        {observation.expected && (
          <Field label="Expected">{observation.expected}</Field>
        )}
        {observation.observed && <Field label="Observed">{observation.observed}</Field>}
        {observation.impact && <Field label="Impact">{observation.impact}</Field>}
        {observation.reasoning && <Field label="Reasoning">{observation.reasoning}</Field>}
        {observation.verificationDetail && (
          <Field label="Verification">{observation.verificationDetail}</Field>
        )}
        {observation.nextTest && <Field label="Next test">{observation.nextTest}</Field>}
        {observation.remediation && <Field label="Remediation">{observation.remediation}</Field>}
      </dl>

      {observation.aiNote ? (
        <p className="mt-2 rounded-md border border-border bg-panel/60 p-2 text-[11px] text-muted-foreground">
          {observation.aiNote}
        </p>
      ) : null}

      <details className="mt-2 rounded-md border border-border bg-panel/60">
        <summary className="cursor-pointer px-3 py-1.5 text-[11px] text-muted-foreground">
          Evidence — {evidence.detail}
        </summary>
        <div className="space-y-2 border-t border-border p-3 text-[11px]">
          <div>
            <span className="mono text-muted-foreground">
              {evidence.request.method} {evidence.request.label}
              {evidence.request.identityId ? ` · ${evidence.request.identityId}` : ""}
            </span>
            <pre className="mono mt-1 overflow-x-auto whitespace-pre-wrap break-all text-foreground/80">
              {evidence.request.url}
            </pre>
          </div>
          <div className="flex flex-wrap gap-3">
            <span>
              status <span className="mono text-foreground">{evidence.response.status}</span>
            </span>
            <span>
              bytes <span className="mono text-foreground">{evidence.response.bodyBytes}</span>
            </span>
            {evidence.baseline && (
              <span>
                baseline{" "}
                <span className="mono text-foreground">
                  {evidence.baseline.status} / {evidence.baseline.bodyBytes}B
                </span>
              </span>
            )}
          </div>
          <pre className="mono max-h-48 overflow-auto whitespace-pre-wrap break-all rounded border border-border bg-background/40 p-2 text-foreground/70">
            {evidence.response.bodyPreview || "(empty body)"}
          </pre>
          {evidence.baseline?.bodyPreview ? (
            <pre className="mono max-h-32 overflow-auto whitespace-pre-wrap break-all rounded border border-border bg-background/40 p-2 text-foreground/50">
              baseline: {evidence.baseline.bodyPreview || "(empty)"}
            </pre>
          ) : null}
        </div>
      </details>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-2">
      <dt className="w-20 shrink-0 text-muted-foreground">{label}</dt>
      <dd className="text-foreground/80">{children}</dd>
    </div>
  );
}
