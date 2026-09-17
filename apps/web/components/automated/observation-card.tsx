"use client";

import type { TestObservation } from "@webstrike/testing";
import { Badge } from "@/components/ui/badge";

const STATE_VARIANT: Record<
  TestObservation["state"],
  "warning" | "info" | "success" | "muted" | "default"
> = {
  "Potential Issue": "warning",
  "Needs Verification": "info",
  Verified: "success",
  "Not Reproducible": "default",
  Observation: "muted",
};

export function ObservationCard({ observation }: { observation: TestObservation }) {
  const { evidence } = observation;
  return (
    <div className="rounded-md border border-border bg-panel-2/40 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={STATE_VARIANT[observation.state]}>{observation.state}</Badge>
        <Badge variant="default" className="mono">
          {observation.category}
        </Badge>
        <Badge variant="muted">confidence: {observation.confidence}</Badge>
      </div>

      <p className="mt-2 text-sm font-medium">{observation.title}</p>
      <p className="mt-1 text-xs text-muted-foreground">{observation.summary}</p>

      {observation.guidance && (
        <p className="mt-2 text-xs text-foreground/70">
          <span className="font-medium">Next: </span>
          {observation.guidance}
        </p>
      )}

      <details className="mt-2 rounded-md border border-border bg-panel/60">
        <summary className="cursor-pointer px-3 py-1.5 text-[11px] text-muted-foreground">
          Evidence — {evidence.detail}
        </summary>
        <div className="space-y-2 border-t border-border p-3 text-[11px]">
          <div>
            <span className="mono text-muted-foreground">
              {evidence.request.method} {evidence.request.label}
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
