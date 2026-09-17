import { cn } from "@/lib/utils";
import type { RequestMethod } from "@webstrike/types";

const COLORS: Record<string, string> = {
  GET: "text-info border-info/40 bg-info/10",
  POST: "text-success border-success/40 bg-success/10",
  PUT: "text-warning border-warning/40 bg-warning/10",
  PATCH: "text-accent border-accent/40 bg-accent/10",
  DELETE: "text-danger border-danger/40 bg-danger/10",
  HEAD: "text-muted-foreground border-border bg-panel",
  OPTIONS: "text-muted-foreground border-border bg-panel",
};

export function MethodBadge({
  method,
  className,
}: {
  method: RequestMethod | string;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "mono inline-flex min-w-[3.5rem] items-center justify-center rounded border px-1.5 py-0.5 text-[11px] font-bold tracking-wide",
        COLORS[method] ?? COLORS.GET,
        className,
      )}
    >
      {method}
    </span>
  );
}

export function StatusBadge({
  status,
  className,
}: {
  status: number;
  className?: string;
}) {
  const tone =
    status === 0
      ? "text-muted-foreground border-border bg-panel"
      : status < 300
        ? "text-success border-success/40 bg-success/10"
        : status < 400
          ? "text-info border-info/40 bg-info/10"
          : status < 500
            ? "text-warning border-warning/40 bg-warning/10"
            : "text-danger border-danger/40 bg-danger/10";

  return (
    <span
      className={cn(
        "mono inline-flex items-center justify-center rounded border px-1.5 py-0.5 text-[11px] font-bold",
        tone,
        className,
      )}
    >
      {status === 0 ? "ERR" : status}
    </span>
  );
}