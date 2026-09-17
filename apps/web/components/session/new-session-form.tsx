"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  AlertTriangle,
  CheckCircle2,
  Loader2,
  ShieldCheck,
  Wand2,
} from "lucide-react";
import { createSessionSchema } from "@webstrike/validation";
import { previewScope } from "@webstrike/security/client";
import { Button } from "@/components/ui/button";
import { Input, Label, Textarea } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { TagInput } from "@/components/session/tag-input";
import { useCreateSession } from "@/lib/hooks/use-session";
import { useEphemeralResults } from "@/lib/results/store";
import { ApiClientError } from "@/lib/api/client";
import { cn } from "@/lib/utils";

const DOMAIN_HINT =
  "hostname or *.wildcard — no scheme, path or port";
const PATH_HINT = "path prefix beginning with /";

export function NewSessionForm() {
  const router = useRouter();
  const createSession = useCreateSession();
  const { clearAll } = useEphemeralResults();

  const [name, setName] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [allowedDomains, setAllowedDomains] = useState<string[]>([]);
  const [allowedPaths, setAllowedPaths] = useState<string[]>(["/"]);
  const [blockedDomains, setBlockedDomains] = useState<string[]>([]);
  const [testingIdentity, setTestingIdentity] = useState("");
  const [confirmation, setConfirmation] = useState(false);
  const [durationHours, setDurationHours] = useState(8);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  const scopePreview = useMemo(
    () =>
      targetUrl
        ? previewScope({ targetUrl, allowedDomains, allowedPaths, blockedDomains })
        : null,
    [targetUrl, allowedDomains, allowedPaths, blockedDomains],
  );

  function deriveHost() {
    try {
      const url = new URL(targetUrl);
      const host = url.hostname.replace(/^\[/, "").replace(/\]$/, "");
      if (host && !allowedDomains.includes(host)) {
        setAllowedDomains([host, ...allowedDomains]);
      }
    } catch {
      setError("enter a valid target URL first");
    }
  }

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setFieldErrors({});

    const parsed = createSessionSchema.safeParse({
      name,
      targetUrl,
      allowedDomains,
      allowedPaths,
      blockedDomains,
      testingIdentity,
      authorizationConfirmation: confirmation ? true : false,
      durationHours,
    });

    if (!parsed.success) {
      const next: Record<string, string> = {};
      for (const issue of parsed.error.issues) {
        const key = issue.path.join(".") || "form";
        next[key] ??= issue.message;
      }
      setFieldErrors(next);
      return;
    }

    try {
      const response = await createSession.mutateAsync(parsed.data);
      clearAll();
      if (response.session) {
        router.push(`/session/${response.session.id}`);
      } else {
        router.push("/dashboard");
      }
      router.refresh();
    } catch (err) {
      setError(err instanceof ApiClientError ? err.message : "could not create session");
    }
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Target</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="name">Session name</Label>
            <Input
              id="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Acme staging — auth review"
            />
            {fieldErrors.name && (
              <p className="text-xs text-danger">{fieldErrors.name}</p>
            )}
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="targetUrl">Target URL</Label>
            <Input
              id="targetUrl"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              onBlur={() => {
                if (targetUrl && allowedDomains.length === 0) {
                  const host = (() => {
                    try {
                      return new URL(targetUrl).hostname.replace(/^\[|\]$/g, "");
                    } catch {
                      return "";
                    }
                  })();
                  if (host) setAllowedDomains([host]);
                }
              }}
              placeholder="https://app.example.com"
              className="mono"
              autoComplete="off"
            />
            {fieldErrors.targetUrl && (
              <p className="text-xs text-danger">{fieldErrors.targetUrl}</p>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="size-4 text-primary" /> Scope
          </CardTitle>
          <Button type="button" variant="ghost" size="sm" onClick={deriveHost}>
            <Wand2 className="size-3.5" /> Use target host
          </Button>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5">
            <Label>Allowed domains</Label>
            <TagInput
              value={allowedDomains}
              onChange={setAllowedDomains}
              placeholder="example.com, *.example.com"
              validate={(v) =>
                /[\\/?#@\s]/.test(v) || v.includes("**") ? DOMAIN_HINT : null
              }
            />
            <p className="text-[11px] text-muted-foreground">
              A bare hostname also matches its subdomains. Wildcards match
              subdomains only.
            </p>
            {fieldErrors.allowedDomains && (
              <p className="text-xs text-danger">{fieldErrors.allowedDomains}</p>
            )}
          </div>

          <div className="space-y-1.5">
            <Label>Allowed paths</Label>
            <TagInput
              value={allowedPaths}
              onChange={setAllowedPaths}
              placeholder="/api, /account"
              validate={(v) =>
                !v.startsWith("/") || /[?#\s]/.test(v) ? PATH_HINT : null
              }
            />
            <p className="text-[11px] text-muted-foreground">
              Use <code className="mono">/</code> to allow all paths.
            </p>
            {fieldErrors.allowedPaths && (
              <p className="text-xs text-danger">{fieldErrors.allowedPaths}</p>
            )}
          </div>

          <div className="space-y-1.5">
            <Label>Blocked domains (optional)</Label>
            <TagInput
              value={blockedDomains}
              onChange={setBlockedDomains}
              placeholder="accounts.google.com, *.facebook.com"
              validate={(v) =>
                /[\\/?#@\s]/.test(v) || v.includes("**") ? DOMAIN_HINT : null
              }
            />
            <p className="text-[11px] text-muted-foreground">
              Blocked entries win over allowed entries. The system denylist
              (localhost, private networks, metadata endpoints) always applies.
            </p>
          </div>

          {scopePreview && (
            <div
              className={cn(
                "flex items-start gap-2 rounded-md border p-3 text-xs",
                scopePreview.ok
                  ? "border-success/40 bg-success/5 text-success"
                  : "border-warning/40 bg-warning/5 text-warning",
              )}
            >
              {scopePreview.ok ? (
                <CheckCircle2 className="mt-0.5 size-3.5 shrink-0" />
              ) : (
                <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
              )}
              <span>{scopePreview.message}</span>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Testing identity &amp; authorisation</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="identity">Who is testing, under what authority</Label>
            <Textarea
              id="identity"
              value={testingIdentity}
              onChange={(e) => setTestingIdentity(e.target.value)}
              placeholder="J. Doe (j.doe@example.com) under SOW #1234, approved by security@example.com"
            />
            {fieldErrors.testingIdentity && (
              <p className="text-xs text-danger">{fieldErrors.testingIdentity}</p>
            )}
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="duration">Session lifetime</Label>
            <Select
              id="duration"
              value={durationHours}
              onChange={(e) => setDurationHours(Number(e.target.value))}
            >
              {[1, 2, 4, 8, 12, 24].map((h) => (
                <option key={h} value={h}>
                  {h} hour{h > 1 ? "s" : ""}
                </option>
              ))}
            </Select>
          </div>

          <label className="flex items-start gap-2 rounded-md border border-border bg-panel p-3 text-xs text-muted-foreground">
            <input
              type="checkbox"
              checked={confirmation}
              onChange={(e) => setConfirmation(e.target.checked)}
              className="mt-0.5 size-3.5 accent-[var(--primary)]"
            />
            <span>
              I confirm I have explicit authorisation to test this target. Every
              request is scope-checked and SSRF-filtered; results are held in
              memory only.
            </span>
          </label>
          {fieldErrors.authorizationConfirmation && (
            <p className="text-xs text-danger">
              {fieldErrors.authorizationConfirmation}
            </p>
          )}
        </CardContent>
      </Card>

      {error && (
        <div className="flex items-center gap-2 rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-xs text-danger">
          <AlertTriangle className="size-3.5" /> {error}
        </div>
      )}

      <div className="flex justify-end gap-2">
        <Button
          type="button"
          variant="ghost"
          onClick={() => router.push("/dashboard")}
        >
          Cancel
        </Button>
        <Button type="submit" disabled={createSession.isPending}>
          {createSession.isPending && <Loader2 className="size-4 animate-spin" />}
          Create session
        </Button>
      </div>
    </form>
  );
}