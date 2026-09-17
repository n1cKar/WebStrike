"use client";

import { useEffect, useState, type ReactNode } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Bot,
  Command,
  Globe,
  LayoutDashboard,
  ListChecks,
  LogOut,
  PlusCircle,
  Radio,
  Settings,
  ShieldCheck,
  Square,
} from "lucide-react";
import { cn, formatCountdown } from "@/lib/utils";
import { useTestingSession } from "@/lib/hooks/use-session";
import { useNow } from "@/lib/hooks/use-now";
import { useEndSession } from "@/lib/hooks/use-session";
import { useEphemeralResults } from "@/lib/results/store";
import { apiFetch } from "@/lib/api/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { CommandPalette } from "./command-palette";

const NAV = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/new-session", label: "New Session", icon: PlusCircle },
  { href: "/repeater", label: "Repeater", icon: Radio },
  { href: "/automated", label: "Automated", icon: Bot },
  { href: "/browser", label: "Browser", icon: Globe },
  { href: "/results", label: "Results", icon: ListChecks },
  { href: "/settings", label: "Settings", icon: Settings },
];

function SessionPill() {
  const { data } = useTestingSession();
  const now = useNow();
  const session = data?.session ?? null;

  if (!session) {
    return (
      <Badge variant="muted" className="gap-1.5">
        <span className="size-1.5 rounded-full bg-muted-foreground" />
        no active session
      </Badge>
    );
  }

  const expired = now >= session.expiresAt;
  const host = (() => {
    try {
      return new URL(session.targetUrl).host;
    } catch {
      return session.targetUrl;
    }
  })();

  return (
    <div className="flex items-center gap-2">
      <Badge variant={expired ? "danger" : "success"} className="gap-1.5">
        <span
          className={cn(
            "size-1.5 rounded-full",
            expired ? "bg-danger" : "bg-success ws-pulse",
          )}
        />
        {expired ? "expired" : "active"}
      </Badge>
      <span className="mono hidden max-w-[22ch] truncate text-xs text-muted-foreground sm:inline">
        {host}
      </span>
      <span className="mono text-xs text-muted-foreground">
        {formatCountdown(session.expiresAt, now)} left
      </span>
    </div>
  );
}

export function AppShell({
  user,
  children,
}: {
  user: { email: string };
  children: ReactNode;
}) {
  const pathname = usePathname();
  const router = useRouter();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const endSession = useEndSession();
  const { clearAll, requestCount, testCount } = useEphemeralResults();

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  async function logout() {
    try {
      await apiFetch("/api/auth/logout", { method: "POST" });
    } finally {
      clearAll();
      router.push("/login");
      router.refresh();
    }
  }

  return (
    <div className="flex min-h-screen bg-background">
      <aside className="sticky top-0 hidden h-screen w-56 shrink-0 flex-col border-r border-border bg-panel/60 lg:flex">
        <div className="flex items-center gap-2 border-b border-border px-4 py-4">
          <ShieldCheck className="size-5 text-primary" />
          <div className="leading-tight">
            <p className="text-sm font-semibold tracking-tight">WebStrike</p>
            <p className="text-[10px] uppercase tracking-widest text-muted-foreground">
              security testing
            </p>
          </div>
        </div>
        <nav className="flex-1 space-y-0.5 p-2">
          {NAV.map((item) => {
            const active =
              pathname === item.href || pathname.startsWith(`${item.href}/`);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm transition-colors",
                  active
                    ? "bg-panel-2 text-foreground"
                    : "text-muted-foreground hover:bg-panel-2/60 hover:text-foreground",
                )}
              >
                <item.icon className={cn("size-4", active && "text-primary")} />
                {item.label}
              </Link>
            );
          })}
        </nav>
        <div className="border-t border-border p-3 text-xs text-muted-foreground">
          <div className="mono flex items-center justify-between">
            <span>requests</span>
            <span className="text-foreground">{requestCount}</span>
          </div>
          <div className="mono mt-1 flex items-center justify-between">
            <span>tests</span>
            <span className="text-foreground">{testCount}</span>
          </div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border bg-background/80 px-3 backdrop-blur sm:px-4">
          <div className="flex items-center gap-2 lg:hidden">
            <ShieldCheck className="size-5 text-primary" />
            <span className="text-sm font-semibold">WebStrike</span>
          </div>
          <SessionPill />
          <div className="ml-auto flex items-center gap-2">
            <button
              type="button"
              onClick={() => setPaletteOpen(true)}
              className="hidden items-center gap-2 rounded-md border border-border bg-panel px-2.5 py-1.5 text-xs text-muted-foreground transition-colors hover:border-border-strong hover:text-foreground sm:flex"
            >
              <Command className="size-3.5" />
              <span>Command</span>
              <kbd className="mono rounded border border-border px-1 text-[10px]">⌘K</kbd>
            </button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                endSession.mutate();
                clearAll();
              }}
              disabled={endSession.isPending}
              title="End and discard the testing session"
            >
              <Square className="size-3.5" />
              End
            </Button>
            <div className="hidden max-w-[18ch] truncate text-xs text-muted-foreground sm:block">
              {user.email}
            </div>
            <Button variant="ghost" size="icon" onClick={logout} title="Sign out">
              <LogOut className="size-4" />
            </Button>
          </div>
        </header>

        <nav className="flex gap-1 overflow-x-auto border-b border-border px-2 py-2 lg:hidden">
          {NAV.map((item) => {
            const active =
              pathname === item.href || pathname.startsWith(`${item.href}/`);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "flex shrink-0 items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs",
                  active ? "bg-panel-2 text-foreground" : "text-muted-foreground",
                )}
              >
                <item.icon className="size-3.5" />
                {item.label}
              </Link>
            );
          })}
        </nav>

        <main className="min-w-0 flex-1">{children}</main>
      </div>

      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
    </div>
  );
}