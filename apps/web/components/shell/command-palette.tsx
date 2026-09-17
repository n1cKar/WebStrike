"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { AnimatePresence, motion } from "motion/react";
import {
  Bot,
  CornerDownLeft,
  Globe,
  LayoutDashboard,
  ListChecks,
  PlusCircle,
  Radio,
  Settings,
  Square,
  Search,
} from "lucide-react";
import { useEndSession } from "@/lib/hooks/use-session";
import { useEphemeralResults } from "@/lib/results/store";

interface Command {
  id: string;
  label: string;
  hint: string;
  run: () => void;
  icon: React.ComponentType<{ className?: string }>;
  danger?: boolean;
}

export function CommandPalette({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const router = useRouter();
  const endSession = useEndSession();
  const { clearAll } = useEphemeralResults();
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState(0);

  const close = useCallback(() => {
    setQuery("");
    setCursor(0);
    onOpenChange(false);
  }, [onOpenChange]);

  const commands = useMemo<Command[]>(
    () => [
      { id: "dashboard", label: "Go to Dashboard", hint: "/dashboard", icon: LayoutDashboard, run: () => router.push("/dashboard") },
      { id: "new-session", label: "New testing session", hint: "/new-session", icon: PlusCircle, run: () => router.push("/new-session") },
      { id: "repeater", label: "Open Repeater", hint: "/repeater", icon: Radio, run: () => router.push("/repeater") },
      { id: "automated", label: "Automated checks", hint: "/automated", icon: Bot, run: () => router.push("/automated") },
      { id: "browser", label: "Browser testing", hint: "/browser", icon: Globe, run: () => router.push("/browser") },
      { id: "results", label: "Current results", hint: "/results", icon: ListChecks, run: () => router.push("/results") },
      { id: "settings", label: "Settings", hint: "/settings", icon: Settings, run: () => router.push("/settings") },
      {
        id: "end-session",
        label: "End & discard testing session",
        hint: "ephemeral data is dropped",
        icon: Square,
        danger: true,
        run: () => {
          endSession.mutate();
          clearAll();
          router.push("/dashboard");
        },
      },
    ],
    [router, endSession, clearAll],
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return commands;
    return commands.filter(
      (c) => c.label.toLowerCase().includes(q) || c.hint.toLowerCase().includes(q),
    );
  }, [commands, query]);

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") close();
      if (event.key === "ArrowDown") {
        event.preventDefault();
        setCursor((c) => Math.min(c + 1, filtered.length - 1));
      }
      if (event.key === "ArrowUp") {
        event.preventDefault();
        setCursor((c) => Math.max(c - 1, 0));
      }
      if (event.key === "Enter") {
        const cmd = filtered[cursor];
        if (cmd) {
          close();
          cmd.run();
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, filtered, cursor, close]);

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 px-4 pt-[12vh] backdrop-blur-sm"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.12 }}
          onClick={close}
        >
          <motion.div
            className="w-full max-w-lg overflow-hidden rounded-lg border border-border-strong bg-panel shadow-2xl shadow-black/60"
            initial={{ opacity: 0, y: -8, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -8, scale: 0.98 }}
            transition={{ duration: 0.12 }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center gap-2 border-b border-border px-3">
              <Search className="size-4 text-muted-foreground" />
              <input
                autoFocus
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setCursor(0);
                }}
                placeholder="Run a command…"
                className="h-11 flex-1 bg-transparent text-sm text-foreground outline-none placeholder:text-muted-foreground/70"
              />
              <kbd className="mono rounded border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground">
                ESC
              </kbd>
            </div>
            <div className="max-h-72 overflow-y-auto p-1">
              {filtered.length === 0 && (
                <p className="px-3 py-6 text-center text-sm text-muted-foreground">
                  No matching commands
                </p>
              )}
              {filtered.map((cmd, index) => (
                <button
                  key={cmd.id}
                  onMouseEnter={() => setCursor(index)}
                  onClick={() => {
                    close();
                    cmd.run();
                  }}
                  className={`flex w-full items-center gap-3 rounded-md px-3 py-2 text-left text-sm transition-colors ${
                    index === cursor ? "bg-panel-2" : "hover:bg-panel-2/60"
                  }`}
                >
                  <cmd.icon
                    className={`size-4 ${cmd.danger ? "text-danger" : "text-muted-foreground"}`}
                  />
                  <span className={cmd.danger ? "text-danger" : "text-foreground"}>
                    {cmd.label}
                  </span>
                  <span className="mono ml-auto text-[10px] text-muted-foreground">
                    {cmd.hint}
                  </span>
                  {index === cursor && (
                    <CornerDownLeft className="size-3 text-muted-foreground" />
                  )}
                </button>
              ))}
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}