"use client";

import { useState } from "react";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";

interface TagInputProps {
  value: string[];
  onChange: (value: string[]) => void;
  placeholder?: string;
  validate?: (value: string) => string | null;
  className?: string;
  max?: number;
}

export function TagInput({
  value,
  onChange,
  placeholder,
  validate,
  className,
  max = 20,
}: TagInputProps) {
  const [draft, setDraft] = useState("");
  const [error, setError] = useState<string | null>(null);

  function commit(raw: string) {
    const candidate = raw.trim();
    if (!candidate) return;
    if (value.includes(candidate)) {
      setDraft("");
      return;
    }
    if (value.length >= max) {
      setError(`at most ${max} entries`);
      return;
    }
    const problem = validate?.(candidate) ?? null;
    if (problem) {
      setError(problem);
      return;
    }
    setError(null);
    onChange([...value, candidate]);
    setDraft("");
  }

  return (
    <div className={cn("space-y-1.5", className)}>
      <div className="flex min-h-9 flex-wrap items-center gap-1.5 rounded-md border border-border bg-panel px-2 py-1.5 focus-within:border-primary/60">
        {value.map((tag) => (
          <span
            key={tag}
            className="mono inline-flex items-center gap-1 rounded border border-border-strong bg-panel-2 px-1.5 py-0.5 text-[11px]"
          >
            {tag}
            <button
              type="button"
              aria-label={`remove ${tag}`}
              onClick={() => onChange(value.filter((v) => v !== tag))}
              className="text-muted-foreground hover:text-danger"
            >
              <X className="size-3" />
            </button>
          </span>
        ))}
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === ",") {
              e.preventDefault();
              commit(draft);
            } else if (e.key === "Backspace" && !draft && value.length) {
              onChange(value.slice(0, -1));
            }
          }}
          onBlur={() => commit(draft)}
          placeholder={value.length ? "" : placeholder}
          className="min-w-[8ch] flex-1 bg-transparent text-sm text-foreground outline-none placeholder:text-muted-foreground/60"
        />
      </div>
      {error && <p className="text-xs text-danger">{error}</p>}
    </div>
  );
}