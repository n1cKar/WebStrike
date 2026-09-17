"use client";

import { Plus, X } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

export interface KeyValueRow {
  name: string;
  value: string;
}

export function KeyValueEditor({
  rows,
  onChange,
  namePlaceholder = "name",
  valuePlaceholder = "value",
  addLabel = "Add",
}: {
  rows: KeyValueRow[];
  onChange: (rows: KeyValueRow[]) => void;
  namePlaceholder?: string;
  valuePlaceholder?: string;
  addLabel?: string;
}) {
  function update(index: number, patch: Partial<KeyValueRow>) {
    onChange(rows.map((row, i) => (i === index ? { ...row, ...patch } : row)));
  }

  return (
    <div className="space-y-1.5">
      {rows.map((row, index) => (
        <div key={index} className="flex items-center gap-1.5">
          <Input
            value={row.name}
            onChange={(e) => update(index, { name: e.target.value })}
            placeholder={namePlaceholder}
            className="mono h-8 w-2/5 text-xs"
          />
          <Input
            value={row.value}
            onChange={(e) => update(index, { value: e.target.value })}
            placeholder={valuePlaceholder}
            className="mono h-8 flex-1 text-xs"
          />
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="h-8 w-8"
            onClick={() => onChange(rows.filter((_, i) => i !== index))}
            aria-label="remove row"
          >
            <X className="size-3.5" />
          </Button>
        </div>
      ))}
      <Button
        type="button"
        variant="ghost"
        size="sm"
        onClick={() => onChange([...rows, { name: "", value: "" }])}
      >
        <Plus className="size-3.5" /> {addLabel}
      </Button>
    </div>
  );
}