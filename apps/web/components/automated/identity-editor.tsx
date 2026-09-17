"use client";

import { Plus, Trash2, UserRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { KeyValueEditor, type KeyValueRow } from "@/components/repeater/key-value-editor";

export interface IdentityDraft {
  id: string;
  label: string;
  headers: KeyValueRow[];
  cookies: KeyValueRow[];
}

export function emptyIdentity(id: string, label: string): IdentityDraft {
  return { id, label, headers: [], cookies: [] };
}

export function IdentityEditor({
  identities,
  onChange,
  max = 3,
}: {
  identities: IdentityDraft[];
  onChange: (next: IdentityDraft[]) => void;
  max?: number;
}) {
  function update(index: number, patch: Partial<IdentityDraft>) {
    onChange(identities.map((identity, i) => (i === index ? { ...identity, ...patch } : identity)));
  }

  function add() {
    if (identities.length >= max) return;
    const id = String.fromCharCode(65 + identities.length);
    onChange([...identities, emptyIdentity(id, `Identity ${id}`)]);
  }

  function remove(index: number) {
    onChange(identities.filter((_, i) => i !== index));
  }

  return (
    <div className="space-y-3">
      {identities.length === 0 && (
        <p className="rounded-md border border-dashed border-border px-3 py-2 text-xs text-muted-foreground">
          No identities. Anonymous tests still run; add one or two to compare
          authenticated behaviour and authorization boundaries.
        </p>
      )}

      {identities.map((identity, index) => (
        <div key={index} className="space-y-3 rounded-md border border-border bg-panel-2/40 p-3">
          <div className="flex items-center gap-2">
            <UserRound className="size-3.5 text-muted-foreground" />
            <Input
              value={identity.label}
              onChange={(e) => update(index, { label: e.target.value })}
              placeholder="Label"
              className="h-8 flex-1 text-xs"
            />
            <Badge variant="muted" className="mono">
              id {identity.id}
            </Badge>
            <Button variant="ghost" size="icon" onClick={() => remove(index)} aria-label="Remove identity">
              <Trash2 className="size-3.5" />
            </Button>
          </div>
          <div className="space-y-1.5">
            <Label>Headers (e.g. Authorization)</Label>
            <KeyValueEditor
              rows={identity.headers}
              onChange={(rows) => update(index, { headers: rows })}
              namePlaceholder="Authorization"
              valuePlaceholder="Bearer …"
              addLabel="Add header"
            />
          </div>
          <div className="space-y-1.5">
            <Label>Cookies</Label>
            <KeyValueEditor
              rows={identity.cookies}
              onChange={(rows) => update(index, { cookies: rows })}
              namePlaceholder="session"
              valuePlaceholder="value"
              addLabel="Add cookie"
            />
          </div>
        </div>
      ))}

      {identities.length < max && (
        <Button variant="secondary" size="sm" onClick={add}>
          <Plus className="size-3.5" /> Add identity
        </Button>
      )}
    </div>
  );
}
