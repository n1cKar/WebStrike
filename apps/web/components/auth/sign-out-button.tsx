"use client";

import { useRouter } from "next/navigation";
import { LogOut } from "lucide-react";
import { Button } from "@/components/ui/button";
import { apiFetch } from "@/lib/api/client";
import { useEphemeralResults } from "@/lib/results/store";

export function SignOutButton() {
  const router = useRouter();
  const { clearAll } = useEphemeralResults();

  return (
    <Button
      variant="danger"
      size="sm"
      onClick={async () => {
        try {
          await apiFetch("/api/auth/logout", { method: "POST" });
        } finally {
          clearAll();
          router.push("/login");
          router.refresh();
        }
      }}
    >
      <LogOut className="size-3.5" /> Sign out
    </Button>
  );
}