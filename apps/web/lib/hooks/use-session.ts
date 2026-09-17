"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { TestingSession } from "@webstrike/types";
import { apiFetch } from "@/lib/api/client";

export const SESSION_QUERY_KEY = ["testing-session"] as const;

export interface SessionResponse {
  session: TestingSession | null;
}

export function useTestingSession() {
  return useQuery({
    queryKey: SESSION_QUERY_KEY,
    queryFn: () => apiFetch<SessionResponse>("/api/session"),
    staleTime: 0,
    refetchOnWindowFocus: true,
  });
}

export interface CreateSessionPayload {
  name: string;
  targetUrl: string;
  allowedDomains: string[];
  allowedPaths: string[];
  blockedDomains: string[];
  testingIdentity: string;
  authorizationConfirmation: true;
  durationHours: number;
}

export function useCreateSession() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateSessionPayload) =>
      apiFetch<SessionResponse>("/api/session", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    onSuccess: (data) => {
      client.setQueryData(SESSION_QUERY_KEY, data);
    },
  });
}

export function useEndSession() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: () => apiFetch<{ ok: true }>("/api/session", { method: "DELETE" }),
    onSuccess: () => {
      client.setQueryData(SESSION_QUERY_KEY, { session: null });
    },
  });
}