"use client";

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useReducer,
  type ReactNode,
} from "react";
import type { ScopedHttpResult } from "@webstrike/types";
import type { RequestSpecInput } from "@webstrike/validation";
import type { ResponseAnalysis } from "../analysis";

/**
 * Session-scoped, in-memory result store.
 *
 * Nothing here is persisted: no cookies, no responses, no evidence, no files.
 * It lives in React state for the lifetime of the open testing session and is
 * discarded by "end session" / "discard" / page unload.
 */
export interface EphemeralEntry {
  id: string;
  request: RequestSpecInput;
  result: ScopedHttpResult | null;
  analysis: ResponseAnalysis | null;
  status: "pending" | "done" | "error";
  error?: string;
  createdAt: number;
}

interface EphemeralState {
  entries: EphemeralEntry[];
  requestCount: number;
  testCount: number;
}

type Action =
  | { type: "pending"; request: RequestSpecInput }
  | { type: "resolve"; id: string; result: ScopedHttpResult; analysis: ResponseAnalysis }
  | { type: "fail"; id: string; error: string }
  | { type: "tests"; count: number }
  | { type: "discard"; id: string }
  | { type: "clear" };

const initialState: EphemeralState = {
  entries: [],
  requestCount: 0,
  testCount: 0,
};

const MAX_ENTRIES = 50;

function reducer(state: EphemeralState, action: Action): EphemeralState {
  switch (action.type) {
    case "pending": {
      const entry: EphemeralEntry = {
        id: action.request.id,
        request: action.request,
        result: null,
        analysis: null,
        status: "pending",
        createdAt: Date.now(),
      };
      const entries = [entry, ...state.entries].slice(0, MAX_ENTRIES);
      return { ...state, entries, requestCount: state.requestCount + 1 };
    }
    case "resolve":
      return {
        ...state,
        entries: state.entries.map((e) =>
          e.id === action.id
            ? { ...e, status: "done", result: action.result, analysis: action.analysis, error: undefined }
            : e,
        ),
      };
    case "fail":
      return {
        ...state,
        entries: state.entries.map((e) =>
          e.id === action.id ? { ...e, status: "error", error: action.error } : e,
        ),
      };
    case "tests":
      return { ...state, testCount: state.testCount + action.count };
    case "discard":
      return { ...state, entries: state.entries.filter((e) => e.id !== action.id) };
    case "clear":
      return initialState;
    default:
      return state;
  }
}

interface EphemeralContextValue extends EphemeralState {
  markPending(request: RequestSpecInput): void;
  resolve(id: string, result: ScopedHttpResult, analysis: ResponseAnalysis): void;
  fail(id: string, error: string): void;
  recordTests(count: number): void;
  discard(id: string): void;
  clearAll(): void;
}

const EphemeralContext = createContext<EphemeralContextValue | null>(null);

export function EphemeralResultsProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initialState);

  const value = useMemo<EphemeralContextValue>(
    () => ({
      ...state,
      markPending: (request) => dispatch({ type: "pending", request }),
      resolve: (id, result, analysis) => dispatch({ type: "resolve", id, result, analysis }),
      fail: (id, error) => dispatch({ type: "fail", id, error }),
      recordTests: (count) => dispatch({ type: "tests", count }),
      discard: (id) => dispatch({ type: "discard", id }),
      clearAll: () => dispatch({ type: "clear" }),
    }),
    [state],
  );

  return <EphemeralContext.Provider value={value}>{children}</EphemeralContext.Provider>;
}

export function useEphemeralResults(): EphemeralContextValue {
  const ctx = useContext(EphemeralContext);
  if (!ctx) {
    throw new Error("useEphemeralResults must be used inside EphemeralResultsProvider");
  }
  return ctx;
}

/** Convenience for the results page. */
export function useLatestResults(limit = 20): EphemeralEntry[] {
  const { entries } = useEphemeralResults();
  return useCallback(() => entries.slice(0, limit), [entries, limit])();
}