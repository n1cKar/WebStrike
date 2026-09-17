import Link from "next/link";
import {
  ArrowRight,
  Boxes,
  Eye,
  Globe,
  Lock,
  Radio,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import { Button } from "@/components/ui/button";

const FEATURES = [
  {
    icon: Radio,
    title: "Repeater-style testing",
    body: "Compose a request — method, URL, query, headers, cookies, body — send it through strict scope checks and inspect the real response.",
  },
  {
    icon: ShieldCheck,
    title: "Authorised-target model",
    body: "Every session declares allowed domains, allowed paths, an identity and an expiry. Out-of-scope requests are refused server-side.",
  },
  {
    icon: Lock,
    title: "SSRF-hardened",
    body: "Hostnames are resolved and private, loopback, link-local and metadata ranges are rejected on every hop, including redirects.",
  },
  {
    icon: Eye,
    title: "Response analysis",
    body: "Security headers, cookie attributes, redirects and auth boundaries surfaced as observations with evidence and confidence.",
  },
  {
    icon: Globe,
    title: "Browser testing",
    body: "Short-lived, user-started browser sessions for navigation, network observation and screenshots — destroyed when the session ends.",
  },
  {
    icon: Trash2,
    title: "Ephemeral by design",
    body: "No findings database, no scan history, no stored evidence. Results live in memory for the session and are then discarded.",
  },
];

export default function HomePage() {
  return (
    <div className="grid-backdrop min-h-screen">
      <header className="mx-auto flex max-w-6xl items-center justify-between px-4 py-5">
        <div className="flex items-center gap-2">
          <ShieldCheck className="size-5 text-primary" />
          <span className="font-semibold tracking-tight">WebStrike</span>
        </div>
        <div className="flex items-center gap-2">
          <Button asChild variant="ghost" size="sm">
            <Link href="/automated">Automated checks</Link>
          </Button>
          <Button asChild size="sm">
            <Link href="/dashboard">Open WebStrike</Link>
          </Button>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4">
        <section className="py-16 sm:py-24">
          <div className="inline-flex items-center gap-2 rounded-full border border-border bg-panel px-3 py-1 text-xs text-muted-foreground">
            <span className="size-1.5 rounded-full bg-primary ws-pulse" />
            Vercel-only · Neon-optional · ephemeral testing data
          </div>
          <h1 className="mt-6 max-w-3xl text-4xl font-semibold tracking-tight sm:text-5xl">
            Serious web security testing,
            <span className="text-primary"> without a persistent proxy.</span>
          </h1>
          <p className="mt-5 max-w-2xl text-sm leading-relaxed text-muted-foreground sm:text-base">
            WebStrike is a request-runner and analysis workspace for authorised
            penetration testing. Build requests, run controlled security checks,
            and read real responses — all strictly scoped, all temporary.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Button asChild size="lg">
              <Link href="/new-session">
                Start a testing session <ArrowRight className="size-4" />
              </Link>
            </Button>
            <Button asChild variant="outline" size="lg">
              <Link href="/dashboard">Open the dashboard</Link>
            </Button>
          </div>
        </section>

        <section className="grid gap-3 pb-16 sm:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map((feature) => (
            <div
              key={feature.title}
              className="rounded-lg border border-border bg-panel/70 p-5"
            >
              <feature.icon className="size-5 text-primary" />
              <h2 className="mt-3 text-sm font-semibold">{feature.title}</h2>
              <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">
                {feature.body}
              </p>
            </div>
          ))}
        </section>

        <section className="mb-20 rounded-xl border border-border bg-panel/60 p-6">
          <div className="flex items-center gap-2">
            <Boxes className="size-4 text-accent" />
            <h2 className="text-sm font-semibold">The first milestone, working</h2>
          </div>
          <div className="mono mt-4 grid gap-1 text-xs text-muted-foreground">
            <p>create testing session → define authorised target → validate scope</p>
            <p className="text-foreground">→ send one real HTTP request → display real response → discard</p>
          </div>
        </section>
      </main>

      <footer className="border-t border-border px-4 py-6">
        <p className="mx-auto max-w-6xl text-xs text-muted-foreground">
          Use WebStrike only against systems you are explicitly authorised to
          test. Scope enforcement and SSRF protection are always on.
        </p>
      </footer>
    </div>
  );
}