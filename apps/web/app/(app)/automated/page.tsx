import type { Metadata } from "next";
import { AutomatedView } from "@/components/automated/automated-view";

export const metadata: Metadata = { title: "Automated checks" };

export default function AutomatedPage() {
  return <AutomatedView />;
}
