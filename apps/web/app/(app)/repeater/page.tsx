import type { Metadata } from "next";
import { RepeaterView } from "@/components/repeater/repeater-view";

export const metadata: Metadata = { title: "Repeater" };

export default function RepeaterPage() {
  return <RepeaterView />;
}