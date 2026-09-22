"use client";

import * as React from "react";
import { Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { ShieldPage } from "@/app/shield-page";
import type { UrlAnalysisResult } from "@/app/actions";

function ShieldContent() {
  const searchParams = useSearchParams();
  const data = searchParams.get("data");

  let analysisResult: UrlAnalysisResult | null = null;
  let error: string | null = null;

  if (data) {
    try {
      const decodedData = Buffer.from(data, "base64").toString("utf-8");
      analysisResult = JSON.parse(decodedData);
    } catch (e) {
      console.error("Failed to parse analysis data:", e);
      error = "Invalid analysis data provided. Could not display shield information.";
    }
  } else {
    error = "No analysis data found.";
  }

  return <ShieldPage analysisResult={analysisResult} error={error} />;
}

export default function Shield() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <ShieldContent />
    </Suspense>
  );
}
