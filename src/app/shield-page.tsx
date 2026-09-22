"use client";

import * as React from "react";
import { useEffect } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Loader2,
  AlertTriangle,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ResultDisplay } from "@/app/result-display";
import type { UrlAnalysisResult } from "@/app/actions";

interface ShieldPageProps {
  analysisResult: UrlAnalysisResult | null;
  error: string | null;
}

export function ShieldPage({ analysisResult, error }: ShieldPageProps) {
  const isSafe = analysisResult?.content.isSafe ?? false;
  const url = analysisResult?.phishing.url ?? ""; // Correctly get the URL from the phishing analysis result

  useEffect(() => {
    if (isSafe && url) {
      const timer = setTimeout(() => {
        window.location.href = url;
      }, 5000); // 5-second delay before redirecting

      return () => clearTimeout(timer);
    }
  }, [isSafe, url]);

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-gray-900 text-white p-4">
        <Card className="w-full max-w-lg bg-gray-800 border-red-500 border-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-6 w-6" />
              Error
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p>{error}</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!analysisResult) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-900 text-white">
        <Loader2 className="h-12 w-12 animate-spin text-accent" />
        <p className="ml-4 text-lg">Loading analysis...</p>
      </div>
    );
  }

  return (
    <div className={`min-h-screen flex items-center justify-center p-4 ${isSafe ? 'bg-gray-900' : 'bg-red-900/20'}`}>
        <style jsx global>{`
          body {
            background-color: ${isSafe ? '#111827' : '#230d0f'};
          }
        `}</style>
      <Card className={`w-full max-w-2xl shadow-2xl ${isSafe ? 'bg-gray-800 border-blue-500' : 'bg-gray-800 border-red-500'} border-2`}>
        <CardHeader className="text-center">
          {isSafe ? (
            <>
              <div className="flex justify-center">
                <ShieldCheck className="w-16 h-16 text-green-400 animate-pulse" />
              </div>
              <CardTitle className="text-3xl font-bold text-white mt-4">This Link is Likely Safe</CardTitle>
              <p className="text-gray-300 mt-2">
                Redirecting you in 5 seconds...
              </p>
            </>
          ) : (
            <>
              <div className="flex justify-center">
                <ShieldAlert className="w-16 h-16 text-red-400 animate-bounce" />
              </div>
              <CardTitle className="text-3xl font-bold text-white mt-4">DANGER: Link Blocked</CardTitle>
              <p className="text-gray-300 mt-2">
                This link was identified as potentially harmful. Access has been prevented.
              </p>
            </>
          )}
          <p className="font-mono text-sm break-all text-gray-400 pt-4">{url}</p>
        </CardHeader>
        <CardContent>
          <ResultDisplay results={analysisResult} />
        </CardContent>
      </Card>
    </div>
  );
}
