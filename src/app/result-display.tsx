"use client";

import * as React from "react";
import { ShieldAlert, ShieldCheck, Siren, CreditCard, Landmark, HelpCircle, AlertTriangle, Info } from "lucide-react";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import type { UrlAnalysisResult } from "./actions";

interface ResultDisplayProps {
  results: UrlAnalysisResult | null;
}

export function ResultDisplay({ results }: ResultDisplayProps) {

  const getFinancialSafetyVariant = (results: UrlAnalysisResult | null, isSafeForFinance: boolean, assessment: string): "secondary" | "destructive" | "default" => {
    if (!results?.content.requestsFinancialInfo) return "default";
    if (!isSafeForFinance || assessment.toLowerCase().includes("suspicious") || assessment.toLowerCase().includes("unsafe") || assessment.toLowerCase().includes("do not enter")) return "destructive";
    if (isSafeForFinance || assessment.toLowerCase().includes("legitimate") || assessment.toLowerCase().includes("secure") || assessment.toLowerCase().includes("appears safe")) return "secondary";
    return "default";
  };

  const getFinancialSafetyClass = (variant: "secondary" | "destructive" | "default"): string => {
    switch (variant) {
      case "secondary": return "bg-green-100 text-green-800";
      case "destructive": return "bg-red-100 text-red-800";
      default: return "bg-gray-200 text-gray-800";
    }
  };

  const getFinancialSafetyBadgeText = (isSafeForFinance: boolean, requested: boolean, assessment: string): string => {
    if (!requested) return "Financial Info Not Requested";
    if (!isSafeForFinance || assessment.toLowerCase().includes("suspicious") || assessment.toLowerCase().includes("unsafe") || assessment.toLowerCase().includes("do not enter")) return "Unsafe for Financial Data";
    if (isSafeForFinance || assessment.toLowerCase().includes("legitimate") || assessment.toLowerCase().includes("secure") || assessment.toLowerCase().includes("appears safe")) return "Appears Safe for Financial Data";
    return "Caution Advised";
  };

  const getWarningLevelVariant = (level?: "Low" | "Medium" | "High"): "secondary" | "destructive" | "default" => {
    switch (level) {
      case "Low": return "secondary";
      case "Medium": return "default";
      case "High": return "destructive";
      default: return "default";
    }
  };

  const getWarningLevelClass = (level?: "Low" | "Medium" | "High"): string => {
    switch (level) {
      case "Low": return "bg-green-100 text-green-800";
      case "Medium": return "bg-yellow-100 text-yellow-800";
      case "High": return "bg-red-100 text-red-800";
      default: return "bg-gray-200 text-gray-800";
    }
  };

  const getWarningLevelIcon = (level?: "Low" | "Medium" | "High") => {
    switch (level) {
      case "Low": return <ShieldCheck className="w-4 h-4 text-green-600" />;
      case "Medium": return <AlertTriangle className="w-4 h-4 text-yellow-600" />;
      case "High": return <Siren className="w-4 h-4 text-red-600" />;
      default: return <Info className="w-4 h-4 text-muted-foreground" />;
    }
  };
  
  if (!results) {
    return <p className="text-center text-muted-foreground">No analysis results to display.</p>;
  }

  return (
    <TooltipProvider>
      <Accordion type="single" collapsible className="w-full space-y-4" defaultValue="item-0">
        <AccordionItem value="item-0" className="border-none">
          <AccordionTrigger className="p-4 hover:no-underline justify-center text-white">
            Show Detailed Analysis
          </AccordionTrigger>
          <AccordionContent className="p-2">
            <div className="space-y-6 p-2">
              <div className="p-4 border rounded-md bg-gray-900/50 border-gray-700">
                <h3 className="text-lg font-semibold mb-2 flex items-center gap-2 text-white">
                  {results.content.isSafe ? (
                    <ShieldCheck className="w-6 h-6 text-green-500" />
                  ) : (
                    <ShieldAlert className="w-6 h-6 text-red-500" />
                  )}
                  Overall Website Safety
                </h3>
                <Badge
                  variant={results.content.isSafe ? "secondary" : "destructive"}
                  className={`${results.content.isSafe ? "bg-green-600 text-white" : "bg-red-600 text-white"} text-base py-1 px-3`}
                >
                  {results.content.isSafe ? "Likely Safe" : "Potentially Unsafe"}
                </Badge>
                <div className="mt-3 space-y-1">
                  <div className="flex justify-between items-center text-sm">
                    <span className="text-gray-400">Overall Warning Level:</span>
                    <Badge variant={getWarningLevelVariant(results.content.overallWarningLevel)} className={getWarningLevelClass(results.content.overallWarningLevel)}>
                      {getWarningLevelIcon(results.content.overallWarningLevel)}
                      <span className="ml-1">{results.content.overallWarningLevel ?? 'N/A'}</span>
                    </Badge>
                  </div>
                  <div className="text-sm">
                    <span className="text-gray-400">Overall Confidence: {results.content.overallConfidenceScore ?? 'N/A'}%</span>
                    <Progress value={results.content.overallConfidenceScore ?? 0} className="h-2 mt-1 bg-gray-700" indicatorClassName={results.content.overallConfidenceScore > 70 ? "bg-green-500" : results.content.overallConfidenceScore > 40 ? "bg-yellow-500" : "bg-red-500"} />
                  </div>
                </div>
              </div>

              <div className="p-4 border rounded-md bg-gray-900/50 border-gray-700">
                <h3 className="text-lg font-semibold mb-2 flex items-center gap-2 text-white">
                  {results.phishing.isSafe ? (
                    <ShieldCheck className="w-5 h-5 text-green-500" />
                  ) : (
                    <Siren className="w-5 h-5 text-red-500" />
                  )}
                  Phishing Potential
                  <Tooltip delayDuration={100}>
                    <TooltipTrigger>
                      <HelpCircle className="w-4 h-4 text-gray-500 cursor-help" />
                    </TooltipTrigger>
                    <TooltipContent>
                      <p>Assesses risk of phishing attempts based on URL and content cues.</p>
                    </TooltipContent>
                  </Tooltip>
                </h3>
                <Badge variant={results.phishing.isSafe ? "secondary" : "destructive"} className={`${results.phishing.isSafe ? "bg-green-100 text-green-800" : "bg-red-100 text-red-800"} mb-2`}>
                  {results.phishing.isSafe ? "Low Phishing Risk" : "Potential Phishing Detected"}
                </Badge>
                <p className="text-sm text-gray-400 mb-2">{results.phishing.riskAssessment}</p>
                <div className="space-y-1 text-sm">
                  <div className="flex justify-between items-center">
                    <span className="text-gray-400">Phishing Warning Level:</span>
                    <Badge variant={getWarningLevelVariant(results.phishing.phishingWarningLevel)} className={getWarningLevelClass(results.phishing.phishingWarningLevel)}>
                      {getWarningLevelIcon(results.phishing.phishingWarningLevel)}
                      <span className="ml-1">{results.phishing.phishingWarningLevel ?? 'N/A'}</span>
                    </Badge>
                  </div>
                  <div>
                    <span className="text-gray-400">Phishing Confidence: {results.phishing.phishingConfidenceScore ?? 'N/A'}%</span>
                    <Progress value={results.phishing.phishingConfidenceScore ?? 0} className="h-2 mt-1 bg-gray-700" indicatorClassName={results.phishing.phishingConfidenceScore > 70 ? "bg-green-500" : results.phishing.phishingConfidenceScore > 40 ? "bg-yellow-500" : "bg-red-500"} />
                  </div>
                </div>
              </div>

              <div className="p-4 border rounded-md bg-gray-900/50 border-gray-700">
                <h3 className="text-lg font-semibold mb-2 flex items-center gap-2 text-white">
                  {results.content.isContentGenerallySafe ? (
                    <ShieldCheck className="w-5 h-5 text-green-500" />
                  ) : (
                    <ShieldAlert className="w-5 h-5 text-yellow-500" />
                  )}
                  General Content Safety
                  <Tooltip delayDuration={100}>
                    <TooltipTrigger>
                      <HelpCircle className="w-4 h-4 text-gray-500 cursor-help" />
                    </TooltipTrigger>
                    <TooltipContent>
                      <p>Checks for suspicious elements like malware, deceptive language, or poor design in the website's content.</p>
                    </TooltipContent>
                  </Tooltip>
                </h3>
                <Badge variant={results.content.isContentGenerallySafe ? "secondary" : "destructive"} className={`${results.content.isContentGenerallySafe ? "bg-green-100 text-green-800" : "bg-yellow-100 text-yellow-800"} mb-2`}>
                  {results.content.isContentGenerallySafe ? "Content Appears Generally Safe" : "Suspicious Content Elements Found"}
                </Badge>
                <p className="text-sm text-gray-400">{results.content.report}</p>
              </div>

              <div className="p-4 border rounded-md bg-gray-900/50 border-gray-700">
                <h3 className="text-lg font-semibold mb-2 flex items-center gap-2 text-white">
                  <CreditCard className="w-5 h-5 text-gray-500" />
                  <Landmark className="w-5 h-5 text-gray-500" />
                  Financial Data Safety
                  <Tooltip delayDuration={100}>
                    <TooltipTrigger>
                      <HelpCircle className="w-4 h-4 text-gray-500 cursor-help" />
                    </TooltipTrigger>
                    <TooltipContent>
                      <p>Assesses whether it's safe to enter financial information (credit cards, bank details) on this site.</p>
                    </TooltipContent>
                  </Tooltip>
                </h3>
                <Badge
                  variant={getFinancialSafetyVariant(results, results.content.isSafeForFinancialData, results.content.financialDataSafetyAssessment)}
                  className={`${getFinancialSafetyClass(getFinancialSafetyVariant(results, results.content.isSafeForFinancialData, results.content.financialDataSafetyAssessment))} mb-2`}
                >
                  {getFinancialSafetyBadgeText(results.content.isSafeForFinancialData, results.content.requestsFinancialInfo, results.content.financialDataSafetyAssessment)}
                </Badge>
                <p className="text-sm text-gray-400">{results.content.financialDataSafetyAssessment}</p>
              </div>
            </div>
          </AccordionContent>
        </AccordionItem>
      </Accordion>
    </TooltipProvider>
  );
}
