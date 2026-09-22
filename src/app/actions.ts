"use server";

import { z } from "zod";
import { analyzeWebsiteContent } from "@/ai/flows/analyze-website-content";
import type { AnalyzeWebsiteContentOutput, AnalyzeWebsiteContentInput } from "@/ai/flows/analyze-website-content";
import { detectPhishingIndicators } from "@/ai/flows/detect-phishing-indicators";
import type { DetectPhishingIndicatorsOutput } from "@/ai/flows/detect-phishing-indicators";

const urlSchema = z.object({
  url: z.string().url(),
});

export interface UrlAnalysisResult {
  phishing: DetectPhishingIndicatorsOutput;
  content: AnalyzeWebsiteContentOutput; 
}

const textSchema = z.object({
  text: z.string(),
});

export interface AnalysisReport {
  url: string;
  results: UrlAnalysisResult | null;
  error?: string;
}

// List of common TLDs (2-6 letters, you can expand this list as needed)
const validTldRegex = /\.(com|org|net|gov|edu|in|co|io|ai|uk|us|info|biz|me|app|dev|xyz|online|site|store|tech|ac|ca|au|de|fr|jp|cn|ru|br|za|tv|mobi|name|pro|club|top|int|mil|arpa|asia|cat|jobs|museum|travel|[a-z]{2,6})$/i;

// Helper: Check if a string is a likely valid web domain (for non-protocol links)
function isLikelyWebDomain(url: string): boolean {
  // If it starts with http:// or https://, always allow
  if (/^https?:\/\//i.test(url)) return true;
  // Otherwise, must have at least one dot, valid TLD, and no spaces
  return /^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$/.test(url) && validTldRegex.test(url) && !/\s/.test(url);
}

/**
 * Analyzes a URL for phishing indicators and content safety.
 */
export async function analyzeUrl(input: z.infer<typeof urlSchema>): Promise<UrlAnalysisResult> {
  const validatedInput = urlSchema.safeParse(input);

  if (!validatedInput.success) {
    throw new Error("Invalid URL provided.");
  }

  const { url } = validatedInput.data;

  // First, get phishing indicators
  const phishingResult = await detectPhishingIndicators({ url });

  // Then, pass phishing results to the content analysis flow
  const contentAnalysisInput: AnalyzeWebsiteContentInput = {
    url,
    phishingAnalysis: {
      isSafe: phishingResult.isSafe,
      riskAssessment: phishingResult.riskAssessment,
      phishingConfidenceScore: phishingResult.phishingConfidenceScore,
      phishingWarningLevel: phishingResult.phishingWarningLevel,
    }
  };
  const contentResult = await analyzeWebsiteContent(contentAnalysisInput);

  return {
    phishing: phishingResult,
    content: contentResult,
  };
}

/**
 * Extracts URLs from a block of text and analyzes each one.
 *
 * @param input An object containing the text to analyze.
 * @returns A promise that resolves to an array of analysis reports.
 */
export async function analyzeTextForLinks(input: z.infer<typeof textSchema>): Promise<AnalysisReport[]> {
  const validatedInput = textSchema.safeParse(input);

  if (!validatedInput.success) {
    throw new Error("Invalid text provided.");
  }

  const { text } = validatedInput.data;

  // Regex to match URLs with or without protocol
  const urlRegex = /((https?:\/\/)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/[^\s]*)?)/g;
  const urls = text.match(urlRegex) || [];
  
  // Remove duplicates
  const uniqueUrls = [...new Set(urls)];

  if (uniqueUrls.length === 0) {
    return [];
  }

  const analysisPromises = uniqueUrls.map(async (rawUrl): Promise<AnalysisReport> => {
    // Prepend https:// if missing
    let url = rawUrl;
    if (!/^https?:\/\//i.test(url)) {
      url = "https://" + url;
    }

    // Check if it's a likely valid web domain
    if (!isLikelyWebDomain(rawUrl)) {
      return {
        url: rawUrl,
        results: null,
        error: "Not a fully functional web link. Analysis not possible."
      };
    }

    try {
      const results = await analyzeUrl({ url });
      return { url: rawUrl, results };
    } catch (error) {
      console.error(`Error analyzing URL ${url}:`, error);
      const errorMessage = error instanceof Error ? error.message : "An unknown error occurred";
      return { url: rawUrl, results: null, error: `Failed to analyze: ${errorMessage}` };
    }
  });

  return Promise.all(analysisPromises);
}