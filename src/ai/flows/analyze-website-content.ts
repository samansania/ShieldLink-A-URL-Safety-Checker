'use server';
/**
 * @fileOverview Analyzes the content of a website to determine if it contains any suspicious elements and assesses its security for entering financial information.
 *
 * - analyzeWebsiteContent - A function that analyzes website content for safety and financial data security.
 * - AnalyzeWebsiteContentInput - The input type for the analyzeWebsiteContent function.
 * - AnalyzeWebsiteContentOutput - The return type for the analyzeWebsiteContent function.
 */
import { heuristicFallback} from '@/utils/heuristicFallback';
import {ai} from '@/ai/ai-instance';
import {z} from 'genkit';
import {assessUrlSafety, type SafetyAssessment} from '@/services/url-scan';
import type { DetectPhishingIndicatorsOutput } from './detect-phishing-indicators';


// Extended input schema to include phishing analysis results
const AnalyzeWebsiteContentInputSchema = z.object({
  url: z.string().describe('The URL of the website to analyze.'),
  phishingAnalysis: z.object({
    isSafe: z.boolean(),
    riskAssessment: z.string(),
    phishingConfidenceScore: z.number(),
    phishingWarningLevel: z.enum(["Low", "Medium", "High"]),
  }).describe("Results from a preliminary phishing-specific analysis."),
});
export type AnalyzeWebsiteContentInput = z.infer<typeof AnalyzeWebsiteContentInputSchema>;


const AnalyzeWebsiteContentOutputSchema = z.object({
  isSafe: z.boolean().describe('Overall safety assessment of the website, considering general content, financial data security, and phishing analysis. This is the final verdict used to BLOCK or ALLOW user access. True if the site is deemed safe, false otherwise.'),
  report: z.string().describe('A detailed report of the general website content analysis, highlighting any potential risks or suspicious elements identified (excluding financial data analysis). If no specific risks are found, this should briefly state that.'),
  isContentGenerallySafe: z.boolean().describe('Whether the general website content (excluding financial aspects) is considered safe based on the analysis. True if no significant suspicious elements were found, false otherwise.'),
  requestsFinancialInfo: z.boolean().describe('Whether the website appears to request sensitive financial information (e.g., credit card numbers, bank account details).'),
  financialDataSafetyAssessment: z.string().describe('An assessment of the safety of providing financial information on this page. Explains the risk level (e.g., "Appears to use secure payment processing indicators on a trusted domain", "Suspicious request for financial details on an unknown or insecure-looking page", "No direct financial input fields found").'),
  isSafeForFinancialData: z.boolean().describe('Whether the website is considered safe specifically for entering financial data, based on the assessment.'),
  overallConfidenceScore: z.number().min(0).max(100).describe('Overall confidence score (0-100%) for this entire website safety assessment, factoring in phishing, general content, and financial safety signals. This reflects certainty in the final `isSafe` verdict.'),
  overallWarningLevel: z.enum(["Low", "Medium", "High"]).describe('Overall warning level for the website, categorized as Low, Medium, or High, based on the comprehensive analysis (phishing, content, financial).'),
});
export type AnalyzeWebsiteContentOutput = z.infer<typeof AnalyzeWebsiteContentOutputSchema>;

export async function analyzeWebsiteContent(input: AnalyzeWebsiteContentInput): Promise<AnalyzeWebsiteContentOutput> {
  return analyzeWebsiteContentFlow(input);
}

const analyzeWebsiteContentPrompt = ai.definePrompt({
  name: 'analyzeWebsiteContentPrompt',
  input: {
    schema: z.object({
      url: z.string().describe('The URL to analyze.'),
      urlSafetyAssessment: z.string().describe('A pre-assessment of the URL\'s safety (e.g., known malicious domain).'),
      phishingAnalysis: z.object({ // Include phishing results in the prompt input
        isSafe: z.boolean().describe("Result from phishing-specific check."),
        riskAssessment: z.string().describe("Phishing risk assessment details."),
        phishingConfidenceScore: z.number().describe("Confidence in phishing assessment."),
        phishingWarningLevel: z.enum(["Low", "Medium", "High"]).describe("Warning level from phishing assessment."),
      }),
    }),
  },
  output: {
    schema: AnalyzeWebsiteContentOutputSchema,
  },
  prompt: `You are an AI assistant specialized in comprehensive website security analysis. Your primary role is to act as a gatekeeper. Your final assessment will determine if a user is BLOCKED from a site or ALLOWED to proceed. Be decisive and cautious.

URL: {{{url}}}
Initial URL Safety Check: {{{urlSafetyAssessment}}}
Preliminary Phishing Analysis:
  Is Phishing Safe: {{phishingAnalysis.isSafe}}
  Phishing Risk Assessment: {{phishingAnalysis.riskAssessment}}
  Phishing Confidence: {{phishingAnalysis.phishingConfidenceScore}}%
  Phishing Warning Level: {{phishingAnalysis.phishingWarningLevel}}

Analyze the website content with the following process:
1.  **General Content Safety:**
    *   Examine the site for suspicious links, unexpected redirects, potential malicious scripts, deceptive language (scare tactics, urgent calls to action unrelated to payments), unprofessional design (typos, inconsistencies suggesting a fake site), excessive pop-ups, or requests for unnecessary permissions.
    *   Set 'isContentGenerallySafe' to 'false' if you find any indicators of risk. Otherwise, set it to 'true'.
    *   Summarize your findings in the 'report' field. Focus on *why* the content is or is not safe.
2.  **Financial Information Request Safety:**
    *   Does the page contain input fields for credit card numbers, expiry dates, CVV/CVC, or bank details? Set 'requestsFinancialInfo' accordingly.
    *   If financial information IS requested:
        *   Assess the safety: Is the domain legitimate for payments? Does it appear secure (HTTPS)? Are there trust seals? Is the request appropriate?
        *   Provide a concise 'financialDataSafetyAssessment' explaining your findings.
        *   Set 'isSafeForFinancialData' to 'false' if the request seems suspicious, the domain is untrusted, or security indicators are weak. It can only be 'true' if multiple positive indicators are present. If no financial info is requested, set it to 'true' (as there's no risk in this context).
3.  **Overall Verdict ('isSafe' field):**
    *   This is the most critical field. It determines if the user is blocked.
    *   The site is UNSAFE ('isSafe' = false) if ANY of these conditions are met: 'phishingAnalysis.isSafe' is false, OR 'isContentGenerallySafe' is false, OR ('requestsFinancialInfo' is true AND 'isSafeForFinancialData' is false).
    *   The site is only SAFE ('isSafe' = true) if ALL checks pass.
4.  **Overall Confidence Score ('overallConfidenceScore' field):**
    *   Provide a score (0-100%) reflecting your certainty in the 'isSafe' verdict. High confidence is required for a 'safe' verdict. If there is any ambiguity, confidence should be lowered.
5.  **Overall Warning Level ('overallWarningLevel' field):**
    *   Assign a level based on the most severe finding:
        *   "High": If 'isSafe' is false. This is a definitive block.
        *   "Medium": If there are some suspicious elements but not enough to block, but the user should be cautious. 'isSafe' might still be true in this case, but with a lower confidence.
        *   "Low": If the site appears completely safe and trustworthy.

Provide your response as a JSON object conforming to the output schema. Your analysis is a shield for the user; err on the side of caution.
`,
});

const analyzeWebsiteContentFlow = ai.defineFlow<
  typeof AnalyzeWebsiteContentInputSchema, // Input now includes phishingAnalysis
  typeof AnalyzeWebsiteContentOutputSchema
>({
  name: 'analyzeWebsiteContentFlow',
  inputSchema: AnalyzeWebsiteContentInputSchema,
  outputSchema: AnalyzeWebsiteContentOutputSchema,
}, async (input) => {
  // The input to this flow now includes `phishingAnalysis`.
  // We still perform the initial URL safety check.
  const safetyAssessment: SafetyAssessment = await assessUrlSafety(input.url);

  // If the URL itself is flagged as unsafe by the basic scan, it's definitely not safe.
  // We can override the AI's detailed analysis with this fundamental finding.
  if (!safetyAssessment.isSafe) {
     return {
        report: `Analysis halted: The URL itself (${input.url}) was flagged as potentially unsafe by initial scan. Reason: ${safetyAssessment.description}.`,
        isContentGenerallySafe: false,
        requestsFinancialInfo: false,
        financialDataSafetyAssessment: `URL (${input.url}) is flagged as unsafe by initial scan. DO NOT ENTER FINANCIAL INFORMATION. Reason: ${safetyAssessment.description}.`,
        isSafeForFinancialData: false,
        isSafe: false, // Overall unsafe due to URL
        overallConfidenceScore: 100, // High confidence in this unsafe verdict due to initial scan.
        overallWarningLevel: "High", // High warning due to initial scan.
     };
  }

  // AI turned off, use heuristic fallback
  let html = '';
  let fetchFailed = false;

  try {
    // Add timeout of 5 seconds to prevent hanging
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    
    const response = await fetch(input.url, { signal: controller.signal });
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      fetchFailed = true;
      console.warn(`HTTP ${response.status} for ${input.url}`);
    } else {
      html = await response.text();
    }
  } catch (error) {
    fetchFailed = true;
    console.warn(`Failed to fetch ${input.url}:`, error instanceof Error ? error.message : String(error));
  }

  // If fetch failed, analyze URL without HTML content using heuristic fallback
  const fallback = heuristicFallback(input.url, html);

  // If we couldn't fetch the page, apply stricter analysis or warning
  if (fetchFailed) {
    return {
      isSafe: fallback.isSafe,
      report: fallback.detailedReports.content + (html === '' ? ' Note: Could not fetch webpage content for full analysis - assessment based on URL analysis only.' : ''),
      isContentGenerallySafe: fallback.isSafe && html !== '',
      requestsFinancialInfo: html !== '' && /password|card|cvv|expiry/i.test(html),
      financialDataSafetyAssessment: fallback.detailedReports.financial + (html === '' ? ' Unable to verify page security due to fetch failure.' : ''),
      isSafeForFinancialData: fallback.isSafe && html !== '',
      overallConfidenceScore: fallback.isSafe ? 60 : 75, // Lower confidence when we couldn't fetch
      overallWarningLevel: fallback.isSafe ? "Low" : "Medium",
    };
  }

  return {
    isSafe: fallback.isSafe,
    report: fallback.detailedReports.content,
    isContentGenerallySafe: fallback.isSafe,
    requestsFinancialInfo: /password|card|cvv|expiry/i.test(html),
    financialDataSafetyAssessment: fallback.detailedReports.financial,
    isSafeForFinancialData: fallback.isSafe,
    overallConfidenceScore: fallback.isSafe ? 75 : 85,
    overallWarningLevel: fallback.isSafe ? "Low" : "High",
  };
});
