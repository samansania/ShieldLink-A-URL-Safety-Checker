'use server';
/**
 * @fileOverview Detects phishing indicators in a URL and its content.
 *
 * - detectPhishingIndicators - A function that analyzes a URL for phishing indicators.
 * - DetectPhishingIndicatorsInput - The input type for the detectPhishingIndicators function.
 * - DetectPhishingIndicatorsOutput - The return type for the detectPhishingIndicators function.
 */

import {ai} from '@/ai/ai-instance';
import {z} from 'genkit';
import {assessUrlSafety} from '@/services/url-scan';

const DetectPhishingIndicatorsInputSchema = z.object({
  url: z.string().describe('The URL to analyze.'),
});
export type DetectPhishingIndicatorsInput = z.infer<typeof DetectPhishingIndicatorsInputSchema>;

const DetectPhishingIndicatorsOutputSchema = z.object({
  url: z.string().describe('The original URL that was analyzed.'),
  isSafe: z.boolean().describe('Whether the URL is considered safe from phishing. This is a critical assessment. If false, the user may be blocked from the site.'),
  riskAssessment: z
    .string()
    .describe('A brief risk assessment (1-2 sentences) explaining the reasoning behind the `isSafe` verdict, especially if unsafe.'),
  phishingConfidenceScore: z.number().min(0).max(100).describe('Confidence score (0-100%) that reflects how certain the AI is about the phishing assessment verdict. If confidence is low, explain why in the riskAssessment.'),
  phishingWarningLevel: z.enum(["Low", "Medium", "High"]).describe('Warning level for phishing risk. "High" indicates a definitive phishing attempt.'),
});
export type DetectPhishingIndicatorsOutput = z.infer<
  typeof DetectPhishingIndicatorsOutputSchema
>;

export async function detectPhishingIndicators(
  input: DetectPhishingIndicatorsInput
): Promise<DetectPhishingIndicatorsOutput> {
  return detectPhishingIndicatorsFlow(input);
}

const detectPhishingIndicatorsPrompt = ai.definePrompt({
  name: 'detectPhishingIndicatorsPrompt',
  input: {
    schema: z.object({
      url: z.string().describe('The URL to analyze.'),
      safetyDescription: z
        .string()
        .describe('A description of the safety assessment of the url.'),
      isSafe: z.boolean().describe('A boolean indicating whether the URL is safe based on the initial safety assessment.'),
    }),
  },
  output: {
    schema: DetectPhishingIndicatorsOutputSchema,
  },
  prompt: `You are an AI security analyst. Your task is to detect phishing indicators in a URL. Your output will be used to decide whether to BLOCK a user from visiting a website. Be decisive and err on the side of caution.

URL: {{url}}
Initial Safety Check: {{safetyDescription}}
Is URL Initially Flagged Safe: {{isSafe}}

Analyze the URL and its implied content for phishing.
1.  **URL Field:** Set the 'url' field in your output to the exact URL provided above: {{url}}.
2.  **Phishing Safety Verdict ('isSafe' field):**
    *   This is the most important field. Set 'isSafe' to 'false' if you find any significant phishing indicators (e.g., misleading domain, imitation of a known brand, unusual characters, suspicious subdomains, URL shorteners in a suspicious context).
    *   Set 'isSafe' to 'true' only if you are highly confident there are no phishing signals. If there is any doubt, it is not safe.
3.  **Risk Assessment ('riskAssessment' field):**
    *   Provide a brief justification (1-2 sentences) for your 'isSafe' verdict. If unsafe, clearly state what indicators you found.
4.  **Confidence Score ('phishingConfidenceScore' field):**
    *   Provide a confidence score (0-100%) for your 'isSafe' verdict. A verdict of 'true' (safe) should generally have a high confidence score (>90%). A low confidence score on an unsafe verdict means you suspect something but lack definitive proof.
5.  **Warning Level ('phishingWarningLevel' field):**
    *   Assign a 'phishingWarningLevel' based on the severity and number of indicators:
        *   "High": You have found clear, strong evidence of phishing. 'isSafe' must be false.
        *   "Medium": There are suspicious elements, but they aren't conclusive proof of phishing. 'isSafe' should likely be false.
        *   "Low": You have found no phishing indicators.

Provide your response as a JSON object. Your primary duty is to protect the user.
`,
});

const detectPhishingIndicatorsFlow = ai.defineFlow<
  typeof DetectPhishingIndicatorsInputSchema,
  typeof DetectPhishingIndicatorsOutputSchema
>(
  {
    name: 'detectPhishingIndicatorsFlow',
    inputSchema: DetectPhishingIndicatorsInputSchema,
    outputSchema: DetectPhishingIndicatorsOutputSchema,
  },
  async input => {
    // Perform initial safety check
    const safetyAssessment = await assessUrlSafety(input.url);

    if (!safetyAssessment.isSafe) {
      return {
        url: input.url,
        isSafe: false,
        riskAssessment: `URL flagged as unsafe by initial scan: ${safetyAssessment.description}`,
        phishingConfidenceScore: 100,
        phishingWarningLevel: "High" as const,
      };
    }

    // Heuristic phishing detection (AI turned off)
    const reasons: string[] = [];
    let score = 0;

    if (!input.url.startsWith("https")) {
      score += 30;
      reasons.push("URL does not use HTTPS");
    }

    if (input.url.length > 100) { // Increased threshold
      score += 12;
      reasons.push("URL length is unusually long");
    }

    // More specific suspicious keywords - avoid legitimate sites
    const suspiciousKeywords = /(login|verify|secure|update|confirm|account|signin|password|reset)/i;
    const legitimateDomains = /(paypal|amazon|google|facebook|microsoft|apple|icici|hdfc|sbi|axis|edu|gov|org)/i;
    const knownBanks = /(icici|hdfc|sbi|axis|bankofbaroda|canarabank|unionbank|punjabnationalbank|idbi|bandhanbank)/i;

    // Domain analysis - moved up to avoid initialization error
    const domain = new URL(input.url).hostname;

    // Check for suspicious bank domains that aren't well-known
    if (/bank/i.test(domain) && !knownBanks.test(domain)) {
      score += 40;
      reasons.push("Unknown or suspicious banking domain");
    }

    if (suspiciousKeywords.test(input.url) && !legitimateDomains.test(input.url)) {
      score += 15;
      reasons.push("Suspicious keywords found in URL");
    }

    if (/[0-9]{5,}/.test(input.url)) { // More than 4 consecutive numbers
      score += 12;
      reasons.push("Unusual number sequences in URL");
    }

    if (input.url.includes("..") || input.url.includes("//")) {
      score += 18;
      reasons.push("Suspicious URL structure");
    }

    // Domain analysis
    if (domain.split('.').length > 3) {
      score += 12;
      reasons.push("Unusual domain structure");
    }

    // Check for obviously suspicious domains
    if (/fake|phish|testfire|unsafe|demo.*unsafe/i.test(domain)) {
      score += 40;
      reasons.push("Domain appears to be a known test or fake site");
    }

    const isSafe = score < 50; // Balanced threshold
    const riskAssessment = isSafe
      ? "No significant phishing indicators detected in URL analysis."
      : `Potential phishing detected. Suspicious indicators: ${reasons.join(", ")}. This URL exhibits characteristics commonly associated with phishing attempts.`;
    const confidence = isSafe ? 80 : Math.min(95, 70 + score);
    const warning: "Low" | "Medium" | "High" = isSafe ? "Low" : score > 50 ? "High" : "Medium";

    return {
      url: input.url,
      isSafe,
      riskAssessment,
      phishingConfidenceScore: confidence,
      phishingWarningLevel: warning,
    };
  }
);
