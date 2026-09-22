export function heuristicFallback(url: string, html: string) {
  let score = 0;
  const reasons: string[] = [];
  const phishingIndicators: string[] = [];
  const contentRisks: string[] = [];
  const financialRisks: string[] = [];

  // URL checks
  if (!url.startsWith("https")) {
    score += 30; // Increased for non-HTTPS
    reasons.push("URL does not use HTTPS");
    phishingIndicators.push("Non-HTTPS connection increases phishing risk");
  }

  if (url.length > 100) { // Increased threshold
    score += 12;
    reasons.push("URL length is unusually long");
    phishingIndicators.push("Unusually long URL may indicate obfuscation");
  }

  // More specific keyword checks - avoid flagging legitimate sites
  const suspiciousKeywords = /(login|verify|secure|update|confirm|account|signin|password|reset)/i;
  const legitimateDomains = /(paypal|amazon|google|facebook|microsoft|apple|icici|hdfc|sbi|axis|edu|gov|org)/i;
  const knownBanks = /(icici|hdfc|sbi|axis|bankofbaroda|canarabank|unionbank|punjabnationalbank|idbi|bandhanbank)/i;

  // Domain checks - moved up to avoid initialization error
  const domain = new URL(url).hostname;

  // Check for suspicious bank domains that aren't well-known
  if (/bank/i.test(domain) && !knownBanks.test(domain)) {
    score += 25; // High penalty for unknown bank domains
    reasons.push("Unknown or suspicious banking domain");
    phishingIndicators.push("Domain claims to be a bank but is not a well-known financial institution");
  }

  if (suspiciousKeywords.test(url) && !legitimateDomains.test(url)) {
    score += 15; // Increased penalty for non-legitimate sites
    reasons.push("Suspicious keywords found in URL");
    phishingIndicators.push("URL contains keywords commonly used in phishing attempts");
  }

  if (/[0-9]{5,}/.test(url)) { // More than 4 consecutive numbers
    score += 12;
    reasons.push("Unusual number sequences in URL");
    phishingIndicators.push("Multiple consecutive numbers in URL may indicate generated or malicious links");
  }

  if (url.includes("..") || url.includes("//")) {
    score += 18;
    reasons.push("Suspicious URL structure");
    phishingIndicators.push("URL structure anomalies detected");
  }

  // Domain checks
  if (domain.split('.').length > 3) {
    score += 12;
    reasons.push("Unusual domain structure");
    phishingIndicators.push("Complex subdomain structure may indicate domain spoofing");
  }

  // Check for obviously suspicious domains
  if (/fake|phish|testfire|unsafe|demo.*unsafe/i.test(domain)) {
    score += 40; // High penalty for obviously fake/test domains
    reasons.push("Domain appears to be a known test or fake site");
    phishingIndicators.push("Domain matches known suspicious patterns");
  }

  // Content checks - be much more lenient for legitimate sites
  const isLikelyLegitimate = legitimateDomains.test(url) || knownBanks.test(domain);

  const hasPasswordField = /type=["']password["']/i.test(html);
  if (hasPasswordField) {
    if (!isLikelyLegitimate) {
      score += 20; // Increased penalty for non-legitimate sites
      reasons.push("Password input field detected");
      contentRisks.push("Password input fields present - verify legitimacy of login request");
    } else {
      // Even legitimate sites get a small penalty if they have password fields
      score += 5;
      contentRisks.push("Password input fields present on known legitimate domain");
    }
  }

  const hasFinancialFields = /card|cvv|expiry|security.*code/i.test(html);
  if (hasFinancialFields) {
    if (!isLikelyLegitimate) {
      score += 25; // Increased penalty for non-legitimate sites
      reasons.push("Financial input fields detected");
      financialRisks.push("Credit card or financial information input fields detected");
    } else {
      // Small penalty even for legitimate sites to be cautious
      score += 8;
      financialRisks.push("Financial input fields detected on legitimate domain - appears safe");
    }
  }

  if (/hidden/i.test(html)) {
    if (!isLikelyLegitimate) {
      score += 10; // Increased penalty
      reasons.push("Hidden elements detected");
      contentRisks.push("Hidden form elements may be used to collect additional data");
    } else {
      score += 3; // Small penalty for legitimate sites
      contentRisks.push("Hidden elements present (common on legitimate sites)");
    }
  }

  if (/script.*src/i.test(html) && /eval\(|document\.write|innerHTML/i.test(html)) {
    if (!isLikelyLegitimate) {
      score += 15; // Increased penalty
      reasons.push("Potentially malicious scripts detected");
      contentRisks.push("Dynamic script execution detected - potential malware risk");
    } else {
      score += 5; // Small penalty for legitimate sites
      contentRisks.push("Dynamic scripts present (common on legitimate sites)");
    }
  }

  if (/iframe/i.test(html)) {
    if (!isLikelyLegitimate) {
      score += 10; // Increased penalty
      reasons.push("Embedded iframes detected");
      contentRisks.push("Iframes can be used to load malicious content");
    } else {
      score += 3; // Small penalty for legitimate sites
      contentRisks.push("Iframes present (common on legitimate sites for embeds)");
    }
  }

  // Balanced threshold - more cautious
  const isSafe = score < 35;

  // Generate detailed reports
  const phishingReport = phishingIndicators.length > 0
    ? `Potential phishing indicators identified: ${phishingIndicators.join(", ")}`
    : "No significant phishing indicators detected in URL structure";

  const contentReport = contentRisks.length > 0
    ? `Content analysis revealed risks: ${contentRisks.join(", ")}`
    : "Content appears generally safe with no obvious malicious elements";

  const financialReport = financialRisks.length > 0
    ? `Financial data analysis: ${financialRisks.join(", ")}. ${hasFinancialFields && isLikelyLegitimate ? "Appears safe for legitimate financial transactions." : "Exercise caution with financial transactions."}`
    : "No financial information collection detected";

  return {
    isSafe,
    score,
    reasons,
    method: "Heuristic Fallback Analysis",
    detailedReports: {
      phishing: phishingReport,
      content: contentReport,
      financial: financialReport
    }
  };
}
