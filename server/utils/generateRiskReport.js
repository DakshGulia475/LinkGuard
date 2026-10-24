
import analyzeUrl, { safeUrl } from "./analyzeUrl.js";

const HIGH_SEVERITY = "high";
const WARNING_SEVERITY = "warning";

// High-severity destination-policy blocks must not, by themselves,
// increase the assessment of URL maliciousness.
const POLICY_ONLY_SIGNALS = new Set([
    "redirect.private_target"
]);

function generateRiskReport(
    inputUrl,
    inspection = null,
    inspectionError = null
) {
    const signals = analyzeUrl(inputUrl, inspection, inspectionError);

    const assessmentSignals = signals.filter(
        signal => !POLICY_ONLY_SIGNALS.has(signal.id)
    );

    const hasHigh = assessmentSignals.some(
        signal => signal.severity === HIGH_SEVERITY
    );

    const hasWarning = assessmentSignals.some(
        signal => signal.severity === WARNING_SEVERITY
    );

    let riskLevel;
    let status;

    if (inspection) {
        status = "completed";

        if (hasHigh) {
            riskLevel = "high";
        } else if (hasWarning) {
            riskLevel = "medium";
        } else {
            riskLevel = "low";
        }
    } else if (hasHigh) {
        // Reserve this branch for high-concern signals that actually
        // contribute to the URL risk assessment.
        riskLevel = "high";
        status = "partial";
    } else {
        riskLevel = "inconclusive";
        status = inspectionError?.partialInspection
            ? "partial"
            : "inconclusive";
    }

    const reasons = signals
        .filter(
            signal =>
                signal.severity === HIGH_SEVERITY ||
                signal.severity === WARNING_SEVERITY
        )
        .map(signal => signal.message);

    let summary;

    if (riskLevel === "high") {
        summary =
            "One or more high-concern indicators were detected. This does not by itself prove the URL is malicious.";
    } else if (riskLevel === "medium") {
        summary =
            "One or more warning indicators were detected. Review the evidence before trusting the destination.";
    } else if (riskLevel === "low") {
        summary =
            "No configured warning or high-concern indicators were detected. This is not a guarantee of safety.";
    } else {
        summary =
            "There was insufficient evidence to assign a reliable risk level.";
    }

    const partial = inspectionError?.partialInspection ?? null;
    const result = inspection ?? partial;

    return {
        url: safeUrl(inputUrl),

        assessment: {
            riskLevel,
            status,
            summary,
            reasons
        },

        signals: {
            url: signals.filter(signal =>
                signal.id.startsWith("url.")
            ),

            redirects: signals.filter(signal =>
                signal.id.startsWith("redirect.")
            ),

            http: signals.filter(
                signal =>
                    signal.id.startsWith("http.") ||
                    signal.id.startsWith("inspection.")
            )
        },

        inspection: {
            originalUrl: safeUrl(result?.originalUrl ?? inputUrl),
            finalUrl: safeUrl(result?.finalUrl ?? null),
            httpStatus: result?.statusCode ?? null,
            contentType: result?.contentType ?? null,
            responseBytes: result?.responseBytes ?? null,
            redirectCount: result?.redirectCount ?? 0,

            redirectChain: (result?.redirectChain ?? []).map(
                redirect => ({
                    statusCode: redirect.statusCode,
                    from: safeUrl(redirect.from),
                    to: safeUrl(redirect.to)
                })
            ),

            securityHeaders: result?.securityHeaders ?? null
        },

        reputation: {
            status: "not_checked",
            provider: null
        },

        limitations: [
            "No external threat-reputation service was consulted.",
            "Rule-based indicators cannot identify every malicious URL.",
            "A low risk assessment is not a guarantee that a destination is safe."
        ]
    };
}

export default generateRiskReport;
