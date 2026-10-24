
import net from "node:net";

const SECURITY_HEADERS = [
    "contentSecurityPolicy",
    "xContentTypeOptions",
    "xFrameOptions"
];

function addSignal(signals, id, severity, message, evidence = {}) {
    signals.push({ id, severity, message, evidence });
}

function safeUrl(input) {
    try {
        const url = new URL(input);
        url.username = "";
        url.password = "";
        url.hash = "";
        return url.href;
    } catch {
        return null;
    }
}

function getHostname(input) {
    try {
        return new URL(input).hostname.replace(/^\[|\]$/g, "");
    } catch {
        return null;
    }
}

function analyzeUrl(inputUrl, inspection = null, inspectionError = null) {
    const signals = [];
    let parsed;

    try {
        parsed = new URL(inputUrl);
    } catch {
        addSignal(
            signals,
            "inspection.failed",
            "info",
            "The URL could not be parsed for analysis."
        );
        return signals;
    }

    const hostname = getHostname(inputUrl);

    // Embedded credentials can disguise a destination, but are not
    // sufficient evidence that the URL is malicious.
    if (parsed.username || parsed.password) {
        addSignal(
            signals,
            "url.userinfo",
            "warning",
            "The URL contains embedded user-information fields. Verify the actual destination before trusting it.",
            {
                usernamePresent: Boolean(parsed.username),
                passwordPresent: Boolean(parsed.password)
            }
        );
    }

    if (parsed.protocol === "https:") {
        addSignal(
            signals,
            "url.https",
            "info",
            "The URL uses HTTPS.",
            { protocol: parsed.protocol }
        );
    } else if (parsed.protocol === "http:") {
        addSignal(
            signals,
            "url.http",
            "warning",
            "The URL uses unencrypted HTTP.",
            { protocol: parsed.protocol }
        );
    }

    if (hostname && net.isIP(hostname) !== 0) {
        addSignal(
            signals,
            "url.ip_host",
            "warning",
            "The URL uses an IP address instead of a domain name.",
            { hostname }
        );
    }

    if (
        hostname &&
        hostname.toLowerCase().split(".").some(
            label => label.startsWith("xn--")
        )
    ) {
        addSignal(
            signals,
            "url.punycode",
            "warning",
            "The hostname contains a punycode label. Inspect it carefully for possible lookalike characters.",
            { hostname }
        );
    }

    const chain =
        inspection?.redirectChain ??
        inspectionError?.partialInspection?.redirectChain ??
        [];

    for (const redirect of chain) {
        let fromHost;
        let toHost;

        try {
            fromHost = new URL(redirect.from).hostname.toLowerCase();
            toHost = new URL(redirect.to).hostname.toLowerCase();
        } catch {
            continue;
        }

        if (fromHost !== toHost) {
            addSignal(
                signals,
                "redirect.cross_host",
                "warning",
                "A redirect changes the destination hostname. Cross-host redirects can be legitimate, but the destination should be reviewed.",
                {
                    fromHost,
                    toHost,
                    statusCode: redirect.statusCode
                }
            );
        }
    }

    // This is a high-severity security-policy event, not proof that
    // the original URL is malicious. The report scorer treats it separately.
    const blockedUrl = inspectionError?.blockedUrl;

    if (
        blockedUrl &&
        inspectionError?.code === "DESTINATION_PROHIBITED"
    ) {
        addSignal(
            signals,
            "redirect.private_target",
            "high",
            "Inspection blocked a redirect to a prohibited destination.",
            { blockedUrl: safeUrl(blockedUrl) }
        );
    }

    if (chain.length > 1) {
        addSignal(
            signals,
            "redirect.multiple",
            "info",
            "The URL passed through multiple redirects.",
            { redirectCount: chain.length }
        );
    }

    if (inspection) {
        addSignal(
            signals,
            "http.status",
            "info",
            "An HTTP response was received.",
            { statusCode: inspection.statusCode }
        );

        if (inspection.contentType) {
            addSignal(
                signals,
                "http.content_type",
                "info",
                "The response declared a content type.",
                { contentType: inspection.contentType }
            );
        }

        const headers = inspection.securityHeaders;

        if (
            parsed.protocol === "https:" &&
            headers &&
            SECURITY_HEADERS.every(
                header => headers[header] === false
            )
        ) {
            addSignal(
                signals,
                "http.missing_security_header",
                "warning",
                "Several common browser security-hardening headers were absent. This is a configuration observation, not proof of maliciousness.",
                { absentHeaders: SECURITY_HEADERS }
            );
        }
    } else if (inspectionError) {
        addSignal(
            signals,
            "inspection.failed",
            "info",
            "The HTTP inspection did not complete. This does not by itself indicate maliciousness.",
            { code: inspectionError.code ?? "INSPECTION_FAILED" }
        );
    }

    return signals;
}

export { safeUrl };
export default analyzeUrl;
