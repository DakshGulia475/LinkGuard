
import net from "node:net";
import isPublicIp from "./isPublicIp.js";
import validateurl from "./validateurl.js";
import resolveHostname from "./resolveHostname.js";
import requestUrl from "./requestUrl.js";

const INSPECTION_TIMEOUT_MS = 15_000;
const MAX_REDIRECTS = 5;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function makeError(message, code) {
    const error = new Error(message);
    error.code = code;
    return error;
}

function normalizeUrl(input) {
    let url;

    try {
        url = new URL(input);
    } catch {
        throw makeError("Invalid URL", "URL_INVALID");
    }

    if (!validateurl(input)) {
        throw makeError("Only absolute HTTP and HTTPS URLs are allowed", "URL_INVALID");
    }

    if (url.username || url.password) {
        throw makeError("URL credentials are not allowed", "URL_INVALID");
    }

    const expectedPort = url.protocol === "https:" ? 443 : 80;
    const port = url.port ? Number(url.port) : expectedPort;

    if (port !== expectedPort) {
        throw makeError("URL port is not allowed", "URL_INVALID");
    }

    url.hash = "";
    return url;
}

function remainingTime(deadline) {
    const remaining = deadline - Date.now();

    if (remaining <= 0) {
        throw makeError("Inspection deadline exceeded", "INSPECTION_TIMEOUT");
    }

    return remaining;
}

function attachPartialEvidence(error, originalUrl, currentUrl, redirectChain) {
    error.partialInspection = {
        originalUrl,
        finalUrl: currentUrl,
        statusCode: null,
        redirectCount: redirectChain.length,
        redirectChain: [...redirectChain],
        contentType: null,
        responseBytes: null,
        inspectionStatus: "partial",
        securityHeaders: null
    };

    // Only label this a blocked redirect if the destination followed a redirect.
    if (redirectChain.length > 0 && currentUrl !== originalUrl) {
        error.blockedUrl = currentUrl;
    }

    return error;
}

function getSecurityHeaders(headers = {}) {
    const present = name =>
        typeof headers[name] === "string" && headers[name].trim() !== "";

    return {
        strictTransportSecurity: present("strict-transport-security"),
        contentSecurityPolicy: present("content-security-policy"),
        xContentTypeOptions: present("x-content-type-options"),
        xFrameOptions: present("x-frame-options"),
        referrerPolicy: present("referrer-policy"),
        permissionsPolicy: present("permissions-policy")
    };
}

async function inspectUrl(inputUrl, dependencies = {}) {
    const resolver = dependencies.resolveHostname ?? resolveHostname;
    const requester = dependencies.requestUrl ?? requestUrl;
    const deadlineMs = dependencies.deadlineMs ?? INSPECTION_TIMEOUT_MS;

    const deadline = Date.now() + deadlineMs;
    const deadlineSignal = AbortSignal.timeout(deadlineMs);

    let currentUrl = normalizeUrl(inputUrl).href;
    const originalUrl = currentUrl;
    const visited = new Set([currentUrl]);
    const redirectChain = [];

    while (true) {
        remainingTime(deadline);

        const url = normalizeUrl(currentUrl);
        const hostname = url.hostname.replace(/^\[|\]$/g, "");

        if (net.isIP(hostname) !== 0 && !isPublicIp(hostname)) {
            throw attachPartialEvidence(
                makeError("Prohibited destination IP address", "DESTINATION_PROHIBITED"),
                originalUrl,
                currentUrl,
                redirectChain
            );
        }

        let addresses;

        try {
            addresses = await resolver(hostname, { signal: deadlineSignal });
        } catch (error) {
            if (deadlineSignal.aborted || Date.now() >= deadline) {
                throw attachPartialEvidence(
                    makeError("Inspection deadline exceeded", "INSPECTION_TIMEOUT"),
                    originalUrl,
                    currentUrl,
                    redirectChain
                );
            }

            if (
                error?.code === "DESTINATION_PROHIBITED" ||
                error?.code === "HOSTNAME_INVALID"
            ) {
                throw attachPartialEvidence(
                    error,
                    originalUrl,
                    currentUrl,
                    redirectChain
                );
            }

            throw attachPartialEvidence(
                makeError("Could not resolve destination hostname", "DNS_FAILED"),
                originalUrl,
                currentUrl,
                redirectChain
            );
        }

        remainingTime(deadline);

        if (!Array.isArray(addresses) || addresses.length === 0) {
            throw attachPartialEvidence(
                makeError("Hostname has no usable IP addresses", "DNS_FAILED"),
                originalUrl,
                currentUrl,
                redirectChain
            );
        }

        if (!addresses.every(address =>
            typeof address === "string" && isPublicIp(address)
        )) {
            throw attachPartialEvidence(
                makeError(
                    "Hostname resolves to a prohibited IP address",
                    "DESTINATION_PROHIBITED"
                ),
                originalUrl,
                currentUrl,
                redirectChain
            );
        }

        const pinnedIp = addresses[0];

        if (net.isIP(pinnedIp) === 0) {
            throw attachPartialEvidence(
                makeError("Invalid destination IP address", "DNS_FAILED"),
                originalUrl,
                currentUrl,
                redirectChain
            );
        }

        let response;

        try {
            response = await requester(currentUrl, pinnedIp, {
                timeoutMs: Math.min(5000, remainingTime(deadline))
            });
        } catch (error) {
            if (Date.now() >= deadline || error?.code === "INSPECTION_TIMEOUT") {
                throw attachPartialEvidence(
                    makeError("Inspection deadline exceeded", "INSPECTION_TIMEOUT"),
                    originalUrl,
                    currentUrl,
                    redirectChain
                );
            }

            throw attachPartialEvidence(
                error?.code
                    ? error
                    : makeError("HTTP or TLS request failed", "REQUEST_FAILED"),
                originalUrl,
                currentUrl,
                redirectChain
            );
        }

        remainingTime(deadline);

        const location = response.headers?.location;

        if (!REDIRECT_STATUSES.has(response.statusCode) || !location) {
            const rawContentType = response.headers?.["content-type"];
            const contentType = typeof rawContentType === "string"
                ? rawContentType.split(";")[0].trim()
                : null;

            return {
                originalUrl,
                finalUrl: currentUrl,
                statusCode: response.statusCode,
                redirectCount: redirectChain.length,
                redirectChain,
                contentType,
                responseBytes: response.responseBytes,
                inspectionStatus: "completed",
                securityHeaders: getSecurityHeaders(response.headers)
            };
        }

        if (redirectChain.length >= MAX_REDIRECTS) {
            throw attachPartialEvidence(
                makeError("Redirect limit exceeded", "REDIRECT_LIMIT"),
                originalUrl,
                currentUrl,
                redirectChain
            );
        }

        let nextUrl;

        try {
            nextUrl = normalizeUrl(new URL(location, currentUrl).href).href;
        } catch (error) {
            throw attachPartialEvidence(
                error?.code
                    ? error
                    : makeError("Invalid redirect destination", "URL_INVALID"),
                originalUrl,
                currentUrl,
                redirectChain
            );
        }

        if (visited.has(nextUrl)) {
            throw attachPartialEvidence(
                makeError("Redirect loop detected", "REDIRECT_LOOP"),
                originalUrl,
                currentUrl,
                redirectChain
            );
        }

        redirectChain.push({
            statusCode: response.statusCode,
            from: currentUrl,
            to: nextUrl
        });

        visited.add(nextUrl);
        currentUrl = nextUrl;
    }
}

export default inspectUrl;
