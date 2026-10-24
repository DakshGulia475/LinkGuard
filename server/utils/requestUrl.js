
import http from "node:http";
import https from "node:https";
import net from "node:net";
import ipaddr from "ipaddr.js";
import isPublicIp from "./isPublicIp.js";

const REQUEST_TIMEOUT_MS = 5000;
const MAX_RESPONSE_BYTES = 64 * 1024;

function makeError(message, code) {
    const error = new Error(message);
    error.code = code;
    return error;
}

function sameIp(first, second) {
    if (net.isIP(first) === 0 || net.isIP(second) === 0) {
        return false;
    }

    try {
        return ipaddr.process(first).toNormalizedString() ===
            ipaddr.process(second).toNormalizedString();
    } catch {
        return false;
    }
}

/*
 * Internal transport core.
 *
 * It pins the connection to the supplied IP and never follows redirects.
 * This core does not enforce public-IP policy; production callers must use
 * the default export below. Tests use this core against local fixtures.
 */
export function requestUrlCore(
    inputUrl,
    pinnedIp,
    { timeoutMs = REQUEST_TIMEOUT_MS, maxResponseBytes = MAX_RESPONSE_BYTES } = {}
) {
    return new Promise((resolve, reject) => {
        let url;

        try {
            url = new URL(inputUrl);
        } catch {
            reject(makeError("Invalid URL", "URL_INVALID"));
            return;
        }

        if (url.protocol !== "http:" && url.protocol !== "https:") {
            reject(makeError("Unsupported URL protocol", "URL_INVALID"));
            return;
        }

        if (url.username || url.password) {
            reject(makeError("URL credentials are not allowed", "URL_INVALID"));
            return;
        }

        if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
            reject(makeError("Invalid request timeout", "REQUEST_TIMEOUT"));
            return;
        }

        if (!Number.isInteger(maxResponseBytes) || maxResponseBytes < 1) {
            reject(makeError("Invalid response size limit", "RESPONSE_TOO_LARGE"));
            return;
        }

        const expectedPort = url.protocol === "https:" ? 443 : 80;
        const port = url.port ? Number(url.port) : expectedPort;

        if (!Number.isInteger(port) || port < 1 || port > 65535) {
            reject(makeError("Invalid URL port", "URL_INVALID"));
            return;
        }

        const family = net.isIP(pinnedIp);

        if (family === 0) {
            reject(makeError("Invalid pinned IP address", "DESTINATION_PROHIBITED"));
            return;
        }

        const hostname = url.hostname.replace(/^\[|\]$/g, "");
        const hostnameIsIp = net.isIP(hostname) !== 0;

        // Node may skip DNS lookup when the URL itself contains an IP literal.
        // Never let the URL's IP bypass the selected, validated destination.
        if (hostnameIsIp && !sameIp(hostname, pinnedIp)) {
            reject(makeError("Pinned IP does not match URL IP", "DESTINATION_PROHIBITED"));
            return;
        }

        const client = url.protocol === "https:" ? https : http;
        let settled = false;
        let timer;

        const finish = (error, result) => {
            if (settled) return;
            settled = true;
            if (timer) clearTimeout(timer);

            if (error) reject(error);
            else resolve(result);
        };

        const options = {
            protocol: url.protocol,
            hostname,
            port,
            method: "GET",
            path: `${url.pathname}${url.search}`,
            agent: false,
            headers: {
                Host: url.host,
                "User-Agent": "LinkGuard/1.0",
                Accept: "*/*",
                "Accept-Encoding": "identity"
            },
            lookup: (_hostname, lookupOptions, callback) => {
                if (lookupOptions?.all) {
                    callback(null, [{ address: pinnedIp, family }]);
                } else {
                    callback(null, pinnedIp, family);
                }
            }
        };

        // Keep certificate verification enabled and preserve the original
        // domain name for TLS SNI and certificate hostname validation.
        if (url.protocol === "https:" && !hostnameIsIp) {
            options.servername = hostname;
        }

        let req;

        try {
            req = client.request(options, (res) => {
                let responseBytes = 0;

                const declaredLength = Number(res.headers["content-length"]);

                if (
                    Number.isFinite(declaredLength) &&
                    declaredLength > maxResponseBytes
                ) {
                    finish(
                        makeError("Response body exceeds size limit", "RESPONSE_TOO_LARGE")
                    );
                    res.destroy();
                    req.destroy();
                    return;
                }

                res.on("data", (chunk) => {
                    responseBytes += chunk.length;

                    if (responseBytes > maxResponseBytes) {
                        finish(
                            makeError("Response body exceeds size limit", "RESPONSE_TOO_LARGE")
                        );
                        res.destroy();
                        req.destroy();
                    }
                });

                res.on("end", () => {
                    finish(null, {
                        statusCode: res.statusCode,
                        headers: res.headers,
                        responseBytes
                    });
                });

                res.on("error", (error) => {
                    finish(
                        makeError(
                            error.message || "Response read failed",
                            "REQUEST_FAILED"
                        )
                    );
                });
            });
        } catch {
            finish(makeError("HTTP request could not be created", "REQUEST_FAILED"));
            return;
        }

        req.on("error", (error) => {
            if (settled) return;

            if (error.code === "RESPONSE_TOO_LARGE") {
                finish(makeError("Response body exceeds size limit", "RESPONSE_TOO_LARGE"));
            } else if (error.code === "ETIMEDOUT" || error.code === "ABORT_ERR") {
                finish(makeError("Request timed out", "REQUEST_TIMEOUT"));
            } else {
                finish(makeError("HTTP or TLS request failed", "REQUEST_FAILED"));
            }
        });

        timer = setTimeout(() => {
            finish(makeError("Request timed out", "REQUEST_TIMEOUT"));
            req.destroy();
        }, timeoutMs);

        req.end();
    });
}

/*
 * Production entry point: do not call the transport core directly from
 * application routes. Public-IP and standard-port policy lives here.
 */
export default function requestUrl(inputUrl, pinnedIp, { timeoutMs = REQUEST_TIMEOUT_MS } = {}) {
    let url;

    try {
        url = new URL(inputUrl);
    } catch {
        throw makeError("Invalid URL", "URL_INVALID");
    }

    if (url.protocol !== "http:" && url.protocol !== "https:") {
        throw makeError("Unsupported URL protocol", "URL_INVALID");
    }

    if (url.username || url.password) {
        throw makeError("URL credentials are not allowed", "URL_INVALID");
    }

    const expectedPort = url.protocol === "https:" ? 443 : 80;
    const port = url.port ? Number(url.port) : expectedPort;

    if (port !== expectedPort) {
        throw makeError("URL port is not allowed", "URL_INVALID");
    }

    if (!isPublicIp(pinnedIp)) {
        throw makeError("Prohibited destination IP address", "DESTINATION_PROHIBITED");
    }

    const hostname = url.hostname.replace(/^\[|\]$/g, "");

    if (net.isIP(hostname) !== 0 && !sameIp(hostname, pinnedIp)) {
        throw makeError("Pinned IP does not match URL IP", "DESTINATION_PROHIBITED");
    }

    return requestUrlCore(inputUrl, pinnedIp, {
        timeoutMs: Math.min(timeoutMs, REQUEST_TIMEOUT_MS),
        maxResponseBytes: MAX_RESPONSE_BYTES
    });
}
