
import net from "node:net";
import isPublicIp from "./isPublicIp.js";
import validateHostname from "./validateHostname.js";

const DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";
const DNS_TIMEOUT_MS = 3000;

function makeError(message, code = "DNS_FAILED") {
    const error = new Error(message);
    error.code = code;
    return error;
}

async function queryDns(hostname, type, signal) {
    const url = new URL(DOH_ENDPOINT);
    url.searchParams.set("name", hostname);
    url.searchParams.set("type", type);

    const timeoutSignal = AbortSignal.timeout(DNS_TIMEOUT_MS);
    const combinedSignal = signal
        ? AbortSignal.any([timeoutSignal, signal])
        : timeoutSignal;

    let response;

    try {
        response = await fetch(url, {
            headers: { Accept: "application/dns-json" },
            signal: combinedSignal,
            redirect: "error"
        });
    } catch (error) {
        if (signal?.aborted) {
            throw makeError("Inspection deadline exceeded", "INSPECTION_TIMEOUT");
        }

        if (error?.name === "TimeoutError" || combinedSignal.aborted) {
            throw makeError("DNS query timed out", "DNS_TIMEOUT");
        }

        throw makeError("DNS provider request failed", "DNS_FAILED");
    }

    if (!response.ok) {
        throw makeError("DNS provider request failed", "DNS_FAILED");
    }

    let data;

    try {
        data = await response.json();
    } catch {
        throw makeError("Invalid DNS response", "DNS_FAILED");
    }

    if (
        !data ||
        typeof data.Status !== "number" ||
        (data.Answer !== undefined && !Array.isArray(data.Answer))
    ) {
        throw makeError("Invalid DNS response", "DNS_FAILED");
    }

    const expectedType = type === "A" ? 1 : 28;
    const normalizedHostname = hostname.replace(/\.$/, "").toLowerCase();

    if (
        !Array.isArray(data.Question) ||
        !data.Question.some(question =>
            typeof question.name === "string" &&
            question.name.replace(/\.$/, "").toLowerCase() === normalizedHostname &&
            question.type === expectedType
        )
    ) {
        throw makeError("DNS response question mismatch", "DNS_FAILED");
    }

    if (data.Status !== 0) {
        if (data.Status === 3) {
            throw makeError("Hostname does not exist (NXDOMAIN)", "DNS_FAILED");
        }

        throw makeError("DNS query was unsuccessful", "DNS_FAILED");
    }

    if (data.TC === true) {
        throw makeError("DNS response was truncated", "DNS_FAILED");
    }

    const answers = data.Answer ?? [];

    return answers
        .filter(record => record.type === expectedType)
        .map(record => {
            if (
                typeof record.data !== "string" ||
                net.isIP(record.data) !== (type === "A" ? 4 : 6)
            ) {
                throw makeError("Invalid IP address in DNS response", "DNS_FAILED");
            }

            return record.data;
        });
}

async function resolveHostname(hostname, { signal } = {}) {
    if (typeof hostname !== "string" || hostname.trim() === "") {
        throw makeError("Invalid hostname", "HOSTNAME_INVALID");
    }

    let normalizedHostname = hostname.trim().toLowerCase();

    if (
        normalizedHostname.startsWith("[") &&
        normalizedHostname.endsWith("]")
    ) {
        normalizedHostname = normalizedHostname.slice(1, -1);
    }

    if (net.isIP(normalizedHostname) !== 0) {
        if (!isPublicIp(normalizedHostname)) {
            throw makeError(
                "Hostname resolves to a prohibited IP address",
                "DESTINATION_PROHIBITED"
            );
        }

        return [normalizedHostname];
    }

    if (!validateHostname(normalizedHostname)) {
        throw makeError("Invalid or prohibited hostname", "HOSTNAME_INVALID");
    }

    const [ipv4Addresses, ipv6Addresses] = await Promise.all([
        queryDns(normalizedHostname, "A", signal),
        queryDns(normalizedHostname, "AAAA", signal)
    ]);

    const addresses = [...new Set([...ipv4Addresses, ...ipv6Addresses])];

    if (addresses.length === 0) {
        throw makeError("Hostname has no usable IP addresses", "DNS_FAILED");
    }

    if (!addresses.every(isPublicIp)) {
        throw makeError(
            "Hostname resolves to a prohibited IP address",
            "DESTINATION_PROHIBITED"
        );
    }

    return addresses;
}

export default resolveHostname;
