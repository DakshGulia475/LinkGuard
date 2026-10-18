
import net from "node:net";
import isPublicIp from "./isPublicIp.js";
import validateHostname from "./validateHostname.js";

const DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";
const DNS_TIMEOUT_MS = 3000;

async function queryDns(hostname, type) {
    const url = new URL(DOH_ENDPOINT);
    url.searchParams.set("name", hostname);
    url.searchParams.set("type", type);

    const response = await fetch(url, {
        headers: {
            Accept: "application/dns-json"
        },
        signal: AbortSignal.timeout(DNS_TIMEOUT_MS),
        redirect: "error"
    });

    if (!response.ok) {
        throw new Error("DNS provider request failed");
    }

    const data = await response.json();

    if (
        !data ||
        typeof data.Status !== "number" ||
        (data.Answer !== undefined && !Array.isArray(data.Answer))
    ) {
        throw new Error("Invalid DNS response");
    }

    const expectedType = type === "A" ? 1 : 28;

    // Verify that the response contains our requested DNS question.
    if (
        !Array.isArray(data.Question) ||
        !data.Question.some(question =>
            typeof question.name === "string" &&
            question.name.replace(/\.$/, "").toLowerCase() ===
                hostname.replace(/\.$/, "").toLowerCase() &&
            question.type === expectedType
        )
    ) {
        throw new Error("DNS response question mismatch");
    }

    // DNS status 0 means NOERROR.
    if (data.Status !== 0) {
        if (data.Status === 3) {
            throw new Error("Hostname does not exist (NXDOMAIN)");
        }

        throw new Error("DNS query was unsuccessful");
    }

    if (data.TC === true) {
        throw new Error("DNS response was truncated");
    }

    const answers = data.Answer ?? [];

    return answers
        .filter(record => record.type === expectedType)
        .map(record => {
            if (
                typeof record.data !== "string" ||
                net.isIP(record.data) !== (type === "A" ? 4 : 6)
            ) {
                throw new Error("Invalid IP address in DNS response");
            }

            return record.data;
        });
}

async function resolveHostname(hostname) {
    if (typeof hostname !== "string" || hostname.trim() === "") {
        throw new Error("Invalid hostname");
    }

    let normalizedHostname = hostname.trim().toLowerCase();

    // Remove brackets around IPv6 literals, if present.
    if (
        normalizedHostname.startsWith("[") &&
        normalizedHostname.endsWith("]")
    ) {
        normalizedHostname = normalizedHostname.slice(1, -1);
    }

    // IP literals do not require DNS resolution.
    // They must still pass our public-IP policy.
    if (net.isIP(normalizedHostname) !== 0) {
        if (!isPublicIp(normalizedHostname)) {
            throw new Error("Hostname resolves to a prohibited IP address");
        }

        return [normalizedHostname];
    }

    // Reject invalid, local, or reserved hostnames before DNS requests.
    if (!validateHostname(normalizedHostname)) {
        throw new Error("Invalid or prohibited hostname");
    }

    // Resolve IPv4 and IPv6 concurrently.
    // Reject if either query fails, rather than using incomplete results.
    const [ipv4Addresses, ipv6Addresses] = await Promise.all([
        queryDns(normalizedHostname, "A"),
        queryDns(normalizedHostname, "AAAA")
    ]);

    const addresses = [...new Set([
        ...ipv4Addresses,
        ...ipv6Addresses
    ])];

    if (addresses.length === 0) {
        throw new Error("Hostname has no usable IP addresses");
    }

    // Every returned address must pass the IP safety policy.
    if (!addresses.every(isPublicIp)) {
        throw new Error("Hostname resolves to a prohibited IP address");
    }

    return addresses;
}

export default resolveHostname;
