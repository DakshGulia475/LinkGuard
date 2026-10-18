
import net from "node:net";

function validateHostname(hostname) {
    if (typeof hostname !== "string" || hostname.trim() === "") {
        return false;
    }

    const host = hostname.trim().toLowerCase();

    // Reject IP literals here; resolveHostname handles them separately.
    if (net.isIP(host) !== 0) {
        return false;
    }

    // Reject local names and their subdomains.
    if (
        host === "localhost" ||
        host.endsWith(".localhost") ||
        host.endsWith(".local") ||
        host.endsWith(".internal") ||
        host.endsWith(".test") ||
        host.endsWith(".invalid") ||
        host.endsWith(".example")
    ) {
        return false;
    }

    // Require a fully qualified hostname with at least two labels.
    if (!host.includes(".")) {
        return false;
    }

    // DNS hostname length limit.
    if (host.length > 253) {
        return false;
    }

    const labels = host.split(".");

    // Validate each DNS label.
    for (const label of labels) {
        if (
            label.length < 1 ||
            label.length > 63 ||
            !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
        ) {
            return false;
        }
    }

    return true;
}

export default validateHostname;
