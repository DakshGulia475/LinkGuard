
import ipaddr from "ipaddr.js";

function isPublicIp(ip) {
    if (typeof ip !== "string" || ip.trim() === "") {
        return false;
    }

    const normalizedIp = ip.trim();

    if (!ipaddr.isValid(normalizedIp)) {
        return false;
    }

    try {
        // Convert IPv4-mapped IPv6 addresses to IPv4.
        const address = ipaddr.process(normalizedIp);
        const range = address.range();

        // Only globally routable unicast addresses pass.
        return range === "unicast";
    } catch {
        return false;
    }
}

export default isPublicIp;
