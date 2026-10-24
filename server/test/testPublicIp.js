import isPublicIp from "../utils/isPublicIp.js";

const ips = [
    ["1.1.1.1", true],
    ["8.8.8.8", true],
    ["192.168.1.1", false],
    ["10.0.0.1", false],
    ["127.0.0.1", false],
    ["169.254.169.254", false],
    ["224.0.0.1", false],
    ["::1", false],
    ["fc00::1", false],
    ["fe80::1", false],
    ["2001:4860:4860::8888", true],
    ["::ffff:192.168.1.25", false],
    ["::ffff:8.8.8.8", true],
    ["not-an-ip", false],
    ["", false],

    // Additional special-purpose address checks
    ["0.0.0.0", false],
    ["100.64.0.1", false],
    ["192.0.2.1", false],
    ["198.51.100.1", false],
    ["203.0.113.1", false],
    ["240.0.0.1", false],
    ["2001:db8::1", false],
    ["ff02::1", false]
];

let passed = 0;
let failed = 0;

for (const [ip, expected] of ips) {
    const actual = isPublicIp(ip);
    const ok = actual === expected;

    console.log(
        `${ip || "(empty)"} -> ${actual} | ${ok ? "PASS" : "FAIL"}`
    );

    if (ok) passed++;
    else failed++;
}

console.log(`\nSummary: ${passed}/${ips.length} passed, ${failed} failed`);
