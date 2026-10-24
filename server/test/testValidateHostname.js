
import validateHostname from "./utils/validateHostname.js";

const hostnames = [
    ["example.com", true],
    ["google.com", true],
    ["api.example.com", true],
    ["localhost", false],
    ["api.localhost", false],
    ["intranet", false],
    ["my-server.local", false],
    ["service.internal", false],
    ["invalid-domain.example", false],
    ["-bad.example.com", false],
    ["good..example.com", false],
    ["192.168.1.25", false],
    ["", false],
    ["not a hostname", false]
];

let passed = 0;
let failed = 0;

for (const [hostname, expected] of hostnames) {
    const actual = validateHostname(hostname);
    const ok = actual === expected;

    console.log(
        `${JSON.stringify(hostname)} -> ${actual} | ${ok ? "PASS" : "FAIL"}`
    );

    if (ok) passed++;
    else failed++;
}

console.log(`\nSummary: ${passed}/${hostnames.length} passed, ${failed} failed`);
