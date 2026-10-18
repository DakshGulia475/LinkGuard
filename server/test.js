
import resolveHostname from "./utils/resolveHostname.js";

const testCases = [
    // Public domains: should resolve successfully
    { input: "example.com", expected: "ALLOW" },
    { input: "google.com", expected: "ALLOW" },

    // Local and reserved hostnames: should be blocked
    { input: "localhost", expected: "BLOCK" },
    { input: "api.localhost", expected: "BLOCK" },
    { input: "intranet", expected: "BLOCK" },
    { input: "service.internal", expected: "BLOCK" },
    { input: "invalid-domain.example", expected: "BLOCK" },

    // Malformed hostnames: should be blocked
    { input: "-bad.example.com", expected: "BLOCK" },
    { input: "good..example.com", expected: "BLOCK" },
    { input: "not a hostname", expected: "BLOCK" },
    { input: "", expected: "BLOCK" },

    // Private, loopback, and link-local IPs: should be blocked
    { input: "127.0.0.1", expected: "BLOCK" },
    { input: "192.168.1.25", expected: "BLOCK" },
    { input: "169.254.169.254", expected: "BLOCK" },
    { input: "10.0.0.1", expected: "BLOCK" },
    { input: "::1", expected: "BLOCK" },
    { input: "::ffff:192.168.1.25", expected: "BLOCK" }
];

let passed = 0;
let failed = 0;

for (const test of testCases) {
    console.log(`\nChecking: ${JSON.stringify(test.input)}`);

    const start = Date.now();

    try {
        const addresses = await resolveHostname(test.input);

        console.log("Result: ALLOW");
        console.log("Resolved IPs:", addresses);

        if (test.expected === "ALLOW") {
            console.log("Check: PASS");
            passed++;
        } else {
            console.log("Check: FAIL — expected BLOCK");
            failed++;
        }
    } catch (error) {
        console.log("Result: BLOCK");
        console.log("Reason:", error.message);

        if (test.expected === "BLOCK") {
            console.log("Check: PASS");
            passed++;
        } else {
            console.log("Check: FAIL — expected ALLOW");
            failed++;
        }
    }

    console.log("Time:", `${Date.now() - start} ms`);
}

console.log("\n========== SUMMARY ==========");
console.log(`Passed: ${passed}/${testCases.length}`);
console.log(`Failed: ${failed}/${testCases.length}`);

if (failed > 0) {
    console.log("Some cases need investigation.");
} else {
    console.log("All manual checks passed.");
}
