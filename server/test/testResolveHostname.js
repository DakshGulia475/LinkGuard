
import resolveHostname from "../utils/resolveHostname.js";

const testCases = [
    { input: "example.com", expected: "ALLOW" },
    { input: "google.com", expected: "ALLOW" },

    { input: "localhost", expected: "BLOCK" },
    { input: "api.localhost", expected: "BLOCK" },
    { input: "intranet", expected: "BLOCK" },
    { input: "service.internal", expected: "BLOCK" },
    { input: "invalid-domain.example", expected: "BLOCK" },

    { input: "-bad.example.com", expected: "BLOCK" },
    { input: "good..example.com", expected: "BLOCK" },
    { input: "not a hostname", expected: "BLOCK" },
    { input: "", expected: "BLOCK" },

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

    try {
        const addresses = await resolveHostname(test.input);
        const actual = "ALLOW";

        console.log("Resolved IPs:", addresses);

        if (actual === test.expected) {
            console.log("Check: PASS");
            passed++;
        } else {
            console.log(`Check: FAIL — expected ${test.expected}`);
            failed++;
        }
    } catch (error) {
        const actual = "BLOCK";

        console.log("Reason:", error.message);

        if (actual === test.expected) {
            console.log("Check: PASS");
            passed++;
        } else {
            console.log(`Check: FAIL — expected ${test.expected}`);
            failed++;
        }
    }
}

console.log("\n========== SUMMARY ==========");
console.log(`Passed: ${passed}/${testCases.length}`);
console.log(`Failed: ${failed}/${testCases.length}`);
