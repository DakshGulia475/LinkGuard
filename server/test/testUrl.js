
import validateurl from "../utils/validateurl.js";

const testCases = [
    ["https://example.com", true],
    ["http://google.com", true],
    ["https://example.com/path?q=1", true],
    ["ftp://example.com", false],
    ["javascript:alert(1)", false],
    ["file:///etc/passwd", false],
    ["example.com", false],
    ["", false],
    ["   ", false],
    [null, false],
    [123, false],
    ["not a url", false]
];

let passed = 0;
let failed = 0;

for (const [input, expected] of testCases) {
    const actual = validateurl(input);
    const ok = actual === expected;

    console.log(
        `${JSON.stringify(input)} -> ${actual} | ${ok ? "PASS" : "FAIL"}`
    );

    if (ok) passed++;
    else failed++;
}

console.log(`\nSummary: ${passed}/${testCases.length} passed, ${failed} failed`);
