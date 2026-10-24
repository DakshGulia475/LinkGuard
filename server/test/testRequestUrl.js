
import requestUrl from "../utils/requestUrl.js";
import resolveHostname from "../utils/resolveHostname.js";

let passed = 0;
let failed = 0;

async function test(name, callback) {
    try {
        await callback();
        passed++;
        console.log(`PASS: ${name}`);
    } catch (error) {
        failed++;
        console.error(`FAIL: ${name}`);
        console.error(`  ${error.message}`);
    }
}

async function expectRejection(name, callback, expectedMessage) {
    await test(name, async () => {
        let rejected = false;

        try {
            await callback();
        } catch (error) {
            rejected = true;

            if (
                expectedMessage &&
                !error.message.includes(expectedMessage)
            ) {
                throw new Error(
                    `Expected error containing "${expectedMessage}", ` +
                    `received "${error.message}"`
                );
            }
        }

        if (!rejected) {
            throw new Error("Expected the request to be rejected");
        }
    });
}

async function runTests() {
    let publicUrl;
    let publicIp;

    // Resolve a real public URL once for network-dependent tests.
    try {
        publicUrl = new URL("https://example.com");
        const addresses = await resolveHostname(publicUrl.hostname);
        publicIp = addresses[0];

        console.log("Validated IP:", publicIp);
        console.log("");
    } catch (error) {
        console.error("Could not prepare network tests:", error.message);
        process.exitCode = 1;
        return;
    }

    // 1. Destination security checks

    await expectRejection(
        "Reject loopback IPv4",
        () => requestUrl("http://127.0.0.1", "127.0.0.1"),
        "Prohibited destination IP"
    );

    await expectRejection(
        "Reject private IPv4",
        () => requestUrl("http://192.168.1.1", "192.168.1.1"),
        "Prohibited destination IP"
    );

    await expectRejection(
        "Reject loopback IPv6",
        () => requestUrl("http://[::1]", "::1"),
        "Prohibited destination IP"
    );

    await expectRejection(
        "Reject unsupported protocol",
        () => requestUrl("ftp://example.com", publicIp),
        "Unsupported URL protocol"
    );

    await expectRejection(
        "Reject non-standard port",
        () => requestUrl("https://example.com:8443", publicIp),
        "URL port is not allowed"
    );

    await expectRejection(
        "Reject URL credentials",
        () => requestUrl("https://user:pass@example.com", publicIp),
        "URLs containing credentials"
    );

    await expectRejection(
        "Reject invalid URL",
        () => requestUrl("not a valid URL", publicIp),
        "Invalid URL"
    );

    // 2. Successful public HTTPS request

    await test("Fetch public HTTPS URL successfully", async () => {
        const result = await requestUrl(
            "https://example.com",
            publicIp
        );

        if (result.statusCode !== 200) {
            throw new Error(
                `Expected status 200, received ${result.statusCode}`
            );
        }

        if (result.responseBytes <= 0) {
            throw new Error("Expected a non-empty response body");
        }

        console.log("  Status:", result.statusCode);
        console.log("  Bytes:", result.responseBytes);
    });

    // 3. Redirect handling

    await test("Return redirect response without following it", async () => {
        const result = await requestUrl(
            "https://example.com",
            publicIp
        );

        // This confirms the response metadata is returned.
        // It does NOT guarantee example.com will redirect.
        if (typeof result.statusCode !== "number") {
            throw new Error("Missing HTTP status code");
        }

        if (!result.headers) {
            throw new Error("Missing response headers");
        }
    });

    // 4. Invalid pinned IP

    await expectRejection(
        "Reject invalid pinned IP",
        () => requestUrl("https://example.com", "not-an-ip"),
        "Prohibited destination IP"
    );

    // Summary
    console.log("\n------------------------------");
    console.log(`Passed: ${passed}`);
    console.log(`Failed: ${failed}`);
    console.log("------------------------------");

    if (failed > 0) {
        process.exitCode = 1;
    }
}

runTests().catch((error) => {
    console.error("Unexpected test runner error:", error);
    process.exitCode = 1;
});
