
import http from "node:http";

function testLocalRequest(path, timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
        const req = http.get(
            {
                hostname: "127.0.0.1",
                port: 4317,
                path,
                timeout: timeoutMs
            },
            (res) => {
                let responseBytes = 0;
                let settled = false;

                res.on("data", (chunk) => {
                    responseBytes += chunk.length;

                    if (responseBytes > 64 * 1024) {
                        settled = true;
                        req.destroy(
                            new Error("Response body exceeds size limit")
                        );
                    }
                });

                res.on("end", () => {
                    if (settled) return;

                    settled = true;
                    resolve({
                        statusCode: res.statusCode,
                        headers: res.headers,
                        responseBytes
                    });
                });

                res.on("error", (error) => {
                    if (!settled) {
                        settled = true;
                        reject(error);
                    }
                });
            }
        );

        req.on("timeout", () => {
            req.destroy(new Error("Request timed out"));
        });

        req.on("error", reject);
    });
}

async function runTests() {
    // Redirect behavior
    const redirect = await testLocalRequest("/redirect");

    if (
        redirect.statusCode === 302 &&
        redirect.headers.location === "/"
    ) {
        console.log("PASS: Redirect returned without following it");
    } else {
        console.error("FAIL: Unexpected redirect response");
    }

    // Response-size limit
    try {
        await testLocalRequest("/large");
        console.error("FAIL: Oversized response was accepted");
    } catch (error) {
        if (error.message.includes("Response body exceeds size limit")) {
            console.log("PASS: Oversized response rejected");
        } else {
            console.error("FAIL: Large response test:", error.message);
        }
    }

    // Timeout
    try {
        await testLocalRequest("/slow", 1000);
        console.error("FAIL: Slow response was accepted");
    } catch (error) {
        if (error.message.includes("Request timed out")) {
            console.log("PASS: Slow response timed out");
        } else {
            console.error("FAIL: Timeout test:", error.message);
        }
    }
}

runTests().catch((error) => {
    console.error("Test runner failed:", error);
    process.exitCode = 1;
});
