
import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

import requestUrl, { requestUrlCore } from "../utils/requestUrl.js";
import inspectUrl from "../utils/inspectUrl.js";

let server;
let baseUrl;

before(async () => {
    server = http.createServer((req, res) => {
        if (req.url === "/redirect") {
            res.writeHead(302, { Location: "/status/200" });
            res.end("Redirect");
            return;
        }

        if (req.url === "/large") {
            res.writeHead(200, {
                "Content-Type": "text/plain",
                "Content-Length": String(128 * 1024)
            });
            res.end("A".repeat(128 * 1024));
            return;
        }

        if (req.url === "/slow") {
            setTimeout(() => {
                if (!res.destroyed) {
                    res.writeHead(200, { "Content-Type": "text/plain" });
                    res.end("Too late");
                }
            }, 500);
            return;
        }

        if (req.url === "/status/404") {
            res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
            res.end("Not found");
            return;
        }

        if (req.url === "/status/500") {
            res.writeHead(500, { "Content-Type": "text/plain" });
            res.end("Server error");
            return;
        }

        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end("<html>fixture</html>");
    });

    await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", resolve);
    });

    const { port } = server.address();
    baseUrl = `http://linkguard.test:${port}`;
});

after(async () => {
    if (!server) return;

    await new Promise(resolve => server.close(resolve));
});

function fakeResolver(hostname) {
    // Public documentation IP used only with mocked requests; no network call.
    if (hostname === "example.com" || hostname === "redirect.example") {
        return Promise.resolve(["8.8.8.8"]);
    }

    if (hostname === "127.0.0.1" || hostname === "localhost") {
        return Promise.resolve(["127.0.0.1"]);
    }

    return Promise.resolve(["8.8.8.8"]);
}

function fakeResponse(statusCode, headers = {}, responseBytes = 100) {
    return { statusCode, headers, responseBytes };
}

test("production request wrapper rejects private IP destinations", () => {
    assert.throws(
        () => requestUrl("http://example.com", "127.0.0.1"),
        { code: "DESTINATION_PROHIBITED" }
    );

    assert.throws(
        () => requestUrl("http://example.com", "10.0.0.1"),
        { code: "DESTINATION_PROHIBITED" }
    );
});

test("production request wrapper rejects invalid protocols, ports and credentials", () => {
    assert.throws(
        () => requestUrl("ftp://example.com", "8.8.8.8"),
        { code: "URL_INVALID" }
    );

    assert.throws(
        () => requestUrl("http://example.com:8080", "8.8.8.8"),
        { code: "URL_INVALID" }
    );

    assert.throws(
        () => requestUrl("http://user:pass@example.com", "8.8.8.8"),
        { code: "URL_INVALID" }
    );

    assert.throws(
        () => requestUrl("not a URL", "8.8.8.8"),
        { code: "URL_INVALID" }
    );
});

test("transport core pins the request to the supplied IP and reads response metadata", async () => {
    const result = await requestUrlCore(`${baseUrl}/status/404`, "127.0.0.1");

    assert.equal(result.statusCode, 404);
    assert.match(result.headers["content-type"], /text\/plain/);
    assert.ok(result.responseBytes > 0);
});

test("transport core returns server error statuses as HTTP responses", async () => {
    const result = await requestUrlCore(`${baseUrl}/status/500`, "127.0.0.1");
    assert.equal(result.statusCode, 500);
});

test("transport core does not follow redirects automatically", async () => {
    const result = await requestUrlCore(`${baseUrl}/redirect`, "127.0.0.1");

    assert.equal(result.statusCode, 302);
    assert.equal(result.headers.location, "/status/200");
});

test("transport core rejects oversized responses", async () => {
    await assert.rejects(
        requestUrlCore(`${baseUrl}/large`, "127.0.0.1"),
        { code: "RESPONSE_TOO_LARGE" }
    );
});

test("transport core times out a slow response", async () => {
    await assert.rejects(
        requestUrlCore(`${baseUrl}/slow`, "127.0.0.1", { timeoutMs: 50 }),
        { code: "REQUEST_TIMEOUT" }
    );
});

test("transport core rejects a URL IP that differs from the pinned IP", async () => {
    await assert.rejects(
        requestUrlCore("http://127.0.0.1/", "8.8.8.8"),
        { code: "DESTINATION_PROHIBITED" }
    );
});

test("TLS handshake failure is rejected", async () => {
    // The fixture speaks plain HTTP, not TLS. An HTTPS request must fail.
    const { port } = server.address();

    await assert.rejects(
        requestUrlCore(`https://linkguard.test:${port}/`, "127.0.0.1", {
            timeoutMs: 1000
        }),
        { code: "REQUEST_FAILED" }
    );
});

test("inspection follows a redirect and returns a structured result", async () => {
    const calls = [];

    const result = await inspectUrl("https://example.com/start", {
        resolveHostname: fakeResolver,
        requestUrl: async (url, ip) => {
            calls.push({ url, ip });

            if (url === "https://example.com/start") {
                return fakeResponse(302, { location: "/final" });
            }

            return fakeResponse(200, {
                "content-type": "text/html; charset=utf-8"
            }, 240);
        }
    });

    assert.equal(calls.length, 2);
    assert.equal(result.originalUrl, "https://example.com/start");
    assert.equal(result.finalUrl, "https://example.com/final");
    assert.equal(result.statusCode, 200);
    assert.equal(result.redirectCount, 1);
    assert.equal(result.redirectChain[0].statusCode, 302);
    assert.equal(result.contentType, "text/html");
    assert.equal(result.responseBytes, 240);
    assert.equal(result.inspectionStatus, "completed");
});

test("inspection rejects a redirect to a private IP before requesting it", async () => {
    let calls = 0;

    await assert.rejects(
        inspectUrl("https://example.com/start", {
            resolveHostname: fakeResolver,
            requestUrl: async () => {
                calls += 1;
                return fakeResponse(302, { location: "http://127.0.0.1/admin" });
            }
        }),
        { code: "DESTINATION_PROHIBITED" }
    );

    // Only the first public destination was requested.
    assert.equal(calls, 1);
});

test("inspection detects redirect loops", async () => {
    await assert.rejects(
        inspectUrl("https://example.com/a", {
            resolveHostname: fakeResolver,
            requestUrl: async () =>
                fakeResponse(302, { location: "/a" })
        }),
        { code: "REDIRECT_LOOP" }
    );
});

test("inspection rejects more than five redirects", async () => {
    let count = 0;

    await assert.rejects(
        inspectUrl("https://example.com/0", {
            resolveHostname: fakeResolver,
            requestUrl: async () => {
                count += 1;
                return fakeResponse(302, {
                    location: `/${count}`
                });
            }
        }),
        { code: "REDIRECT_LIMIT" }
    );

    assert.equal(count, 6);
});

test("inspection accepts a 404 as a completed HTTP inspection", async () => {
    const result = await inspectUrl("https://example.com/missing", {
        resolveHostname: fakeResolver,
        requestUrl: async () =>
            fakeResponse(404, { "content-type": "text/plain; charset=utf-8" }, 9)
    });

    assert.equal(result.statusCode, 404);
    assert.equal(result.inspectionStatus, "completed");
    assert.equal(result.contentType, "text/plain");
});

test("inspection rejects invalid input before resolving DNS", async () => {
    let resolverCalls = 0;

    await assert.rejects(
        inspectUrl("file:///etc/passwd", {
            resolveHostname: async () => {
                resolverCalls += 1;
                return ["8.8.8.8"];
            },
            requestUrl: async () => fakeResponse(200)
        }),
        { code: "URL_INVALID" }
    );

    assert.equal(resolverCalls, 0);
});
