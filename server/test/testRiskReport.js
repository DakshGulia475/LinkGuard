
import test from "node:test";
import assert from "node:assert/strict";

import analyzeUrl from "../utils/analyzeUrl.js";
import generateRiskReport from "../utils/generateRiskReport.js";
import { checkUrl } from "../controllers/urlController.js";

function completedInspection(overrides = {}) {
    return {
        originalUrl: "https://example.com/",
        finalUrl: "https://example.com/",
        statusCode: 200,
        redirectCount: 0,
        redirectChain: [],
        contentType: "text/html",
        responseBytes: 128,
        inspectionStatus: "completed",
        securityHeaders: {
            strictTransportSecurity: true,
            contentSecurityPolicy: true,
            xContentTypeOptions: true,
            xFrameOptions: true,
            referrerPolicy: true,
            permissionsPolicy: true
        },
        ...overrides
    };
}

function mockResponse() {
    return {
        statusCode: null,
        body: null,
        status(code) {
            this.statusCode = code;
            return this;
        },
        json(body) {
            this.body = body;
            return this;
        }
    };
}

test("report has the complete schema and honest reputation limitations", () => {
    const report = generateRiskReport(
        "https://example.com/",
        completedInspection()
    );

    assert.equal(report.url, "https://example.com/");
    assert.deepEqual(
        Object.keys(report.assessment),
        ["riskLevel", "status", "summary", "reasons"]
    );
    assert.deepEqual(
        Object.keys(report.signals),
        ["url", "redirects", "http"]
    );

    for (const group of Object.values(report.signals)) {
        for (const signal of group) {
            assert.equal(typeof signal.id, "string");
            assert.ok(["info", "warning", "high"].includes(signal.severity));
            assert.equal(typeof signal.message, "string");
            assert.equal(typeof signal.evidence, "object");
        }
    }

    assert.equal(report.reputation.status, "not_checked");
    assert.equal(report.reputation.provider, null);
    assert.ok(report.limitations.length > 0);
    assert.equal(report.assessment.riskLevel, "low");
    assert.equal(report.assessment.status, "completed");
});

test("HTTPS is informational and HTTP produces a warning", () => {
    const httpsSignals = analyzeUrl("https://example.com/");
    const httpSignals = analyzeUrl("http://example.com/");

    assert.ok(
        httpsSignals.some(
            s => s.id === "url.https" && s.severity === "info"
        )
    );
    assert.ok(
        httpSignals.some(
            s => s.id === "url.http" && s.severity === "warning"
        )
    );
});

test("IP literal hostname produces a warning", () => {
    const signals = analyzeUrl("http://8.8.8.8/");

    assert.ok(signals.some(s => s.id === "url.ip_host"));
});

test("embedded URL credentials produce a warning without exposing them", () => {
    const report = generateRiskReport(
        "https://user:secret@example.com/",
        null,
        Object.assign(new Error("URL credentials are not allowed"), {
            code: "URL_INVALID"
        })
    );

    const signal = report.signals.url.find(
        s => s.id === "url.userinfo"
    );

    assert.ok(signal);
    assert.equal(signal.severity, "warning");
    assert.equal(signal.evidence.usernamePresent, true);
    assert.equal(signal.evidence.passwordPresent, true);
    assert.equal(report.assessment.riskLevel, "inconclusive");
    assert.equal(report.assessment.status, "inconclusive");
    assert.ok(!JSON.stringify(report).includes("secret"));
});

test("punycode hostname produces a warning without claiming maliciousness", () => {
    const signals = analyzeUrl("https://xn--example-ova.com/");

    assert.ok(
        signals.some(
            s => s.id === "url.punycode" && s.severity === "warning"
        )
    );
});

test("normal hostname does not trigger IP or punycode signals", () => {
    const signals = analyzeUrl("https://example.com/");

    assert.ok(!signals.some(s => s.id === "url.ip_host"));
    assert.ok(!signals.some(s => s.id === "url.punycode"));
});

test("cross-host redirects produce a warning", () => {
    const inspection = completedInspection({
        originalUrl: "https://example.com/",
        finalUrl: "https://other.example/",
        redirectCount: 1,
        redirectChain: [{
            statusCode: 302,
            from: "https://example.com/",
            to: "https://other.example/"
        }]
    });

    const signals = analyzeUrl(inspection.originalUrl, inspection);

    assert.ok(signals.some(s => s.id === "redirect.cross_host"));
});

test("multiple redirects are reported when there are more than one", () => {
    const inspection = completedInspection({
        redirectCount: 2,
        redirectChain: [
            {
                statusCode: 301,
                from: "https://example.com/",
                to: "https://example.com/a"
            },
            {
                statusCode: 302,
                from: "https://example.com/a",
                to: "https://example.com/b"
            }
        ]
    });

    assert.ok(
        analyzeUrl(inspection.originalUrl, inspection)
            .some(s => s.id === "redirect.multiple")
    );
});

test("blocked private redirect is a high-severity event, not proof of maliciousness", () => {
    const error = Object.assign(
        new Error("Prohibited destination IP address"),
        {
            code: "DESTINATION_PROHIBITED",
            blockedUrl: "http://127.0.0.1/admin",
            partialInspection: {
                originalUrl: "https://example.com/",
                finalUrl: "http://127.0.0.1/admin",
                redirectCount: 1,
                redirectChain: [{
                    statusCode: 302,
                    from: "https://example.com/",
                    to: "http://127.0.0.1/admin"
                }]
            }
        }
    );

    const report = generateRiskReport(
        error.partialInspection.originalUrl,
        null,
        error
    );

    assert.equal(report.assessment.riskLevel, "inconclusive");
    assert.equal(report.assessment.status, "partial");

    assert.ok(
        report.signals.redirects.some(
            s => s.id === "redirect.private_target" &&
                s.severity === "high"
        )
    );

    assert.equal(report.inspection.redirectCount, 1);

    assert.ok(
        report.assessment.reasons.some(
            reason =>
                reason.includes(
                    "blocked a redirect to a prohibited destination"
                )
        )
    );
});

test("prohibited hostname redirect is reported even when blocked URL is not an IP literal", () => {
    const error = Object.assign(
        new Error("Prohibited destination IP address"),
        {
            code: "DESTINATION_PROHIBITED",
            blockedUrl: "http://internal.example/admin",
            partialInspection: {
                originalUrl: "https://example.com/",
                finalUrl: "http://internal.example/admin",
                redirectCount: 1,
                redirectChain: [{
                    statusCode: 302,
                    from: "https://example.com/",
                    to: "http://internal.example/admin"
                }]
            }
        }
    );

    const report = generateRiskReport(
        error.partialInspection.originalUrl,
        null,
        error
    );

    assert.ok(
        report.signals.redirects.some(
            s => s.id === "redirect.private_target" &&
                s.severity === "high"
        )
    );

    assert.equal(report.assessment.riskLevel, "inconclusive");
    assert.equal(report.assessment.status, "partial");
});

test("404 is a completed inspection, not an inspection failure", () => {
    const inspection = completedInspection({ statusCode: 404 });
    const report = generateRiskReport(
        inspection.originalUrl,
        inspection
    );

    assert.equal(report.inspection.httpStatus, 404);
    assert.equal(report.assessment.status, "completed");
    assert.ok(report.signals.http.some(s => s.id === "http.status"));
});

test("response metadata and missing hardening headers are represented", () => {
    const inspection = completedInspection({
        contentType: "text/html",
        responseBytes: 2048,
        securityHeaders: {
            strictTransportSecurity: false,
            contentSecurityPolicy: false,
            xContentTypeOptions: false,
            xFrameOptions: false,
            referrerPolicy: false,
            permissionsPolicy: false
        }
    });

    const report = generateRiskReport(
        inspection.originalUrl,
        inspection
    );

    assert.equal(report.inspection.contentType, "text/html");
    assert.equal(report.inspection.responseBytes, 2048);

    assert.ok(
        report.signals.http.some(
            s => s.id === "http.missing_security_header" &&
                s.severity === "warning"
        )
    );

    assert.equal(report.assessment.riskLevel, "medium");
});

test("warning signals yield medium risk; HTTPS alone does not prove safety", () => {
    const inspection = completedInspection({
        securityHeaders: {
            strictTransportSecurity: true,
            contentSecurityPolicy: true,
            xContentTypeOptions: true,
            xFrameOptions: true,
            referrerPolicy: true,
            permissionsPolicy: true
        }
    });

    const report = generateRiskReport(
        "http://example.com/",
        {
            ...inspection,
            originalUrl: "http://example.com/"
        }
    );

    assert.equal(report.assessment.riskLevel, "medium");
    assert.equal(report.assessment.status, "completed");
});

test("embedded credentials alone do not establish high risk", () => {
    const report = generateRiskReport(
        "http://user:pass@example.com/",
        null,
        Object.assign(new Error("Inspection failed"), {
            code: "REQUEST_FAILED"
        })
    );

    assert.equal(report.assessment.riskLevel, "inconclusive");
    assert.equal(report.assessment.status, "inconclusive");
});

test("inspection failure without high-concern evidence is inconclusive", () => {
    const error = Object.assign(new Error("Timed out"), {
        code: "INSPECTION_TIMEOUT"
    });

    const report = generateRiskReport(
        "https://example.com/",
        null,
        error
    );

    assert.equal(report.assessment.riskLevel, "inconclusive");
    assert.equal(report.assessment.status, "inconclusive");

    assert.ok(
        report.signals.http.some(s => s.id === "inspection.failed")
    );
});

test("partial inspection does not turn an ordinary warning into a maliciousness claim", () => {
    const error = Object.assign(new Error("Request failed"), {
        code: "REQUEST_FAILED",
        partialInspection: {
            originalUrl: "http://example.com/",
            finalUrl: "http://example.com/",
            redirectCount: 0,
            redirectChain: []
        }
    });

    const report = generateRiskReport(
        "http://example.com/",
        null,
        error
    );

    assert.equal(report.assessment.riskLevel, "inconclusive");
    assert.equal(report.assessment.status, "partial");
    assert.match(
        report.assessment.summary,
        /insufficient evidence/i
    );
});

test("invalid URL is rejected before inspection", async () => {
    let inspectionCalls = 0;
    const response = mockResponse();

    await checkUrl(
        { body: { url: "file:///etc/passwd" } },
        response,
        {
            inspectUrl: async () => {
                inspectionCalls++;
                return completedInspection();
            }
        }
    );

    assert.equal(response.statusCode, 400);
    assert.equal(response.body.valid, false);
    assert.equal(inspectionCalls, 0);
});

test("controller returns the generated report for a completed inspection", async () => {
    const response = mockResponse();

    await checkUrl(
        { body: { url: "https://example.com/" } },
        response,
        {
            inspectUrl: async () => completedInspection()
        }
    );

    assert.equal(response.statusCode, 200);
    assert.equal(response.body.assessment.riskLevel, "low");
    assert.equal(response.body.reputation.status, "not_checked");
});

test("controller returns an inconclusive report when inspection fails", async () => {
    const response = mockResponse();

    await checkUrl(
        { body: { url: "https://example.com/" } },
        response,
        {
            inspectUrl: async () => {
                throw Object.assign(
                    new Error("DNS failure"),
                    { code: "DNS_FAILED" }
                );
            }
        }
    );

    assert.equal(response.statusCode, 200);
    assert.equal(response.body.assessment.riskLevel, "inconclusive");
    assert.equal(response.body.assessment.status, "inconclusive");
});
