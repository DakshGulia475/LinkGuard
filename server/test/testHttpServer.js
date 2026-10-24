
import http from "node:http";

const PORT = 4317;

const server = http.createServer((req, res) => {
    if (req.url === "/redirect") {
        res.writeHead(302, {
            Location: "/",
            "Content-Type": "text/plain"
        });
        res.end("Redirect response");
        return;
    }

    if (req.url === "/large") {
        res.writeHead(200, {
            "Content-Type": "text/plain"
        });

        // Send 128 KiB, exceeding LinkGuard's 64 KiB limit.
        res.end("A".repeat(128 * 1024));
        return;
    }

    if (req.url === "/slow") {
        setTimeout(() => {
            if (!res.destroyed) {
                res.writeHead(200, {
                    "Content-Type": "text/plain"
                });
                res.end("Delayed response");
            }
        }, 8000);

        return;
    }

    res.writeHead(200, {
        "Content-Type": "text/plain"
    });
    res.end("Local test server is running");
});

server.listen(PORT, "127.0.0.1", () => {
    console.log(`Test server listening on http://127.0.0.1:${PORT}`);
});
