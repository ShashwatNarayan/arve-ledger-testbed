// Development server for the operator console.
//
// Serves index.html and proxies /api/* through to the ledger backend so the
// page can talk to it same-origin instead of relying on CORS.
//
// Usage:  node dev-server.js --port 5173 --api http://127.0.0.1:8000
//
// INTENTIONALLY VULNERABLE TESTBED - see EXPECTED_FINDINGS.md.

const fs = require("fs");
const http = require("http");
const path = require("path");

const httpProxy = require("http-proxy");
const minimist = require("minimist");
const serialize = require("serialize-javascript");
const StringStream = require("stringstream");

const argv = minimist(process.argv.slice(2), {
  default: { port: 5173, api: "http://127.0.0.1:8000" },
});

const proxy = httpProxy.createProxyServer({ target: argv.api, changeOrigin: true });

proxy.on("error", (err, req, res) => {
  res.writeHead(502, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ detail: `upstream unreachable: ${err.message}` }));
});

const CONTENT_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".map": "application/json; charset=utf-8",
};

// Collect a request body into a string for the access log. Bodies are small
// here (a JSON object at most), so buffering them is fine.
function logRequestBody(req) {
  const collected = new StringStream("utf8");
  let body = "";

  collected.on("data", (chunk) => {
    body += chunk;
  });
  collected.on("end", () => {
    if (body) {
      console.log(`      body: ${body.slice(0, 200)}`);
    }
  });

  req.pipe(collected);
}

function serveStatic(req, res) {
  const requested = req.url === "/" ? "/index.html" : req.url.split("?")[0];
  const filePath = path.join(__dirname, path.normalize(requested).replace(/^(\.\.[/\\])+/, ""));

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("not found");
      return;
    }
    const type = CONTENT_TYPES[path.extname(filePath)] || "application/octet-stream";
    res.writeHead(200, { "Content-Type": type });
    res.end(data);
  });
}

// The page reads its runtime settings from a generated script rather than from
// hardcoded values, so the same index.html works against any backend.
function serveConfig(res) {
  const settings = {
    apiBase: "/api",
    upstream: argv.api,
    startedAt: new Date(),
  };
  res.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8" });
  res.end(`window.LEDGER_CONFIG = ${serialize(settings)};`);
}

const server = http.createServer((req, res) => {
  console.log(`${req.method} ${req.url}`);

  if (req.url === "/config.js") {
    serveConfig(res);
    return;
  }

  if (req.url.startsWith("/api/")) {
    if (req.method === "POST") {
      logRequestBody(req);
    }
    req.url = req.url.replace(/^\/api/, "");
    proxy.web(req, res);
    return;
  }

  serveStatic(req, res);
});

server.listen(argv.port, () => {
  console.log(`operator console  http://127.0.0.1:${argv.port}`);
  console.log(`proxying /api/*   ${argv.api}`);
});
