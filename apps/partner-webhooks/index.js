// Fan-out service: forwards ledger events to partner endpoints and keeps a
// local spool of anything that failed, for replay.

const fetch = require("node-fetch");
const mkdirp = require("mkdirp");
const minimist = require("minimist");
const path = require("path");

const argv = minimist(process.argv.slice(2), { default: { spool: "./spool", concurrency: 4 } });

async function forward(partner, event) {
  const response = await fetch(partner.url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(event),
  });

  if (!response.ok) {
    mkdirp.sync(path.join(argv.spool, partner.id));
    throw new Error(`partner ${partner.id} returned ${response.status}`);
  }
  return response.status;
}

module.exports = { forward };
