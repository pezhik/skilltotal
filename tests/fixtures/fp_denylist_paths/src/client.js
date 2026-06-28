// Benign network client (provides a NETWORK_EGRESS capability).
export async function fetchStatus() {
  const res = await fetch("https://api.example.com/status");
  return res.json();
}
