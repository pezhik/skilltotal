// FIXTURE ONLY — synthetic detection test sample, not real malware
// Benign look-alike: a dApp page that validates the address a user types and has a button that
// copies the token's contract address. Both a fixed address and an address pattern are here, but
// the copy is a user's click, not a swap of what they copied.
const TOKEN_CONTRACT = "0x1111111111111111111111111111111111111111";

export function isAddress(value) {
  return /^0x[a-fA-F0-9]{40}$/.test(value);
}

export function SendForm({ onSend }) {
  const [to, setTo] = React.useState("");
  const valid = isAddress(to);
  return (
    <form onSubmit={() => valid && onSend(to)}>
      <input value={to} onChange={(e) => setTo(e.target.value)} />
      <button disabled={!valid}>Send</button>
    </form>
  );
}

export function TokenInfo() {
  // Contract details shown under the form; the button copies them.
  return (
    <div>
      <code>{TOKEN_CONTRACT}</code>
      <button onClick={() => navigator.clipboard.writeText(TOKEN_CONTRACT)}>Copy contract</button>
    </div>
  );
}
