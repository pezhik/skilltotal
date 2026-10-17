// FIXTURE ONLY — synthetic detection test sample, not real malware
// Benign look-alike: a wallet screen that copies the user's own address to the clipboard, shows
// it shortened, and falls back to a demo address when no wallet is connected. The demo address is
// shown in place of an invalid value, never in place of an address the user copied.
const DEMO_ADDRESS = "0x1111111111111111111111111111111111111111";

function shorten(address) {
  if (/^0x[a-fA-F0-9]{40}$/.test(address)) {
    return address.slice(0, 6) + "…" + address.slice(-4);
  }
  return address;
}

function shown(address) {
  return /^0x[a-fA-F0-9]{40}$/.test(address) ? address : DEMO_ADDRESS;
}

export function WalletHeader({ account }) {
  const address = shown(account);
  const copy = () => navigator.clipboard.writeText(address);
  return (
    <button onClick={copy} title="Copy address to clipboard">
      {shorten(address)}
    </button>
  );
}
