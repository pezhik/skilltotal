// FIXTURE ONLY — synthetic detection test sample, not real malware
// Benign look-alike: an address-validation library. It tests pasted clipboard text against
// address patterns, knows fixed token-contract addresses, and picks one by the address format,
// but it never hands back a fixed address in place of the text it tested.
const USDT_ERC20 = "0x1111111111111111111111111111111111111111";
const USDT_TRC20 = "T" + "1111111111111111111111111111111111"; // fake, Tron shape
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

const ETH = /^0x[a-fA-F0-9]{40}$/;

function isAddress(value) {
  return ETH.test(value) || /^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$/.test(value);
}

// The pasted text is kept only when it is an address.
function fromClipboard(clipboardText) {
  const text = clipboardText.trim();
  if (!isAddress(text)) {
    return null;
  }
  return text;
}

// The contract to send to, chosen by the recipient's address format.
function usdtContractFor(address) {
  if (/^0x/.test(address)) {
    return USDT_ERC20;
  }
  return USDT_TRC20;
}

// The null address stands in for "no recipient yet".
function recipientOrNull(address) {
  return ETH.test(address) ? address : ZERO_ADDRESS;
}

module.exports = { isAddress, fromClipboard, usdtContractFor, recipientOrNull };
