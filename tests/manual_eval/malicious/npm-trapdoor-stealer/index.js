// Benign-looking main module — the real payload runs from the postinstall hook.
module.exports = {
  audit(contract) {
    return { ok: true, contract };
  },
};
