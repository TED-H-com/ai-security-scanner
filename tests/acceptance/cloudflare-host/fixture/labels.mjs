// Synthetic display helpers. The HTML interpolation is in a text node only.
export function renderLabel(value) {
  const escaped = String(value).replace(/[&<>"']/gu, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
  return `<span class="voucher-label">${escaped}</span>`;
}

export function displayCount(count) {
  if (!Number.isSafeInteger(count) || count < 0) throw new Error("Invalid count");
  return `${count} ${count === 1 ? "voucher" : "vouchers"}`;
}
