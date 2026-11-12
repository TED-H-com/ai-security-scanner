// Synthetic asynchronous memory storage; no external services.
export function createStore(initialCredits = 1) {
  if (!Number.isSafeInteger(initialCredits) || initialCredits < 0) {
    throw new Error("Invalid initial credit count");
  }
  const balances = new Map([["dummy-owner", initialCredits]]);
  const vouchers = [];
  return {
    async readBalance(account) {
      return balances.get(account) ?? 0;
    },
    async writeBalance(account, balance) {
      balances.set(account, balance);
    },
    async issueVoucher(account, label) {
      const voucher = { id: vouchers.length + 1, account, label: String(label) };
      vouchers.push(voucher);
      return { ...voucher };
    },
    listVouchers(account) {
      return vouchers.filter((voucher) => voucher.account === account)
        .map((voucher) => ({ ...voucher }));
    },
  };
}
