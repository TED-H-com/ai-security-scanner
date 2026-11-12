// Synthetic voucher service; all identities and balances are dummy data.
export async function redeem(store, principal, label) {
  if (!principal || typeof principal.account !== "string") {
    throw new Error("An account is required");
  }
  const balance = await store.readBalance(principal.account);
  if (balance < 1) throw new Error("Insufficient credits");
  await store.writeBalance(principal.account, balance - 1);
  return store.issueVoucher(principal.account, label);
}
