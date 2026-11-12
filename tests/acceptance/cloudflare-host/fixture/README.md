# Synthetic voucher desk

This is original synthetic acceptance data, not a deployed application.
It uses only in-memory dummy accounts, with no network, credentials or dependencies.

A caller may exchange its own account's credits for vouchers. Each voucher costs
one credit. Concurrent requests are allowed; total vouchers must never exceed
credits paid. The caller identity is supplied by a trusted embedding application.
The memory store models asynchronous storage. Labels are displayed as HTML text.
