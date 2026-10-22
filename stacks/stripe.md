# Stripe playbook

Stripe is hard to misuse for card storage, easy to misuse for everything around it: who is allowed to pay what, and when access is granted.

Maps to: PAY-01, PAY-02, PAY-03, PAY-04, PAY-05, PAY-06, PAY-07, PAY-08, PAY-09, SEC-01, API-01, AUT-08, DAT-14, INF-01

## ST-1 Webhooks verify the signature against the raw body
Maps to: PAY-04, API-01
- Look for: `stripe.webhooks.constructEvent(rawBody, signature, endpointSecret)` (Node), `stripe.Webhook.construct_event` (Python).
- Fail when: the handler parses `req.body` as JSON without verifying; or verification is present but a global `express.json()` runs first so the raw bytes are gone (the verification then fails and someone "fixes" it by deleting it).
- Also check: processed event ids are stored so a replay or Stripe retry is a no-op.

## ST-2 The server decides the price
Maps to: AUT-08, DAT-14, PAY-01
- Look for: `amount`, `price`, `currency`, `quantity` or `coupon` taken from the request body when creating a PaymentIntent or Checkout Session. The client must send a product or plan id and the server looks up the price (Stripe Price ids are best).
- Fail when: the amount comes from the client.

## ST-3 Keys: secret stays secret, test stays out of production
Maps to: SEC-01, INF-01
- Look for: `sk_live_`, `sk_test_`, `rk_`, `whsec_` in source, git history, or client bundles. Publishable keys (`pk_`) are meant for the browser. A secret key found anywhere unsafe is a rotate-now finding, never repeat the value.
- Also check: production deploys use live keys only, local and preview use test keys only.

## ST-4 Access is granted from webhook state, not the success page
Maps to: PAY-04, PAY-08
- Look for: entitlement flipped on the `success_url` route or from a `session_id` query parameter. Users can hit that URL without paying, and failed or async payments never reach it. Entitlement should follow `checkout.session.completed` / `invoice.paid` and be revoked on `customer.subscription.deleted` and final `invoice.payment_failed`.

## ST-5 Idempotency on writes
Maps to: PAY-01, PAY-02
- Look for: `idempotencyKey` (Node) / `idempotency_key` (Python) on charge, PaymentIntent, refund and transfer creation; one open attempt per order enforced by a unique constraint.

## ST-6 Lifecycle events are handled
Maps to: PAY-07, PAY-08, PAY-09, PAY-14
- List which events the webhook handles and compare with: `invoice.payment_failed`, `invoice.paid`, `customer.subscription.updated`, `customer.subscription.deleted`, `charge.refunded`, `charge.dispute.created`, `checkout.session.completed`. Missing events mean refunds, dunning and cancellations made in the Stripe dashboard never reach your app.

## ST-7 Card data never touches your server
Maps to: PAY-03
- Look for: your own card number inputs posted to your API; use of `card[number]` server-side; legacy Charges API with raw card details. Stripe Elements, Checkout or Payment Links keep you at the lightest PCI scope.

## ST-8 Tax, invoices and self-service
Maps to: PAY-05, PAY-06, PAY-11, PAY-13
- Look for: Stripe Tax or another tax engine, tax-ID collection for B2B, Customer Portal for plan changes and invoice history. Whether tax registration is correct for your jurisdictions is not visible in code: mark `unknown` and refer to an accountant.

## ST-9 Amounts are integers
Maps to: DAT-14
- Stripe amounts are integers in the smallest currency unit. Look for `Math.round(x * 100)` on floats computed with tax multipliers, and zero-decimal currencies (JPY, KRW) handled as if they had cents.
