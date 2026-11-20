# COLONY QR backend foundation

This folder contains the first database migration for the account system.

## Current scope
- User accounts and server-controlled roles
- Hashed session-token storage
- Paid and administrator-granted subscription entitlements
- Administrative audit log

## Important security rules
- Never accept a role, plan entitlement, or payment status from a public registration request.
- Public registration must always create a normal `user` account.
- Passwords must be hashed with a modern password-hashing scheme before storage.
- Session cookies must be Secure, HttpOnly, and SameSite=Lax (or stricter where compatible).
- Store only a hash of the random session token in D1.
- Super Admin access and subscription grants must be checked in the Worker on every privileged request.
- Admin-granted subscriptions are not payments and must never trigger a payment charge.
- Do not store payment-card numbers or security codes.

## Apply the schema
After creating a D1 database in the Cloudflare dashboard, apply `database/schema.sql` using the D1 console or Wrangler. The database binding and Worker deployment will be configured in a later step, after the database exists.
