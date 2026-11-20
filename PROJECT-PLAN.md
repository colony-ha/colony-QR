# COLONY QR — Project Blueprint

## Product
COLONY QR is a multilingual QR platform for a global audience.

## Brand and design
- Brand: COLONY QR
- Colors: black #151515, gold #C8A45D, ivory #F5F1E8, light blue #A9DDF5 as a subtle accent.
- Languages: Arabic, French, English.
- Responsive: mobile and desktop.

## Product model
### Free QR Generator
- Free access to standard QR types (website, text, Wi-Fi, WhatsApp, phone, email, SMS, contact, location, event, social, and future types).
- QR customization, center logo upload, and PNG/SVG export.

### Digital Pages (paid subscription)
- A shared page builder engine supports many business categories, not restaurants only.
- Customers create an account, choose a business category/template, enter business details, upload product/service photos, descriptions and prices, add location/contact details, publish a public page, and generate a QR code for that page.
- Categories can include restaurants, cafes, fashion, shoes, electronics, beauty, salons, real estate, furniture, flowers, bakeries, gifts, and professional services.
- Owners can edit their page later without changing its QR code.

## Accounts and roles
- Visitor: browse the public site and pricing.
- User: manage their own QR codes, digital pages, products/services, subscription, and account.
- Moderator/Admin: limited support and content-moderation permissions.
- Super Admin: platform owner; can manage users, pages, QR codes, subscriptions, plans, platform settings, and staff roles.
- Super Admin may securely access a user's workspace through audited "Login as User" impersonation. Never expose or retrieve a user's password.
- Privileged actions must be enforced server-side, not only hidden in the UI.
- Keep an audit log of administrative actions and impersonation sessions.

## Subscription and billing
- Standard QR generator remains free.
- Digital Pages require a monthly paid plan.
- Monthly renewal is automatic when supported by the payment provider, with explicit customer consent and an easy cancellation option.
- Cancellation stops future renewal; the page remains active until the paid period ends.
- After expiry, public pages may be paused while customer content remains saved.
- Payment providers must be verified for Algerian merchant eligibility, international customer payments, recurring billing, fees, and payout methods before production integration.
- Keep payment card details with the payment provider; never store raw card details in COLONY QR.

## Planned architecture
- Frontend hosting: Cloudflare Pages.
- Backend/API: Cloudflare Workers.
- Database: Cloudflare D1.
- Image/file storage: Cloudflare R2.
- Authentication, authorization, billing webhooks, and subscription status must be validated server-side.
- Do not integrate a payment gateway or expose admin privileges until authentication and backend security are in place.

## Delivery sequence
1. Public site structure and responsive UI.
2. Authentication and role-based access.
3. User dashboard and QR management.
4. Shared Digital Page Builder and public page rendering.
5. Worker APIs, D1 schema, and R2 uploads.
6. Admin dashboard, impersonation, and audit logs.
7. Subscription plans, recurring billing, cancellation, and payment webhooks.
8. Testing, security review, and launch.

## Current implementation status
- Public landing page is in `index.html`.
- QR generator is preserved in `generator.html`.
- Existing QR generator must be preserved when the public landing page is introduced (move it to a dedicated generator page rather than deleting it).
- Login, accounts, backend deployment, database provisioning, digital-page publishing, admin controls, and billing are not yet production-ready.
- Initial D1 account/session/subscription/audit schema is prepared in `database/schema.sql`.


## Admin-Granted Free Subscriptions

The Super Admin can grant a user a subscription entitlement without collecting payment. This is separate from paid billing and must be clearly labeled.

- Subscription source/type: `paid` or `admin_granted`.
- The Super Admin can grant Free, Pro, or Business plan access to a selected account.
- Admin-granted access can have a chosen duration (for example 1 month, 6 months, 1 year) or no fixed expiry.
- The Super Admin can change or revoke an admin-granted entitlement.
- The user workspace and public page access must follow the granted plan limits and entitlement status.
- Keep an audit log recording who granted, changed, or revoked access, which account and plan were affected, the duration, timestamp, and optional reason.
- Admin-granted access must never create a payment charge or pretend that a payment occurred.
- The account owner should be able to see that the plan was granted by the platform administrator.
- Enforce all grants, expirations, and revocations on the server side; hiding or showing UI controls alone is not authorization.

This capability is an administrative entitlement feature, not a payment gateway feature.
