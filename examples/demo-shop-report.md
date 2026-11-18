# DPDP Ready scan: demo-shop

Scanned 9 files on 2026-11-18 with DPDP Ready 0.2.0.

**Findings:** 3 high · 0 medium · 4 low · 7 info  
**Personal data types found:** 10 (3 sensitive)  
**Third-party services:** 7

> This is an automated engineering scan, not a legal opinion or a compliance certificate. Results show what the tool could detect in the files and pages it read. Decisions about DPDP compliance must be reviewed by a qualified professional.

## Personal data inventory

| Data type | Sensitive | Locations | Files | Examples |
|---|---|---|---|---|
| Email address | No | 3 | 3 | `prisma/schema.prisma:3`, `src/app/checkout/page.tsx:5`, `src/lib/auth.ts:3` |
| Phone number | No | 4 | 4 | `prisma/schema.prisma:4`, `src/app/checkout/page.tsx:6`, `src/lib/auth.ts:3` |
| Aadhaar number | **Yes** | 2 | 2 | `prisma/schema.prisma:27`, `src/lib/support.ts:4` |
| PAN | **Yes** | 1 | 1 | `prisma/schema.prisma:26` |
| Date of birth / age | No | 1 | 1 | `prisma/schema.prisma:7` |
| Gender | No | 1 | 1 | `prisma/schema.prisma:8` |
| Person's name | No | 3 | 2 | `prisma/schema.prisma:5`, `prisma/schema.prisma:6`, `src/app/checkout/page.tsx:4` |
| Postal address | No | 4 | 2 | `prisma/schema.prisma:18`, `prisma/schema.prisma:20`, `src/app/checkout/page.tsx:7` |
| Credentials (password / OTP) | No | 2 | 2 | `prisma/schema.prisma:9`, `src/lib/sms.ts:5` |
| Financial data (card, bank, UPI, income) | **Yes** | 1 | 1 | `prisma/schema.prisma:33` |

## Third-party services that may receive personal data

| Service | Category | Typically receives | Detected in |
|---|---|---|---|
| Meta (Facebook) Pixel / SDK | Advertising | Browsing events, device data, hashed emails/phones if advanced matching is on | `https://connect.facebook.net/en_US/fbevents.js` (src/app/layout.tsx) |
| Google Analytics / Tag Manager | Analytics | IP address, device and browser identifiers, pages viewed, events | `https://www.googletagmanager.com/gtag/js?id=G-DEMO000000` (src/app/layout.tsx) |
| Mixpanel | Analytics | User IDs, profile properties, events, IP-based location | `mixpanel-browser` (package.json) |
| Sentry | Error monitoring | Error reports, which may include user IDs, IP addresses and request data | `@sentry/nextjs` (package.json) |
| Amazon SES | Messaging (SMS/email) | Email addresses, email content | `@aws-sdk/client-ses` (package.json) |
| Twilio | Messaging (SMS/email) | Phone numbers, message content | `twilio` (package.json) |
| Razorpay | Payments | Name, email, phone, payment details | `razorpay` (package.json) |

## Findings

### High (3)

#### Personal data may be written to logs (Email address, Credentials (password / OTP), Phone number)

- **Where:** `src/lib/auth.ts:5` · **Confidence:** medium
- **Evidence:** Log call references: Email address, Credentials (password / OTP), Phone number
- **Code:** `console.log('Login requested for ${email}, sending otp ${otp} to ${phone}');`
- **Why it matters:** Logs are copied to many places (log tools, backups, developer laptops), are rarely access-controlled like the database, and are often kept longer than the data itself.
- **What to do:** Log a user ID or a masked value instead (e.g. a***@gmail.com, ******1234). Never log passwords, OTPs, card or Aadhaar numbers.
- **Relevant provisions (for review):** DPDP Act s.8(5): reasonable security safeguards to prevent a personal data breach; DPDP Rules 2025, Rule 6: security safeguards (e.g. encryption, masking, access control, logs); DPDP Act s.8(7): erase personal data when the purpose is served or consent is withdrawn

#### Hardcoded password or secret in source code

- **Where:** `src/lib/payments.ts:4` · **Confidence:** medium
- **Evidence:** Xk9m******** (20 chars)
- **Code:** `const RAZORPAY_KEY_SECRET = "Xk9m******** (20 chars)";`
- **Why it matters:** Anyone with access to the repository (or a leaked copy) can use this credential to reach systems that may hold personal data.
- **What to do:** Revoke and rotate this credential now, then load it from an environment variable or secret manager. Removing it from the latest commit is not enough: it stays in git history.
- **Relevant provisions (for review):** DPDP Act s.8(5): reasonable security safeguards to prevent a personal data breach; DPDP Rules 2025, Rule 6: security safeguards (e.g. encryption, masking, access control, logs); DPDP Act s.8(6) and Rules 2025, Rule 7: personal data breach intimation

#### Personal data may be written to logs (Aadhaar number)

- **Where:** `src/lib/support.ts:5` · **Confidence:** medium
- **Evidence:** Log call references: Aadhaar number
- **Code:** `console.info("KYC submitted", user.id, user.aadhaarNumber);`
- **Why it matters:** Logs are copied to many places (log tools, backups, developer laptops), are rarely access-controlled like the database, and are often kept longer than the data itself.
- **What to do:** Log a user ID or a masked value instead (e.g. a***@gmail.com, ******1234). Never log passwords, OTPs, card or Aadhaar numbers.
- **Relevant provisions (for review):** DPDP Act s.8(5): reasonable security safeguards to prevent a personal data breach; DPDP Rules 2025, Rule 6: security safeguards (e.g. encryption, masking, access control, logs); DPDP Act s.8(7): erase personal data when the purpose is served or consent is withdrawn

### Low (4)

#### Sensitive personal data in code: PAN

- **Where:** `prisma/schema.prisma:26` · **Confidence:** medium
- **Evidence:** 1 field definition(s) in 1 file(s), e.g. prisma/schema.prisma:26
- **Code:** `panNumber     String`
- **Why it matters:** Higher-risk personal data increases the impact of a breach and usually needs stronger safeguards and a clear purpose.
- **What to do:** Collect PAN only where needed (e.g. tax, KYC); mask it in UIs and logs. Document why it is collected and how long it is kept.
- **Relevant provisions (for review):** DPDP Act s.6(1) and s.7: process only the personal data necessary for the specified purpose; DPDP Act s.8(5): reasonable security safeguards to prevent a personal data breach; DPDP Act s.8(7): erase personal data when the purpose is served or consent is withdrawn

#### Sensitive personal data in code: Aadhaar number

- **Where:** `prisma/schema.prisma:27` · **Confidence:** medium
- **Evidence:** 2 field definition(s) in 2 file(s), e.g. prisma/schema.prisma:27
- **Code:** `aadhaarNumber String`
- **Why it matters:** Higher-risk personal data increases the impact of a breach and usually needs stronger safeguards and a clear purpose.
- **What to do:** Store Aadhaar only if a law allows you to; prefer masked or tokenised references (e.g. last 4 digits). Document why it is collected and how long it is kept.
- **Relevant provisions (for review):** DPDP Act s.6(1) and s.7: process only the personal data necessary for the specified purpose; DPDP Act s.8(5): reasonable security safeguards to prevent a personal data breach; DPDP Act s.8(7): erase personal data when the purpose is served or consent is withdrawn

#### Sensitive personal data in code: Financial data (card, bank, UPI, income)

- **Where:** `prisma/schema.prisma:33` · **Confidence:** medium
- **Evidence:** 1 field definition(s) in 1 file(s), e.g. prisma/schema.prisma:33
- **Code:** `upiId         String?`
- **Why it matters:** Higher-risk personal data increases the impact of a breach and usually needs stronger safeguards and a clear purpose.
- **What to do:** Never store card numbers or CVV yourself; use your payment gateway's tokens. Encrypt bank and UPI details. Document why it is collected and how long it is kept.
- **Relevant provisions (for review):** DPDP Act s.6(1) and s.7: process only the personal data necessary for the specified purpose; DPDP Act s.8(5): reasonable security safeguards to prevent a personal data breach; DPDP Act s.8(7): erase personal data when the purpose is served or consent is withdrawn

#### Personal data written into source code (email address)

- **Where:** `src/lib/support.ts:2` · **Confidence:** low
- **Evidence:** r***@demoshop-fictional.in
- **Code:** `… r***@demoshop-fictional.in …`
- **Why it matters:** Personal data in source code is copied to every clone, fork and backup, and cannot be erased on request.
- **What to do:** Move real people's data out of the code (to the database or config). Use fake values such as name@example.com in code and tests.
- **Relevant provisions (for review):** DPDP Act s.8(7): erase personal data when the purpose is served or consent is withdrawn; DPDP Act s.8(5): reasonable security safeguards to prevent a personal data breach

### Info (7)

#### Third-party service receives data: Razorpay (Payments)

- **Where:** `package.json:8` · **Confidence:** high
- **Evidence:** razorpay (package.json:8)
- **Code:** `razorpay`
- **Why it matters:** Razorpay typically receives: Name, email, phone, payment details. Users must be told about it, and you need a contract (DPA) with the vendor.
- **What to do:** List this vendor in your data inventory and privacy notice, sign or accept its data processing agreement, check where it stores data, and send it only the fields it needs.
- **Relevant provisions (for review):** DPDP Act s.8(2): a Data Processor may process data only under a valid contract; DPDP Act s.5 and Rules 2025, Rule 3: notice with an itemised description of personal data and purposes; DPDP Act s.16: transfer of personal data outside India (subject to Government restrictions)

#### Third-party service receives data: Sentry (Error monitoring)

- **Where:** `package.json:9` · **Confidence:** high
- **Evidence:** @sentry/nextjs (package.json:9)
- **Code:** `@sentry/nextjs`
- **Why it matters:** Sentry typically receives: Error reports, which may include user IDs, IP addresses and request data. Users must be told about it, and you need a contract (DPA) with the vendor.
- **What to do:** List this vendor in your data inventory and privacy notice, sign or accept its data processing agreement, check where it stores data, and send it only the fields it needs.
- **Relevant provisions (for review):** DPDP Act s.8(2): a Data Processor may process data only under a valid contract; DPDP Act s.5 and Rules 2025, Rule 3: notice with an itemised description of personal data and purposes; DPDP Act s.16: transfer of personal data outside India (subject to Government restrictions)

#### Third-party service receives data: Mixpanel (Analytics)

- **Where:** `package.json:10` · **Confidence:** high
- **Evidence:** mixpanel-browser (package.json:10)
- **Code:** `mixpanel-browser`
- **Why it matters:** Mixpanel typically receives: User IDs, profile properties, events, IP-based location. Users must be told about it, and you need a contract (DPA) with the vendor.
- **What to do:** List this vendor in your data inventory and privacy notice, sign or accept its data processing agreement, check where it stores data, and send it only the fields it needs.
- **Relevant provisions (for review):** DPDP Act s.8(2): a Data Processor may process data only under a valid contract; DPDP Act s.5 and Rules 2025, Rule 3: notice with an itemised description of personal data and purposes; DPDP Act s.16: transfer of personal data outside India (subject to Government restrictions)

#### Third-party service receives data: Amazon SES (Messaging (SMS/email))

- **Where:** `package.json:11` · **Confidence:** high
- **Evidence:** @aws-sdk/client-ses (package.json:11)
- **Code:** `@aws-sdk/client-ses`
- **Why it matters:** Amazon SES typically receives: Email addresses, email content. Users must be told about it, and you need a contract (DPA) with the vendor.
- **What to do:** List this vendor in your data inventory and privacy notice, sign or accept its data processing agreement, check where it stores data, and send it only the fields it needs.
- **Relevant provisions (for review):** DPDP Act s.8(2): a Data Processor may process data only under a valid contract; DPDP Act s.5 and Rules 2025, Rule 3: notice with an itemised description of personal data and purposes; DPDP Act s.16: transfer of personal data outside India (subject to Government restrictions)

#### Third-party service receives data: Twilio (Messaging (SMS/email))

- **Where:** `package.json:12` · **Confidence:** high
- **Evidence:** twilio (package.json:12)
- **Code:** `twilio`
- **Why it matters:** Twilio typically receives: Phone numbers, message content. Users must be told about it, and you need a contract (DPA) with the vendor.
- **What to do:** List this vendor in your data inventory and privacy notice, sign or accept its data processing agreement, check where it stores data, and send it only the fields it needs.
- **Relevant provisions (for review):** DPDP Act s.8(2): a Data Processor may process data only under a valid contract; DPDP Act s.5 and Rules 2025, Rule 3: notice with an itemised description of personal data and purposes; DPDP Act s.16: transfer of personal data outside India (subject to Government restrictions)

#### Third-party service receives data: Google Analytics / Tag Manager (Analytics)

- **Where:** `src/app/layout.tsx:5` · **Confidence:** medium
- **Evidence:** https://www.googletagmanager.com/gtag/js?id=G-DEMO000000 (src/app/layout.tsx:5)
- **Code:** `https://www.googletagmanager.com/gtag/js?id=G-DEMO000000`
- **Why it matters:** Google Analytics / Tag Manager typically receives: IP address, device and browser identifiers, pages viewed, events. Users must be told about it, and you need a contract (DPA) with the vendor.
- **What to do:** List this vendor in your data inventory and privacy notice, sign or accept its data processing agreement, check where it stores data, and send it only the fields it needs.
- **Relevant provisions (for review):** DPDP Act s.8(2): a Data Processor may process data only under a valid contract; DPDP Act s.5 and Rules 2025, Rule 3: notice with an itemised description of personal data and purposes; DPDP Act s.16: transfer of personal data outside India (subject to Government restrictions)

#### Third-party service receives data: Meta (Facebook) Pixel / SDK (Advertising)

- **Where:** `src/app/layout.tsx:8` · **Confidence:** medium
- **Evidence:** https://connect.facebook.net/en_US/fbevents.js (src/app/layout.tsx:8)
- **Code:** `https://connect.facebook.net/en_US/fbevents.js`
- **Why it matters:** Meta (Facebook) Pixel / SDK typically receives: Browsing events, device data, hashed emails/phones if advanced matching is on. Users must be told about it, and you need a contract (DPA) with the vendor.
- **What to do:** List this vendor in your data inventory and privacy notice, sign or accept its data processing agreement, check where it stores data, and send it only the fields it needs.
- **Relevant provisions (for review):** DPDP Act s.8(2): a Data Processor may process data only under a valid contract; DPDP Act s.5 and Rules 2025, Rule 3: notice with an itemised description of personal data and purposes; DPDP Act s.16: transfer of personal data outside India (subject to Government restrictions)

## Limitations

- Static analysis of source files only: databases, logs, cloud configuration, backups and vendor contracts were not inspected.
- Personal data is detected from field names and code patterns; fields with unusual names may be missed, and some matches may not be personal data.
- Secret detection uses high-precision patterns; use a dedicated secret scanner (e.g. gitleaks) for full coverage, including git history.
- Vendors are detected from dependency manifests and URLs in code; services called without an SDK or URL in the code may be missed.
- This is an automated engineering scan, not a legal opinion or a compliance certificate. Results show what the tool could detect in the files and pages it read. Decisions about DPDP compliance must be reviewed by a qualified professional.
