# nuclei-bb-templates

Custom Nuclei templates for bug bounty and security research. Covers IDOR, SSRF, JWT attacks,
WAF bypass detection, secrets exposure, and authentication bypass. Each template targets a
specific vulnerability class with real matcher logic and documented false positive expectations.

---

## Usage

Run all templates against a target:

```
nuclei -t nuclei-bb-templates/ -u https://target.example.com
```

Run a specific category:

```
nuclei -t nuclei-bb-templates/idor/ -u https://target.example.com
nuclei -t nuclei-bb-templates/jwt/ -u https://target.example.com
```

Run with a custom auth token (for IDOR and auth templates that reference `{{token}}`):

```
nuclei -t nuclei-bb-templates/ -u https://target.example.com \
  -var token=eyJhbGciOiJIUzI1NiJ9...
```

Run in verbose mode to see all requests:

```
nuclei -t nuclei-bb-templates/ -u https://target.example.com -v
```

OOB templates (SSRF) require an interactsh server. Nuclei uses its built-in interactsh
integration by default. To use a self-hosted instance:

```
nuclei -t nuclei-bb-templates/ssrf/ -u https://target.example.com \
  -iserver https://your-interactsh-server.com
```

---

## Requirements

- Nuclei v3.0.0 or later
- For OOB detection: outbound internet access or a self-hosted interactsh instance
- For IDOR and auth templates: a valid session token passed via `-var token=...`

---

## Template Inventory

### idor/

**idor-numeric-id-comparison.yaml**
Class: Insecure Direct Object Reference via sequential integer IDs.
Method: Two-request comparison. Fetches resource N, extracts the ID from the response body,
then fetches resource N+1 with the same session. Matches when both return 200, bodies differ,
and both contain an `id` field.
Expected false positive rate: Medium. Fires on public APIs with sequential numeric IDs where
no authorization check exists but all data is intentionally public. Confirm by checking for
user-specific fields (email, account details) in the second response.

**idor-uuid-swap.yaml**
Class: IDOR via UUID-based resource identifiers.
Method: Fetches a known UUID endpoint, extracts a different UUID from the response body (a
related resource link), then accesses that UUID with the original session. Matches when the
second resource returns 200 with different body content.
Expected false positive rate: Medium. UUID obscurity is sometimes intentional. Confirm by
checking whether the second resource belongs to a different user account.

**idor-param-pollution.yaml**
Class: IDOR exploited via HTTP parameter pollution.
Method: Sends duplicate user-scoped parameters (userId, account_id, uid) with conflicting
values. Backend parsers taking different positions than the authorization layer may serve
another account's data.
Expected false positive rate: Low-medium. Requires manual verification that the returned
data belongs to a different account.

### ssrf/

**ssrf-common-params.yaml**
Class: Server-Side Request Forgery via URL-carrying parameters.
Method: Injects an interactsh OOB callback URL into 10 common parameter names (url, callback,
redirect, webhook, endpoint, dest, fetch, proxy, target, load). Detects via DNS or HTTP
interaction on the callback host.
Expected false positive rate: Low. DNS hits on the OOB host confirm outbound requests.
Redirect-only endpoints that do not follow the URL will not trigger.

**ssrf-header-injection.yaml**
Class: SSRF via HTTP headers proxied by backend services.
Method: Injects interactsh URLs into X-Forwarded-Host, X-Forwarded-For, X-Real-IP, Referer,
Origin, and True-Client-IP headers. Also tests a JSON body parameter in a POST to /api/fetch.
Detects via OOB interaction.
Expected false positive rate: Very low. An OOB interaction on these headers means the server
is issuing outbound requests based on client-controlled header values.

**ssrf-redirect-chain.yaml**
Class: SSRF via open redirect chaining to internal metadata endpoints.
Method: Passes internal IP addresses and cloud metadata URLs (AWS IMDSv1, GCP computeMetadata,
Azure) through common redirect parameters. Follows the redirect chain and looks for cloud
metadata field names in the final response body.
Expected false positive rate: Low. Matching on instanceId, ami-id, or computeMetadata in a
response body is a strong signal. Confirm the target is on a cloud provider before reporting.

### jwt/

**jwt-none-algorithm.yaml**
Class: JWT none algorithm acceptance (CVE-2015-9235).
Method: Submits pre-crafted tokens with alg set to "none", "None", "NONE", and "nOnE" with
an empty signature segment to /api/v1/me. Matches on a 200 response containing user-identifying
fields and absence of error messages.
Expected false positive rate: Negligible. A 200 authenticated response to a none-alg token is
a confirmed vulnerability. Verify the response contains actual user data.

**jwt-alg-confusion.yaml**
Class: JWT algorithm confusion (RS256 to HS256 downgrade).
Method: Discovers JWKS endpoints at common locations and confirms the server uses RS256 by
checking for kty, n, and e fields. A positive match provides the public key material needed
for a follow-on manual algorithm confusion test. Does not perform the full attack — that
requires signing a token with the extracted public key as the HS256 secret.
Expected false positive rate: None for the discovery step (JWKS exposure is expected for
RS256 systems). The algorithm confusion confirmation requires manual follow-on testing.

**jwt-weak-secret-probe.yaml**
Class: JWT signed with a weak HMAC secret.
Method: Submits pre-signed tokens using the six most common development secrets (secret,
password, 123456, changeme, jwt_secret, supersecret) to /api/v1/me. Stops on first successful
authentication. Matches on 200 response with user-identifying fields.
Expected false positive rate: None. Any positive match means the application accepts tokens
signed with a known-weak key.

### secrets/

**secrets-http-response-headers.yaml**
Class: Secrets and tokens exposed in HTTP response headers.
Method: Sends baseline requests to /, /api/v1/, and /health and inspects response headers
for patterns matching API keys (X-Api-Key), auth tokens (X-Auth-Token), and internal debug
headers. Also extracts matched values for manual review.
Expected false positive rate: Medium-high. Custom X- headers vary widely. Validate that
matched values are actual secrets and not placeholder strings.

**secrets-js-bundle-api-key.yaml**
Class: Hardcoded API keys and credentials in JavaScript bundles.
Method: Fetches common JS bundle paths and scans body content for known credential patterns:
AWS AKIA keys, Google API keys, Stripe secret keys, Slack tokens, GitHub PATs, SendGrid keys,
and Twilio auth tokens. Also uses a generic pattern for variables named apiKey or secret.
Expected false positive rate: Low for vendor-specific patterns (AKIA is unambiguous).
Medium for the generic variable assignment regex. Stripe publishable keys (pk_) are not
secrets and should be excluded from findings.

**capability-link-unauthenticated.yaml**
Class: Sensitive resource exposure via unauthenticated capability links.
Method: Probes common capability link URL patterns with random tokens and checks whether the
response returns HTTP 200 with body content containing PII field names (email, phone, address).
Expected false positive rate: High for intentionally public share links. Severity applies
only when the returned content contains user-specific sensitive data.

### waf/

**waf-fingerprint-headers.yaml**
Class: WAF vendor identification (informational).
Method: Sends a baseline request and a request with a simple XSS payload, then inspects
response headers and body for vendor-specific markers (Cloudflare cf-ray, Akamai X-Akamai-
Request-ID, Imperva X-Iinfo, AWS x-amzn-requestid, F5 BIGipServer, Sucuri block pages).
Expected false positive rate: None. This is passive fingerprinting. Results are informational
and feed into bypass template selection.

**waf-bypass-path-normalization.yaml**
Class: WAF bypass via path normalization discrepancies.
Method: Sends 12 path variants to /admin using double URL encoding, null byte injection,
self-canceling path traversal, Unicode normalization, case variation, and whitespace tricks.
Matches on 200 responses containing admin-related keywords.
Expected false positive rate: Medium. A baseline blocked request must be confirmed before
treating a 200 response as a bypass. Applications that return 200 for all paths regardless
of WAF blocking will produce false positives.

### auth/

**auth-bypass-jwt-missing.yaml**
Class: Authentication bypass via missing or malformed JWT.
Method: Submits 6 variants of absent or invalid Authorization headers (no header, empty
Bearer, "null", "undefined", ".") to /api/v1/me. Matches on 200 responses containing
user-identifying fields with no login page redirection.
Expected false positive rate: Low. Confirm the endpoint returns user-specific data rather
than a public page.

**auth-capability-link.yaml**
Class: Predictable or leaked capability tokens in authentication flows.
Method: Submits password reset and magic link requests and checks whether the response body
or Location header contains the token directly. Also detects UUID v1 (time-based) tokens
by regex pattern, which are structurally guessable.
Expected false positive rate: Low for token-in-response detection. UUID v1 detection has
medium false positive rate — UUIDs used as non-sensitive identifiers will match.

---

## Notes on Scope and Authorization

These templates are intended for use on targets you own or have explicit written permission
to test. Sending interactsh OOB probes, probing authentication endpoints with crafted tokens,
and testing WAF bypass techniques against unauthorized targets is illegal in most jurisdictions.

IDOR templates require a valid session token. Without one, every IDOR template will test
unauthenticated access only, which is a different finding class.

Templates that use `{{rand_int}}` and `{{randstr}}` generate values at scan time and are
not deterministic across runs. IDOR comparison templates depend on the target having resources
in the tested ID range.
