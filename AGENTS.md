# Keycloak User IDP Redirector Plugin

Keycloak 26 authenticator plugin that owns the username-only login form and auto-redirects users to their IDP. Checks federation links first, then falls back to domain-based matching (using `home.idp.discovery.domains` IDP config), replacing the need for Home IDP Discovery in the flow.

## Architecture

### Plugin Components
- `UserIdpRedirectAuthenticator` — renders username form, checks federation links, redirects to IDP
- `UserIdpRedirectAuthenticatorFactory` — SPI registration, display metadata

### Execution Context
- **Renders a username-only form** — uses `context.form().createLoginUsername()` (Keycloak's built-in template) when no username hint exists
- **Supports bypass** — when `ATTEMPTED_USERNAME` auth note or `login_hint` client note is already set (e.g. from OIDC client), skips the form and checks federation directly
- **Does not require a pre-resolved user** — `requiresUser() = false`. Resolves the `UserModel` itself via `session.users().getUserByUsername()`
- **Sets `ATTEMPTED_USERNAME`** — on form submission, stores the username as an auth note so downstream authenticators (Home IDP Discovery, password form) can read it
- **Handles two form submissions** — `action()` dispatches between username submission (`username` param) and IDP selection (`idpAlias` param for multi-IDP users)

### Flow Logic
1. `authenticate()` checks for existing username hint (`ATTEMPTED_USERNAME` or `login_hint`)
   - **Hint found** → resolve user, check federation, check domain, redirect or `attempted()`
   - **No hint** → render username-only form via `challenge()`
2. `action()` receives form submission
   - **Username submitted** → resolve user, then priority chain:
     1. Federation link found (single IDP) → redirect
     2. Federation link found (multiple IDPs) → show selection form
     3. No federation, domain match found → redirect (reads `home.idp.discovery.domains` from IDP config)
     4. Unknown user, domain extracted from username → redirect
     5. No match → `attempted()` with `ATTEMPTED_USERNAME` set
   - **IDP alias submitted** → validate against session allowlist, redirect

### Domain Matching
When no federation link exists, falls back to domain-based IDP discovery:
- Reads the user's `email` attribute (or extracts domain from username for unknown users)
- Extracts domain part (after `@`)
- Matches against `home.idp.discovery.domains` config on each enabled IDP (delimited by `##`)
- Supports per-attribute override key: `home.idp.discovery.domains.email`
- Supports subdomain matching via `home.idp.discovery.matchSubdomains` IDP config
- Compatible with Home IDP Discovery's IDP configuration — same config keys, same matching semantics

## Integration Notes

This plugin replaces Home IDP Discovery (`de.sventorben:keycloak-home-idp-discovery`) in the authentication flow. It reads the same `home.idp.discovery.domains` IDP config, so no IDP reconfiguration is needed when migrating.

**Priority hierarchy:** User-specific federation link > Domain pattern > Password

**Recommended flow:**
```
Browser Flow
├─ Cookie (ALTERNATIVE)
├─ User IDP Redirector (ALTERNATIVE)   ← username form, federation check, domain fallback
├─ Forms Subflow (ALTERNATIVE)
│  └─ Username+Password Form (REQUIRED) ← full form, username pre-filled
```

Home IDP Discovery should be **removed** from the flow to avoid double username prompts.

## Build
```bash
mvn clean package          # build
mvn clean test             # unit tests
mvn clean verify           # unit + integration tests
```

Output: `target/user-idp-redirector-1.0.0.jar`

## Reference

- `.claude/agents/deploy.md` — local dev (podman) and production deployment
- `.claude/agents/configuration.md` — realm setup and test user creation
- `.claude/agents/testing.md` — unit and integration test strategy
- `.claude/agents/edge-cases.md` — multiple federations, stale links, mixed auth flows
- `.claude/agents/troubleshooting.md` — debugging redirect failures, loops, 404s
- `.claude/agents/development.md` — adding config options, supporting multiple IDPs
