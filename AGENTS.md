# Keycloak User IDP Redirector Plugin

Keycloak 26 authenticator plugin that owns the username-only login form and auto-redirects users to their linked federated IDP. Checks federation links before Home IDP Discovery does domain matching, while preserving the standard login UX.

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
   - **Hint found** → resolve user, check federation, redirect or `attempted()`
   - **No hint** → render username-only form via `challenge()`
2. `action()` receives form submission
   - **Username submitted** → resolve user, check federation links
     - Federation found (single IDP) → redirect
     - Federation found (multiple IDPs) → show selection form
     - No federation or unknown user → `attempted()` with `ATTEMPTED_USERNAME` set
   - **IDP alias submitted** → validate against session allowlist, redirect

## Integration: Home IDP Discovery

Home IDP Discovery (`de.sventorben:keycloak-home-idp-discovery`) is a **third-party** authenticator. It reads the `ATTEMPTED_USERNAME` auth note (set by this plugin) and does domain-based matching. It never calls `context.setUser()` on no-match.

**CRITICAL:** This plugin MUST run BEFORE Home IDP Discovery. It owns the username form and sets `ATTEMPTED_USERNAME` for downstream consumers.

**Priority hierarchy:** User-specific federation link > Domain pattern > Password

**Recommended flow:**
```
Browser Flow
├─ Cookie (ALTERNATIVE)
├─ User IDP Redirector (ALTERNATIVE)   ← username form, federation check
├─ Home IDP Discovery (ALTERNATIVE)    ← bypassLoginPage=true, domain match
├─ Forms Subflow (ALTERNATIVE)
│  └─ Username+Password Form (REQUIRED) ← full form, username pre-filled
```

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
