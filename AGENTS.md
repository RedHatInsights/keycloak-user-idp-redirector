# Keycloak User IDP Redirector Plugin

## Overview
Keycloak 26 authenticator plugin that auto-redirects users to their linked federated IDP after username entry. Skips password prompt when user has federation link.

## Architecture

### Plugin Components
- `UserIdpRedirectAuthenticator` - checks user's federated identities, redirects to IDP if found
- `UserIdpRedirectAuthenticatorFactory` - SPI registration, display metadata

### Execution Context
- **Requires user object** - `requiresUser() = true` means this runs AFTER username resolution
- **Position in flow** - must come AFTER "Username Password Form" or equivalent
- **Not standalone** - depends on prior step identifying user

### Integration Points

#### Home IDP Discovery Plugin
**CRITICAL:** This plugin MUST run BEFORE Home IDP Discovery to avoid routing conflicts.

**Recommended execution order:**
```
1. Username entry (user identified)
2. THIS PLUGIN (user → linked IDP) - checks federation links first
3. Home IDP Discovery (domain → IDP mapping) - fallback for domain patterns
4. Password/OTP (final fallback)
```

**Why this order matters:**
- User `bob@example.com` has federation link to IDP-B
- Domain pattern `@example.com` maps to IDP-A via Home IDP Discovery
- **Wrong order:** Home IDP Discovery catches `@example.com` first → sends bob to IDP-A (incorrect)
- **Right order:** This plugin catches bob's federation link first → sends to IDP-B (correct)

**Priority hierarchy:** User-specific federation link > Domain pattern > Password

#### Browser Flow Configuration
**RECOMMENDED:**
```
Browser Flow
├─ Cookie (ALTERNATIVE)
├─ Browser Forms (ALTERNATIVE)
│  ├─ Username Form (REQUIRED)
│  ├─ User IDP Redirector (REQUIRED)     ← THIS PLUGIN - run first
│  ├─ Home IDP Discovery (REQUIRED)      ← fallback for domain patterns
│  └─ Password Form (REQUIRED)           ← final fallback
└─ OTP (CONDITIONAL)
```

**INCORRECT (causes routing conflicts):**
```
Browser Flow
├─ Cookie (ALTERNATIVE)
├─ Browser Forms (ALTERNATIVE)
│  ├─ Username Form (REQUIRED)
│  ├─ Home IDP Discovery (REQUIRED)      ← catches domain first (wrong!)
│  ├─ User IDP Redirector (REQUIRED)     ← never runs if domain matched
│  └─ Password Form (REQUIRED)
└─ OTP (CONDITIONAL)
```

## Build

### Requirements
- Java 17+
- Maven 3.6+
- Keycloak 26.x dependencies (provided scope)

### Commands
```bash
mvn clean package          # build
mvn clean test            # unit tests
mvn clean verify          # unit + integration tests
```

Output: `target/user-idp-redirector-1.0.0.jar`

## Deploy

### Local Development (podman)
```bash
make run-dev
# or
podman run -d \
  -v $(pwd)/target/user-idp-redirector-1.0.0.jar:/opt/keycloak/providers/user-idp-redirector-1.0.0.jar:z \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.0.0 \
  start-dev
```

### Production
```bash
cp target/user-idp-redirector-1.0.0.jar /opt/keycloak/providers/
/opt/keycloak/bin/kc.sh build
/opt/keycloak/bin/kc.sh start
```

## Configuration

### Enable in Realm
1. Authentication → Flows
2. Copy "Browser" flow
3. Add "User IDP Redirector" step AFTER username/password form
4. Set to REQUIRED
5. Realm Settings → Browser Flow → select modified flow

### Testing Configuration
Create test users:
- User with single IDP link → should redirect
- User with multiple IDP links → redirects to first
- User with no IDP links → continues to password

## Testing

### Unit Tests
Mock Keycloak context, verify redirect logic:
- User with federation → 302 redirect to IDP
- User without federation → `attempted()` call
- No user object → `attempted()` call

### Integration Tests
Real Keycloak instance via Testcontainers:
- End-to-end flow with federated user
- Verify no interference with Home IDP Discovery
- Edge case: user with domain match + different federation

Run: `make test` or `make test-integration`

## Edge Cases

### Multiple Federations
Takes first from `identities.iterator().next()` - non-deterministic if >1 link. Consider:
- Config option to select by priority
- UI to set preferred IDP
- Redirect to account linking page

### Stale Federation Links
Plugin doesn't validate IDP still exists/enabled. If IDP deleted, redirect fails. Consider:
- Catch redirect errors
- Validate IDP enabled before redirect
- Log failures

### Mixed Auth Flows
If user linked to external IDP but tries direct auth, this forces IDP redirect. May frustrate users wanting local password. Consider:
- Query param to skip redirector
- Remember last auth method
- Allow ALTERNATIVE instead of REQUIRED

## Troubleshooting

### User Not Redirecting
- Check user has federation: Admin Console → Users → <user> → Federated Identity
- Verify flow order: redirector AFTER username form
- Check logs: look for "User IDP Redirector" execution

### Redirect Loop
- Home IDP Discovery + this plugin both redirecting
- Check both targeting same IDP or different
- Verify Home IDP Discovery doesn't pre-redirect

### 404 on Redirect
- IDP alias mismatch
- IDP disabled/deleted
- Check URL construction at line 38-46 of authenticator

## Development

### Adding Configuration
Currently no config options. To add:
1. Set `isConfigurable() = true` in factory
2. Add `ProviderConfigProperty` entries
3. Read config in `authenticate()` via `context.getAuthenticatorConfig()`

### Supporting Multiple IDPs
Replace `identities.iterator().next()` with:
- Priority lookup from user attributes
- Config-defined preference order
- UI selection if >1 available
