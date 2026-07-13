# Keycloak User IDP Redirector

Automatically redirects users to their linked Identity Provider after username entry.

## Problem Solved

When users enter their username in Keycloak, this plugin:
- Checks if user has linked federated identity
- Redirects to that IDP instead of showing password prompt
- No IDP selection button needed
- Works even when users share same email domain but need different IDPs

## Build

```bash
mvn clean package
```

Output: `target/user-idp-redirector-1.0.0.jar`

## Deploy

### Option 1: Copy to providers directory
```bash
cp target/user-idp-redirector-1.0.0.jar /opt/keycloak/providers/
/opt/keycloak/bin/kc.sh build
/opt/keycloak/bin/kc.sh start
```

### Option 2: Podman volume mount (development)
```bash
podman run -d \
  -v $(pwd)/target/user-idp-redirector-1.0.0.jar:/opt/keycloak/providers/user-idp-redirector-1.0.0.jar:z \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.0.0 \
  start-dev
```

## Configure

1. Login to Keycloak Admin Console
2. Navigate to: **Authentication** → **Flows**
3. Copy "Browser" flow → name it "Browser with IDP Redirect"
4. Find "Username Password Form" execution
5. Click **Actions** → **Add step**
6. Select **User IDP Redirector**
7. Set requirement to **REQUIRED**
8. Move it **AFTER** "Username Password Form"
9. Navigate to: **Realm Settings** → **General** → **Endpoints**
10. Set **Browser Flow** to "Browser with IDP Redirect"

## Flow Order

Correct execution order:
1. Cookie (ALTERNATIVE)
2. Username Password Form (ALTERNATIVE)
3. **User IDP Redirector (REQUIRED)** ← insert here
4. OTP Form (etc.)

## How It Works

1. User enters username
2. Plugin checks `user.getFederatedIdentities()`
3. If linked IDP found → redirect to IDP
4. If no linked IDP → continue to password prompt

## Requirements

- Keycloak 26.x
- Java 17+
- Maven 3.6+
- User must have federated identity linked in Keycloak
