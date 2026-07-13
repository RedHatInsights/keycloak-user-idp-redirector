package com.example.keycloak;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import jakarta.ws.rs.core.Response;
import java.util.Optional;

public class UserIdpRedirectAuthenticator implements Authenticator {

    private static final Logger log = Logger.getLogger(UserIdpRedirectAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();

        if (user == null) {
            log.debug("No user in context, skipping IDP redirect");
            context.attempted();
            return;
        }

        RealmModel realm = context.getRealm();

        log.debugf("Checking federated identities for user %s in realm %s", user.getUsername(), realm.getName());

        // Get user's linked federated identity (if any)
        Optional<FederatedIdentityModel> identity = context.getSession()
            .users()
            .getFederatedIdentitiesStream(realm, user)
            .findFirst();

        if (identity.isPresent()) {
            String idpAlias = identity.get().getIdentityProvider();

            // Validate IDP exists and is enabled before redirect
            IdentityProviderModel idpModel = realm.getIdentityProviderByAlias(idpAlias);
            if (idpModel == null || !idpModel.isEnabled()) {
                log.warnf("User %s linked to invalid/disabled IDP: %s", user.getUsername(), idpAlias);
                context.attempted();
                return;
            }

            log.infof("Redirecting user %s to linked IDP: %s", user.getUsername(), idpAlias);

            // Build broker redirect URL using Keycloak's URI builder (prevents injection)
            String brokerUrl = context.getUriInfo().getBaseUriBuilder()
                .path("realms")
                .path(realm.getName())
                .path("broker")
                .path(idpAlias)
                .path("login")
                .queryParam("client_id", context.getAuthenticationSession().getClient().getClientId())
                .queryParam("tab_id", context.getAuthenticationSession().getTabId())
                .build()
                .toString();

            Response response = Response.status(302)
                .location(java.net.URI.create(brokerUrl))
                .build();

            context.forceChallenge(response);
            return;
        }

        // No linked IDP - continue to password
        log.debugf("User %s has no linked IDP, continuing to password authentication", user.getUsername());
        context.attempted();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.attempted();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No required actions
    }

    @Override
    public void close() {
        // Nothing to close
    }
}
