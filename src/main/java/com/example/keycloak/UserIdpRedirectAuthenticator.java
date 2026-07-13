package com.example.keycloak;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;

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
            log.infof("Redirecting user %s to linked IDP: %s", user.getUsername(), idpAlias);

            // Redirect to IDP
            String redirectUrl = context.getActionUrl(context.generateAccessCode()).toString();
            Response response = Response.status(302)
                .location(java.net.URI.create(
                    context.getUriInfo().getBaseUri() +
                    "realms/" + realm.getName() +
                    "/broker/" + idpAlias + "/login?" +
                    "client_id=" + context.getAuthenticationSession().getClient().getClientId() +
                    "&tab_id=" + context.getAuthenticationSession().getTabId() +
                    "&session_code=" + context.getAuthenticationSession().getParentSession().getId()
                ))
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
