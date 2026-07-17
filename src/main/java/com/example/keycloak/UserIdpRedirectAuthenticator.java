package com.example.keycloak;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class UserIdpRedirectAuthenticator implements Authenticator {

    private static final Logger log = Logger.getLogger(UserIdpRedirectAuthenticator.class);
    private static final String SESSION_NOTE_ALIASES = "idp_redirector_aliases";

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

        List<IdentityProviderModel> validIdps = context.getSession()
            .users()
            .getFederatedIdentitiesStream(realm, user)
            .map(FederatedIdentityModel::getIdentityProvider)
            .map(realm::getIdentityProviderByAlias)
            .filter(idp -> idp != null && idp.isEnabled())
            .collect(Collectors.toList());

        if (validIdps.isEmpty()) {
            log.debugf("User %s has no linked IDP, continuing to password authentication", user.getUsername());
            context.attempted();
            return;
        }

        if (validIdps.size() == 1) {
            redirectToIdp(context, realm, validIdps.get(0).getAlias());
            return;
        }

        // Multiple IDPs — store allowlist in session, render selection form
        String aliasesNote = validIdps.stream()
            .map(IdentityProviderModel::getAlias)
            .collect(Collectors.joining(","));
        context.getAuthenticationSession().setAuthNote(SESSION_NOTE_ALIASES, aliasesNote);

        List<Map<String, String>> idpList = new ArrayList<>();
        for (IdentityProviderModel idp : validIdps) {
            Map<String, String> entry = new HashMap<>();
            entry.put("alias", idp.getAlias());
            String displayName = idp.getDisplayName();
            entry.put("displayName", (displayName != null && !displayName.isEmpty()) ? displayName : idp.getAlias());
            idpList.add(entry);
        }

        log.infof("User %s has %d linked IDPs, showing selection form", user.getUsername(), validIdps.size());

        Response form = context.form()
            .setAttribute("idps", idpList)
            .createForm("select-idp.ftl");
        context.challenge(form);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();
        String chosenAlias = params.getFirst("idpAlias");

        if (chosenAlias == null || chosenAlias.isEmpty()) {
            log.warn("IDP selection form submitted without idpAlias param");
            context.attempted();
            return;
        }

        String allowedNote = context.getAuthenticationSession().getAuthNote(SESSION_NOTE_ALIASES);
        if (allowedNote == null) {
            log.warn("No IDP allowlist in session — possible replay or direct POST");
            context.attempted();
            return;
        }

        Set<String> allowed = new HashSet<>(Arrays.asList(allowedNote.split(",")));
        if (!allowed.contains(chosenAlias)) {
            log.warnf("Submitted IDP alias '%s' not in session allowlist", chosenAlias);
            Response form = context.form()
                .setError("invalidIdpSelection")
                .createForm("select-idp.ftl");
        context.forceChallenge(form);
            return;
        }

        RealmModel realm = context.getRealm();
        IdentityProviderModel idpModel = realm.getIdentityProviderByAlias(chosenAlias);
        if (idpModel == null || !idpModel.isEnabled()) {
            log.warnf("Chosen IDP '%s' no longer valid/enabled", chosenAlias);
            context.attempted();
            return;
        }

        redirectToIdp(context, realm, chosenAlias);
    }

    private void redirectToIdp(AuthenticationFlowContext context, RealmModel realm, String idpAlias) {
        log.infof("Redirecting user %s to linked IDP: %s", context.getUser().getUsername(), idpAlias);

        String sessionCode = context.generateAccessCode();
        String brokerUrl = context.getUriInfo().getBaseUriBuilder()
            .path("realms")
            .path(realm.getName())
            .path("broker")
            .path(idpAlias)
            .path("login")
            .queryParam("client_id", context.getAuthenticationSession().getClient().getClientId())
            .queryParam("tab_id", context.getAuthenticationSession().getTabId())
            .queryParam("session_code", sessionCode)
            .build()
            .toString();

        Response response = Response.status(302)
            .location(java.net.URI.create(brokerUrl))
            .build();

        context.forceChallenge(response);
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
    }

    @Override
    public void close() {
    }
}
