package com.example.keycloak;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.Details;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;

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
    static final String ATTEMPTED_USERNAME = AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME;

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String username = getExistingUsername(context);

        if (username != null) {
            handleUsernameBypass(context, username);
            return;
        }

        Response form = context.form().createLoginUsername();
        context.challenge(form);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();

        String idpAlias = params.getFirst("idpAlias");
        if (idpAlias != null && !idpAlias.isEmpty()) {
            handleIdpSelection(context, idpAlias);
            return;
        }

        String username = trimToNull(params.getFirst(AuthenticationManager.FORM_USERNAME));
        if (username == null) {
            Response form = context.form()
                .setError("usernameRequired")
                .createLoginUsername();
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, form);
            return;
        }

        context.getEvent().detail(Details.USERNAME, username);
        context.getAuthenticationSession().setAuthNote(ATTEMPTED_USERNAME, username);

        RealmModel realm = context.getRealm();
        UserModel user = context.getSession().users().getUserByUsername(realm, username);

        if (user == null) {
            log.debugf("Unknown user '%s', passing through", username);
            context.attempted();
            return;
        }

        context.setUser(user);

        List<IdentityProviderModel> validIdps = getEnabledFederatedIdps(context, realm, user);

        if (validIdps.isEmpty()) {
            context.attempted();
            return;
        }

        if (validIdps.size() == 1) {
            redirectToIdp(context, realm, validIdps.get(0).getAlias(), user);
            return;
        }

        showIdpSelectionForm(context, validIdps, user);
    }

    private String getExistingUsername(AuthenticationFlowContext context) {
        String username = trimToNull(context.getAuthenticationSession()
            .getAuthNote(ATTEMPTED_USERNAME));
        if (username != null) return username;

        username = trimToNull(context.getAuthenticationSession()
            .getClientNote("login_hint"));
        return username;
    }

    private void handleUsernameBypass(AuthenticationFlowContext context, String username) {
        RealmModel realm = context.getRealm();
        UserModel user = context.getSession().users().getUserByUsername(realm, username);

        if (user == null) {
            context.getAuthenticationSession().setAuthNote(ATTEMPTED_USERNAME, username);
            context.attempted();
            return;
        }

        context.setUser(user);

        List<IdentityProviderModel> validIdps = getEnabledFederatedIdps(context, realm, user);

        if (validIdps.isEmpty()) {
            context.getAuthenticationSession().setAuthNote(ATTEMPTED_USERNAME, username);
            context.attempted();
            return;
        }

        if (validIdps.size() == 1) {
            redirectToIdp(context, realm, validIdps.get(0).getAlias(), user);
            return;
        }

        showIdpSelectionForm(context, validIdps, user);
    }

    private void handleIdpSelection(AuthenticationFlowContext context, String chosenAlias) {
        String allowedNote = context.getAuthenticationSession().getAuthNote(SESSION_NOTE_ALIASES);
        if (allowedNote == null) {
            log.warn("No IDP allowlist in session — possible replay or direct POST");
            context.attempted();
            return;
        }

        Set<String> allowed = new HashSet<>(Arrays.asList(allowedNote.split(",")));
        if (!allowed.contains(chosenAlias)) {
            log.warnf("Submitted IDP alias '%s' not in session allowlist", chosenAlias);
            RealmModel realm = context.getRealm();
            List<Map<String, String>> idpList = buildIdpListFromAliases(realm, allowed);
            Response form = context.form()
                .setAttribute("idps", idpList)
                .setError("invalidIdpSelection")
                .createForm("select-idp.ftl");
            context.challenge(form);
            return;
        }

        RealmModel realm = context.getRealm();
        IdentityProviderModel idpModel = realm.getIdentityProviderByAlias(chosenAlias);
        if (idpModel == null || !idpModel.isEnabled()) {
            log.warnf("Chosen IDP '%s' no longer valid/enabled", chosenAlias);
            context.attempted();
            return;
        }

        redirectToIdp(context, realm, chosenAlias, context.getUser());
    }

    private List<IdentityProviderModel> getEnabledFederatedIdps(
            AuthenticationFlowContext context, RealmModel realm, UserModel user) {
        return context.getSession()
            .users()
            .getFederatedIdentitiesStream(realm, user)
            .map(FederatedIdentityModel::getIdentityProvider)
            .map(realm::getIdentityProviderByAlias)
            .filter(idp -> idp != null && idp.isEnabled())
            .collect(Collectors.toList());
    }

    private void showIdpSelectionForm(AuthenticationFlowContext context,
            List<IdentityProviderModel> validIdps, UserModel user) {
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

    private List<Map<String, String>> buildIdpListFromAliases(RealmModel realm, Set<String> aliases) {
        List<Map<String, String>> idpList = new ArrayList<>();
        for (String alias : aliases) {
            IdentityProviderModel idp = realm.getIdentityProviderByAlias(alias);
            if (idp != null && idp.isEnabled()) {
                Map<String, String> entry = new HashMap<>();
                entry.put("alias", idp.getAlias());
                String displayName = idp.getDisplayName();
                entry.put("displayName", (displayName != null && !displayName.isEmpty()) ? displayName : idp.getAlias());
                idpList.add(entry);
            }
        }
        return idpList;
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        value = value.trim();
        return value.isEmpty() ? null : value;
    }

    private void redirectToIdp(AuthenticationFlowContext context, RealmModel realm, String idpAlias, UserModel user) {
        log.infof("Redirecting user %s to linked IDP: %s", user.getUsername(), idpAlias);

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
        return false;
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
