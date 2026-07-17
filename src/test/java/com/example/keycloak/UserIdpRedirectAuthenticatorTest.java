package com.example.keycloak;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
import java.util.stream.Stream;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
class UserIdpRedirectAuthenticatorTest {

    @Mock private AuthenticationFlowContext context;
    @Mock private KeycloakSession session;
    @Mock private RealmModel realm;
    @Mock private UserModel user;
    @Mock private UserProvider userProvider;
    @Mock private AuthenticationSessionModel authSession;
    @Mock private RootAuthenticationSessionModel rootAuthSession;
    @Mock private ClientModel client;
    @Mock private UriInfo uriInfo;
    @Mock private LoginFormsProvider loginForms;
    @Mock private HttpRequest httpRequest;

    private UserIdpRedirectAuthenticator authenticator;

    @BeforeEach
    void setup() {
        authenticator = new UserIdpRedirectAuthenticator();
    }

    private void setupBasicMocks() {
        lenient().when(context.getSession()).thenReturn(session);
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(session.users()).thenReturn(userProvider);
    }

    private void setupFullMocks() {
        setupBasicMocks();
        lenient().when(context.getAuthenticationSession()).thenReturn(authSession);
        lenient().when(authSession.getClient()).thenReturn(client);
        lenient().when(authSession.getParentSession()).thenReturn(rootAuthSession);
        lenient().when(authSession.getTabId()).thenReturn("test-tab-id");
        lenient().when(client.getClientId()).thenReturn("test-client");
        lenient().when(rootAuthSession.getId()).thenReturn("test-session-id");
        lenient().when(realm.getName()).thenReturn("test-realm");
        lenient().when(context.getUriInfo()).thenReturn(uriInfo);
        lenient().when(uriInfo.getBaseUri()).thenReturn(URI.create("http://localhost:8080/"));
        lenient().when(context.getActionUrl(any())).thenReturn(URI.create("http://localhost:8080/action"));
        lenient().when(context.generateAccessCode()).thenReturn("test-code");

        UriBuilder uriBuilder = mock(UriBuilder.class, RETURNS_SELF);
        lenient().when(uriInfo.getBaseUriBuilder()).thenReturn(uriBuilder);
        lenient().when(uriBuilder.build()).thenReturn(URI.create("http://localhost:8080/realms/test-realm/broker/github/login?client_id=test-client&tab_id=test-tab-id"));
    }

    private void setupFormMocks() {
        lenient().when(context.form()).thenReturn(loginForms);
        lenient().when(loginForms.setAttribute(anyString(), any())).thenReturn(loginForms);
        lenient().when(loginForms.setError(anyString())).thenReturn(loginForms);
        lenient().when(loginForms.createForm(anyString())).thenReturn(Response.ok().build());
    }

    private IdentityProviderModel mockIdp(String alias, String displayName, boolean enabled) {
        IdentityProviderModel idp = mock(IdentityProviderModel.class);
        lenient().when(idp.getAlias()).thenReturn(alias);
        lenient().when(idp.getDisplayName()).thenReturn(displayName);
        lenient().when(idp.isEnabled()).thenReturn(enabled);
        return idp;
    }

    // ---- authenticate() tests ----

    @Test
    void testAuthenticateWithNoUser() {
        when(context.getUser()).thenReturn(null);

        authenticator.authenticate(context);

        verify(context).attempted();
        verify(context, never()).forceChallenge(any());
        verify(context, never()).challenge(any());
    }

    @Test
    void testAuthenticateWithNoFederatedIdentities() {
        setupBasicMocks();
        when(context.getUser()).thenReturn(user);
        when(userProvider.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.empty());

        authenticator.authenticate(context);

        verify(context).attempted();
        verify(context, never()).forceChallenge(any());
        verify(context, never()).challenge(any());
    }

    @Test
    void testAuthenticateWithSingleFederatedIdentity() {
        setupFullMocks();
        when(context.getUser()).thenReturn(user);

        FederatedIdentityModel identity = mock(FederatedIdentityModel.class);
        when(identity.getIdentityProvider()).thenReturn("github");
        IdentityProviderModel idpModel = mockIdp("github", "GitHub", true);
        when(realm.getIdentityProviderByAlias("github")).thenReturn(idpModel);
        when(userProvider.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.of(identity));

        authenticator.authenticate(context);

        verify(context).forceChallenge(any(Response.class));
        verify(context, never()).attempted();
        verify(context, never()).challenge(any());
    }

    @Test
    void testAuthenticateWithMultipleFederatedIdentitiesShowsSelectionForm() {
        setupFullMocks();
        setupFormMocks();
        when(context.getUser()).thenReturn(user);

        FederatedIdentityModel identity1 = mock(FederatedIdentityModel.class);
        when(identity1.getIdentityProvider()).thenReturn("github");
        FederatedIdentityModel identity2 = mock(FederatedIdentityModel.class);
        when(identity2.getIdentityProvider()).thenReturn("google");

        IdentityProviderModel githubIdp = mockIdp("github", "GitHub", true);
        IdentityProviderModel googleIdp = mockIdp("google", "Google", true);
        when(realm.getIdentityProviderByAlias("github")).thenReturn(githubIdp);
        when(realm.getIdentityProviderByAlias("google")).thenReturn(googleIdp);

        when(userProvider.getFederatedIdentitiesStream(realm, user))
            .thenReturn(Stream.of(identity1, identity2));

        authenticator.authenticate(context);

        verify(context).challenge(any(Response.class));
        verify(context, never()).forceChallenge(any());
        verify(context, never()).attempted();
        verify(authSession).setAuthNote(eq("idp_redirector_aliases"), anyString());
        verify(loginForms).setAttribute(eq("idps"), any());
        verify(loginForms).createForm("select-idp.ftl");
    }

    @Test
    void testAuthenticateWithDisabledIdp() {
        setupBasicMocks();
        when(context.getUser()).thenReturn(user);

        FederatedIdentityModel identity = mock(FederatedIdentityModel.class);
        when(identity.getIdentityProvider()).thenReturn("github");
        IdentityProviderModel idpModel = mockIdp("github", "GitHub", false);
        when(realm.getIdentityProviderByAlias("github")).thenReturn(idpModel);
        when(userProvider.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.of(identity));

        authenticator.authenticate(context);

        verify(context).attempted();
        verify(context, never()).forceChallenge(any());
    }

    @Test
    void testAuthenticateWithNonexistentIdp() {
        setupBasicMocks();
        when(context.getUser()).thenReturn(user);

        FederatedIdentityModel identity = mock(FederatedIdentityModel.class);
        when(identity.getIdentityProvider()).thenReturn("deleted-idp");
        when(realm.getIdentityProviderByAlias("deleted-idp")).thenReturn(null);
        when(userProvider.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.of(identity));

        authenticator.authenticate(context);

        verify(context).attempted();
        verify(context, never()).forceChallenge(any());
    }

    // ---- action() tests ----

    @Test
    void testActionWithValidAlias() {
        setupFullMocks();
        when(context.getUser()).thenReturn(user);

        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        params.putSingle("idpAlias", "github");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(params);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(authSession.getAuthNote("idp_redirector_aliases")).thenReturn("github,google");

        IdentityProviderModel idpModel = mockIdp("github", "GitHub", true);
        when(realm.getIdentityProviderByAlias("github")).thenReturn(idpModel);

        authenticator.action(context);

        verify(context).forceChallenge(any(Response.class));
        verify(context, never()).attempted();
    }

    @Test
    void testActionWithAliasNotInAllowlist() {
        setupFormMocks();

        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        params.putSingle("idpAlias", "evil-idp");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(params);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(authSession.getAuthNote("idp_redirector_aliases")).thenReturn("github,google");

        authenticator.action(context);

        verify(context).challenge(any(Response.class));
        verify(loginForms).setError("invalidIdpSelection");
        verify(context, never()).forceChallenge(any());
        verify(context, never()).attempted();
    }

    @Test
    void testActionWithMissingAliasParam() {
        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(params);

        authenticator.action(context);

        verify(context).attempted();
        verify(context, never()).forceChallenge(any());
    }

    @Test
    void testActionWithNoSessionNote() {
        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        params.putSingle("idpAlias", "github");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(params);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(authSession.getAuthNote("idp_redirector_aliases")).thenReturn(null);

        authenticator.action(context);

        verify(context).attempted();
        verify(context, never()).forceChallenge(any());
    }

    // ---- lifecycle tests ----

    @Test
    void testRequiresUser() {
        assert authenticator.requiresUser();
    }

    @Test
    void testConfiguredFor() {
        assert authenticator.configuredFor(session, realm, user);
    }

    @Test
    void testSetRequiredActions() {
        authenticator.setRequiredActions(session, realm, user);
    }

    @Test
    void testClose() {
        authenticator.close();
    }
}
