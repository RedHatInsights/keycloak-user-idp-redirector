package com.example.keycloak;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.events.EventBuilder;
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
    @Mock private EventBuilder eventBuilder;

    private UserIdpRedirectAuthenticator authenticator;

    @BeforeEach
    void setup() {
        authenticator = new UserIdpRedirectAuthenticator();
    }

    private void setupBasicMocks() {
        lenient().when(context.getSession()).thenReturn(session);
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(session.users()).thenReturn(userProvider);
        lenient().when(context.getAuthenticationSession()).thenReturn(authSession);
    }

    private void setupRedirectMocks() {
        setupBasicMocks();
        lenient().when(authSession.getClient()).thenReturn(client);
        lenient().when(authSession.getParentSession()).thenReturn(rootAuthSession);
        lenient().when(authSession.getTabId()).thenReturn("test-tab-id");
        lenient().when(client.getClientId()).thenReturn("test-client");
        lenient().when(rootAuthSession.getId()).thenReturn("test-session-id");
        lenient().when(realm.getName()).thenReturn("test-realm");
        lenient().when(context.getUriInfo()).thenReturn(uriInfo);
        lenient().when(context.generateAccessCode()).thenReturn("test-code");

        UriBuilder uriBuilder = mock(UriBuilder.class, RETURNS_SELF);
        lenient().when(uriInfo.getBaseUriBuilder()).thenReturn(uriBuilder);
        lenient().when(uriBuilder.build()).thenReturn(
            URI.create("http://localhost:8080/realms/test-realm/broker/github/login?client_id=test-client&tab_id=test-tab-id"));
    }

    private void setupFormMocks() {
        lenient().when(context.form()).thenReturn(loginForms);
        lenient().when(loginForms.setAttribute(anyString(), any())).thenReturn(loginForms);
        lenient().when(loginForms.setError(anyString())).thenReturn(loginForms);
        lenient().when(loginForms.createForm(anyString())).thenReturn(Response.ok().build());
        lenient().when(loginForms.createLoginUsername()).thenReturn(Response.ok().build());
    }

    private void setupEventMocks() {
        lenient().when(context.getEvent()).thenReturn(eventBuilder);
        lenient().when(eventBuilder.detail(anyString(), anyString())).thenReturn(eventBuilder);
    }

    private IdentityProviderModel mockIdp(String alias, String displayName, boolean enabled) {
        IdentityProviderModel idp = mock(IdentityProviderModel.class);
        lenient().when(idp.getAlias()).thenReturn(alias);
        lenient().when(idp.getDisplayName()).thenReturn(displayName);
        lenient().when(idp.isEnabled()).thenReturn(enabled);
        return idp;
    }

    // ---- authenticate() tests ----

    @Nested
    class Authenticate {

        @Test
        void noUsernameHint_showsUsernameForm() {
            setupBasicMocks();
            setupFormMocks();
            when(authSession.getAuthNote(anyString())).thenReturn(null);
            when(authSession.getClientNote("login_hint")).thenReturn(null);

            authenticator.authenticate(context);

            verify(loginForms).createLoginUsername();
            verify(context).challenge(any(Response.class));
            verify(context, never()).attempted();
            verify(context, never()).forceChallenge(any());
        }

        @Test
        void attemptedUsername_withFederation_redirectsToIdp() {
            setupRedirectMocks();
            when(authSession.getAuthNote(UserIdpRedirectAuthenticator.ATTEMPTED_USERNAME)).thenReturn("bob");
            when(userProvider.getUserByUsername(realm, "bob")).thenReturn(user);
            when(user.getUsername()).thenReturn("bob");

            FederatedIdentityModel identity = mock(FederatedIdentityModel.class);
            when(identity.getIdentityProvider()).thenReturn("github");
            IdentityProviderModel idp = mockIdp("github", "GitHub", true);
            when(realm.getIdentityProviderByAlias("github")).thenReturn(idp);
            when(userProvider.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.of(identity));

            authenticator.authenticate(context);

            verify(context).forceChallenge(any(Response.class));
            verify(context, never()).attempted();
            verify(context, never()).challenge(any());
        }

        @Test
        void attemptedUsername_noFederation_attempted() {
            setupBasicMocks();
            when(authSession.getAuthNote(UserIdpRedirectAuthenticator.ATTEMPTED_USERNAME)).thenReturn("bob");
            when(userProvider.getUserByUsername(realm, "bob")).thenReturn(user);
            when(userProvider.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.empty());

            authenticator.authenticate(context);

            verify(context).attempted();
            verify(authSession).setAuthNote(UserIdpRedirectAuthenticator.ATTEMPTED_USERNAME, "bob");
            verify(context, never()).forceChallenge(any());
        }

        @Test
        void attemptedUsername_unknownUser_attempted() {
            setupBasicMocks();
            when(authSession.getAuthNote(UserIdpRedirectAuthenticator.ATTEMPTED_USERNAME)).thenReturn("ghost");
            when(userProvider.getUserByUsername(realm, "ghost")).thenReturn(null);

            authenticator.authenticate(context);

            verify(context).attempted();
            verify(authSession).setAuthNote(UserIdpRedirectAuthenticator.ATTEMPTED_USERNAME, "ghost");
        }

        @Test
        void loginHint_withFederation_redirectsToIdp() {
            setupRedirectMocks();
            when(authSession.getAuthNote(UserIdpRedirectAuthenticator.ATTEMPTED_USERNAME)).thenReturn(null);
            when(authSession.getClientNote("login_hint")).thenReturn("bob");
            when(userProvider.getUserByUsername(realm, "bob")).thenReturn(user);
            when(user.getUsername()).thenReturn("bob");

            FederatedIdentityModel identity = mock(FederatedIdentityModel.class);
            when(identity.getIdentityProvider()).thenReturn("github");
            IdentityProviderModel idp = mockIdp("github", "GitHub", true);
            when(realm.getIdentityProviderByAlias("github")).thenReturn(idp);
            when(userProvider.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.of(identity));

            authenticator.authenticate(context);

            verify(context).forceChallenge(any(Response.class));
            verify(context, never()).attempted();
        }

        @Test
        void loginHint_noFederation_attempted() {
            setupBasicMocks();
            when(authSession.getAuthNote(UserIdpRedirectAuthenticator.ATTEMPTED_USERNAME)).thenReturn(null);
            when(authSession.getClientNote("login_hint")).thenReturn("bob");
            when(userProvider.getUserByUsername(realm, "bob")).thenReturn(user);
            when(userProvider.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.empty());

            authenticator.authenticate(context);

            verify(context).attempted();
        }

        @Test
        void bypass_multipleIdps_showsSelectionForm() {
            setupBasicMocks();
            setupFormMocks();
            when(authSession.getAuthNote(UserIdpRedirectAuthenticator.ATTEMPTED_USERNAME)).thenReturn("bob");
            when(userProvider.getUserByUsername(realm, "bob")).thenReturn(user);
            when(user.getUsername()).thenReturn("bob");

            FederatedIdentityModel id1 = mock(FederatedIdentityModel.class);
            when(id1.getIdentityProvider()).thenReturn("github");
            FederatedIdentityModel id2 = mock(FederatedIdentityModel.class);
            when(id2.getIdentityProvider()).thenReturn("google");

            IdentityProviderModel githubIdp = mockIdp("github", "GitHub", true);
            IdentityProviderModel googleIdp = mockIdp("google", "Google", true);
            when(realm.getIdentityProviderByAlias("github")).thenReturn(githubIdp);
            when(realm.getIdentityProviderByAlias("google")).thenReturn(googleIdp);
            when(userProvider.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.of(id1, id2));

            authenticator.authenticate(context);

            verify(context).challenge(any(Response.class));
            verify(loginForms).setAttribute(eq("idps"), any());
            verify(loginForms).createForm("select-idp.ftl");
            verify(authSession).setAuthNote(eq("idp_redirector_aliases"), anyString());
        }
    }

    // ---- action() tests ----

    @Nested
    class Action {

        @Test
        void usernameSubmit_withFederation_redirectsToIdp() {
            setupRedirectMocks();
            setupEventMocks();
            MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
            params.putSingle("username", "bob");
            when(context.getHttpRequest()).thenReturn(httpRequest);
            when(httpRequest.getDecodedFormParameters()).thenReturn(params);
            when(userProvider.getUserByUsername(realm, "bob")).thenReturn(user);
            when(user.getUsername()).thenReturn("bob");

            FederatedIdentityModel identity = mock(FederatedIdentityModel.class);
            when(identity.getIdentityProvider()).thenReturn("github");
            IdentityProviderModel idp = mockIdp("github", "GitHub", true);
            when(realm.getIdentityProviderByAlias("github")).thenReturn(idp);
            when(userProvider.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.of(identity));

            authenticator.action(context);

            verify(authSession).setAuthNote(UserIdpRedirectAuthenticator.ATTEMPTED_USERNAME, "bob");
            verify(context).setUser(user);
            verify(context).forceChallenge(any(Response.class));
        }

        @Test
        void usernameSubmit_noFederation_attempted() {
            setupBasicMocks();
            setupEventMocks();
            MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
            params.putSingle("username", "bob");
            when(context.getHttpRequest()).thenReturn(httpRequest);
            when(httpRequest.getDecodedFormParameters()).thenReturn(params);
            when(userProvider.getUserByUsername(realm, "bob")).thenReturn(user);
            when(userProvider.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.empty());

            authenticator.action(context);

            verify(authSession).setAuthNote(UserIdpRedirectAuthenticator.ATTEMPTED_USERNAME, "bob");
            verify(context).attempted();
        }

        @Test
        void usernameSubmit_unknownUser_attempted() {
            setupBasicMocks();
            setupEventMocks();
            MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
            params.putSingle("username", "ghost");
            when(context.getHttpRequest()).thenReturn(httpRequest);
            when(httpRequest.getDecodedFormParameters()).thenReturn(params);
            when(userProvider.getUserByUsername(realm, "ghost")).thenReturn(null);

            authenticator.action(context);

            verify(authSession).setAuthNote(UserIdpRedirectAuthenticator.ATTEMPTED_USERNAME, "ghost");
            verify(context).attempted();
            verify(context, never()).setUser(any());
        }

        @Test
        void usernameSubmit_multipleIdps_showsSelectionForm() {
            setupBasicMocks();
            setupFormMocks();
            setupEventMocks();
            MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
            params.putSingle("username", "bob");
            when(context.getHttpRequest()).thenReturn(httpRequest);
            when(httpRequest.getDecodedFormParameters()).thenReturn(params);
            when(userProvider.getUserByUsername(realm, "bob")).thenReturn(user);
            when(user.getUsername()).thenReturn("bob");

            FederatedIdentityModel id1 = mock(FederatedIdentityModel.class);
            when(id1.getIdentityProvider()).thenReturn("github");
            FederatedIdentityModel id2 = mock(FederatedIdentityModel.class);
            when(id2.getIdentityProvider()).thenReturn("google");

            IdentityProviderModel githubIdp = mockIdp("github", "GitHub", true);
            IdentityProviderModel googleIdp = mockIdp("google", "Google", true);
            when(realm.getIdentityProviderByAlias("github")).thenReturn(githubIdp);
            when(realm.getIdentityProviderByAlias("google")).thenReturn(googleIdp);
            when(userProvider.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.of(id1, id2));

            authenticator.action(context);

            verify(context).challenge(any(Response.class));
            verify(loginForms).setAttribute(eq("idps"), any());
            verify(loginForms).createForm("select-idp.ftl");
        }

        @Test
        void emptyUsername_failureChallenge() {
            setupFormMocks();
            MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
            when(context.getHttpRequest()).thenReturn(httpRequest);
            when(httpRequest.getDecodedFormParameters()).thenReturn(params);

            authenticator.action(context);

            verify(context).failureChallenge(eq(AuthenticationFlowError.INVALID_USER), any(Response.class));
            verify(loginForms).setError("usernameRequired");
            verify(loginForms).createLoginUsername();
        }

        @Test
        void idpSelection_validAlias_redirects() {
            setupRedirectMocks();
            when(context.getUser()).thenReturn(user);
            when(user.getUsername()).thenReturn("bob");

            MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
            params.putSingle("idpAlias", "github");
            when(context.getHttpRequest()).thenReturn(httpRequest);
            when(httpRequest.getDecodedFormParameters()).thenReturn(params);
            when(authSession.getAuthNote("idp_redirector_aliases")).thenReturn("github,google");

            IdentityProviderModel idpModel = mockIdp("github", "GitHub", true);
            when(realm.getIdentityProviderByAlias("github")).thenReturn(idpModel);

            authenticator.action(context);

            verify(context).forceChallenge(any(Response.class));
            verify(context, never()).attempted();
        }

        @Test
        void idpSelection_invalidAlias_errorFormWithIdps() {
            setupBasicMocks();
            setupFormMocks();

            MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
            params.putSingle("idpAlias", "evil-idp");
            when(context.getHttpRequest()).thenReturn(httpRequest);
            when(httpRequest.getDecodedFormParameters()).thenReturn(params);
            when(authSession.getAuthNote("idp_redirector_aliases")).thenReturn("github,google");

            IdentityProviderModel githubIdp = mockIdp("github", "GitHub", true);
            IdentityProviderModel googleIdp = mockIdp("google", "Google", true);
            when(realm.getIdentityProviderByAlias("github")).thenReturn(githubIdp);
            when(realm.getIdentityProviderByAlias("google")).thenReturn(googleIdp);

            authenticator.action(context);

            verify(context).challenge(any(Response.class));
            verify(loginForms).setAttribute(eq("idps"), any());
            verify(loginForms).setError("invalidIdpSelection");
            verify(context, never()).forceChallenge(any());
            verify(context, never()).attempted();
        }

        @Test
        void idpSelection_noSessionNote_attempted() {
            setupBasicMocks();
            MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
            params.putSingle("idpAlias", "github");
            when(context.getHttpRequest()).thenReturn(httpRequest);
            when(httpRequest.getDecodedFormParameters()).thenReturn(params);
            when(authSession.getAuthNote("idp_redirector_aliases")).thenReturn(null);

            authenticator.action(context);

            verify(context).attempted();
        }
    }

    // ---- lifecycle tests ----

    @Test
    void testRequiresUser() {
        assert !authenticator.requiresUser();
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
