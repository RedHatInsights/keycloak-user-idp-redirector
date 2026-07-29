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
import java.util.Map;
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
        void attemptedUsername_noFederation_noDomainMatch_attempted() {
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
        void attemptedUsername_unknownUser_noDomainMatch_attempted() {
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
        void loginHint_noFederation_noDomainMatch_attempted() {
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
        void usernameSubmit_noFederation_noDomainMatch_attempted() {
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
        void usernameSubmit_unknownUser_noDomainMatch_attempted() {
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

    // ---- domain fallback tests ----

    @Nested
    class DomainFallback {

        private IdentityProviderModel mockIdpWithDomains(String alias, String domains, boolean matchSubdomains) {
            IdentityProviderModel idp = mockIdp(alias, alias, true);
            Map<String, String> config = new java.util.HashMap<>();
            config.put("home.idp.discovery.domains", domains);
            if (matchSubdomains) {
                config.put("home.idp.discovery.matchSubdomains", "true");
            }
            when(idp.getConfig()).thenReturn(config);
            return idp;
        }

        @Test
        void action_noFederation_domainMatch_redirects() {
            setupRedirectMocks();
            setupEventMocks();
            MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
            params.putSingle("username", "bob@example.com");
            when(context.getHttpRequest()).thenReturn(httpRequest);
            when(httpRequest.getDecodedFormParameters()).thenReturn(params);
            when(userProvider.getUserByUsername(realm, "bob@example.com")).thenReturn(user);
            when(user.getUsername()).thenReturn("bob@example.com");
            when(userProvider.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.empty());
            when(user.getFirstAttribute("email")).thenReturn("bob@example.com");

            IdentityProviderModel domainIdp = mockIdpWithDomains("corp-saml", "example.com", false);
            when(realm.getIdentityProvidersStream()).thenReturn(Stream.of(domainIdp));

            authenticator.action(context);

            verify(context).forceChallenge(any(Response.class));
            verify(context, never()).attempted();
        }

        @Test
        void action_noFederation_noDomainMatch_attempted() {
            setupBasicMocks();
            setupEventMocks();
            MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
            params.putSingle("username", "bob@other.com");
            when(context.getHttpRequest()).thenReturn(httpRequest);
            when(httpRequest.getDecodedFormParameters()).thenReturn(params);
            when(userProvider.getUserByUsername(realm, "bob@other.com")).thenReturn(user);
            when(userProvider.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.empty());
            when(user.getFirstAttribute("email")).thenReturn("bob@other.com");

            IdentityProviderModel domainIdp = mockIdpWithDomains("corp-saml", "example.com", false);
            when(realm.getIdentityProvidersStream()).thenReturn(Stream.of(domainIdp));

            authenticator.action(context);

            verify(context).attempted();
            verify(context, never()).forceChallenge(any());
        }

        @Test
        void action_federationTakesPriority_overDomainMatch() {
            setupRedirectMocks();
            setupEventMocks();
            MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
            params.putSingle("username", "bob@example.com");
            when(context.getHttpRequest()).thenReturn(httpRequest);
            when(httpRequest.getDecodedFormParameters()).thenReturn(params);
            when(userProvider.getUserByUsername(realm, "bob@example.com")).thenReturn(user);
            when(user.getUsername()).thenReturn("bob@example.com");

            FederatedIdentityModel identity = mock(FederatedIdentityModel.class);
            when(identity.getIdentityProvider()).thenReturn("linked-idp");
            IdentityProviderModel linkedIdp = mockIdp("linked-idp", "Linked IDP", true);
            when(realm.getIdentityProviderByAlias("linked-idp")).thenReturn(linkedIdp);
            when(userProvider.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.of(identity));

            authenticator.action(context);

            verify(context).forceChallenge(any(Response.class));
            verify(realm, never()).getIdentityProvidersStream();
        }

        @Test
        void action_unknownUser_domainMatchFromUsername_redirects() {
            setupRedirectMocks();
            setupEventMocks();
            MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
            params.putSingle("username", "newuser@example.com");
            when(context.getHttpRequest()).thenReturn(httpRequest);
            when(httpRequest.getDecodedFormParameters()).thenReturn(params);
            when(userProvider.getUserByUsername(realm, "newuser@example.com")).thenReturn(null);

            IdentityProviderModel domainIdp = mockIdpWithDomains("corp-saml", "example.com", false);
            when(realm.getIdentityProvidersStream()).thenReturn(Stream.of(domainIdp));

            authenticator.action(context);

            verify(context).forceChallenge(any(Response.class));
            verify(context, never()).attempted();
        }

        @Test
        void action_unknownUser_noDomainMatch_attempted() {
            setupBasicMocks();
            setupEventMocks();
            MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
            params.putSingle("username", "newuser@unknown.com");
            when(context.getHttpRequest()).thenReturn(httpRequest);
            when(httpRequest.getDecodedFormParameters()).thenReturn(params);
            when(userProvider.getUserByUsername(realm, "newuser@unknown.com")).thenReturn(null);

            IdentityProviderModel domainIdp = mockIdpWithDomains("corp-saml", "example.com", false);
            when(realm.getIdentityProvidersStream()).thenReturn(Stream.of(domainIdp));

            authenticator.action(context);

            verify(context).attempted();
            verify(context, never()).forceChallenge(any());
        }

        @Test
        void subdomainMatch_whenEnabled_redirects() {
            setupRedirectMocks();
            setupEventMocks();
            MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
            params.putSingle("username", "bob@sub.example.com");
            when(context.getHttpRequest()).thenReturn(httpRequest);
            when(httpRequest.getDecodedFormParameters()).thenReturn(params);
            when(userProvider.getUserByUsername(realm, "bob@sub.example.com")).thenReturn(user);
            when(user.getUsername()).thenReturn("bob@sub.example.com");
            when(userProvider.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.empty());
            when(user.getFirstAttribute("email")).thenReturn("bob@sub.example.com");

            IdentityProviderModel domainIdp = mockIdpWithDomains("corp-saml", "example.com", true);
            when(realm.getIdentityProvidersStream()).thenReturn(Stream.of(domainIdp));

            authenticator.action(context);

            verify(context).forceChallenge(any(Response.class));
            verify(context, never()).attempted();
        }

        @Test
        void subdomainMatch_whenDisabled_attempted() {
            setupBasicMocks();
            setupEventMocks();
            MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
            params.putSingle("username", "bob@sub.example.com");
            when(context.getHttpRequest()).thenReturn(httpRequest);
            when(httpRequest.getDecodedFormParameters()).thenReturn(params);
            when(userProvider.getUserByUsername(realm, "bob@sub.example.com")).thenReturn(user);
            when(userProvider.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.empty());
            when(user.getFirstAttribute("email")).thenReturn("bob@sub.example.com");

            IdentityProviderModel domainIdp = mockIdpWithDomains("corp-saml", "example.com", false);
            when(realm.getIdentityProvidersStream()).thenReturn(Stream.of(domainIdp));

            authenticator.action(context);

            verify(context).attempted();
            verify(context, never()).forceChallenge(any());
        }

        @Test
        void perAttributeDomainConfig_takesPrecedence() {
            setupRedirectMocks();
            setupEventMocks();
            MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
            params.putSingle("username", "bob@specific.com");
            when(context.getHttpRequest()).thenReturn(httpRequest);
            when(httpRequest.getDecodedFormParameters()).thenReturn(params);
            when(userProvider.getUserByUsername(realm, "bob@specific.com")).thenReturn(user);
            when(user.getUsername()).thenReturn("bob@specific.com");
            when(userProvider.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.empty());
            when(user.getFirstAttribute("email")).thenReturn("bob@specific.com");

            IdentityProviderModel idp = mockIdp("corp-saml", "Corp SAML", true);
            Map<String, String> config = new java.util.HashMap<>();
            config.put("home.idp.discovery.domains", "general.com");
            config.put("home.idp.discovery.domains.email", "specific.com");
            when(idp.getConfig()).thenReturn(config);
            when(realm.getIdentityProvidersStream()).thenReturn(Stream.of(idp));

            authenticator.action(context);

            verify(context).forceChallenge(any(Response.class));
            verify(context, never()).attempted();
        }

        @Test
        void userWithNullEmail_noDomainMatch_attempted() {
            setupBasicMocks();
            setupEventMocks();
            MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
            params.putSingle("username", "bob");
            when(context.getHttpRequest()).thenReturn(httpRequest);
            when(httpRequest.getDecodedFormParameters()).thenReturn(params);
            when(userProvider.getUserByUsername(realm, "bob")).thenReturn(user);
            when(userProvider.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.empty());
            when(user.getFirstAttribute("email")).thenReturn(null);

            authenticator.action(context);

            verify(context).attempted();
        }

        @Test
        void bypass_noFederation_domainMatch_redirects() {
            setupRedirectMocks();
            when(authSession.getAuthNote(UserIdpRedirectAuthenticator.ATTEMPTED_USERNAME)).thenReturn("bob@example.com");
            when(userProvider.getUserByUsername(realm, "bob@example.com")).thenReturn(user);
            when(user.getUsername()).thenReturn("bob@example.com");
            when(userProvider.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.empty());
            when(user.getFirstAttribute("email")).thenReturn("bob@example.com");

            IdentityProviderModel domainIdp = mockIdpWithDomains("corp-saml", "example.com", false);
            when(realm.getIdentityProvidersStream()).thenReturn(Stream.of(domainIdp));

            authenticator.authenticate(context);

            verify(context).forceChallenge(any(Response.class));
            verify(context, never()).attempted();
        }

        @Test
        void bypass_unknownUser_domainMatch_redirects() {
            setupRedirectMocks();
            when(authSession.getAuthNote(UserIdpRedirectAuthenticator.ATTEMPTED_USERNAME)).thenReturn("new@example.com");
            when(userProvider.getUserByUsername(realm, "new@example.com")).thenReturn(null);

            IdentityProviderModel domainIdp = mockIdpWithDomains("corp-saml", "example.com", false);
            when(realm.getIdentityProvidersStream()).thenReturn(Stream.of(domainIdp));

            authenticator.authenticate(context);

            verify(context).forceChallenge(any(Response.class));
            verify(context, never()).attempted();
        }

        @Test
        void multipleDomains_separatedByDelimiter_matches() {
            setupRedirectMocks();
            setupEventMocks();
            MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
            params.putSingle("username", "bob@second.com");
            when(context.getHttpRequest()).thenReturn(httpRequest);
            when(httpRequest.getDecodedFormParameters()).thenReturn(params);
            when(userProvider.getUserByUsername(realm, "bob@second.com")).thenReturn(user);
            when(user.getUsername()).thenReturn("bob@second.com");
            when(userProvider.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.empty());
            when(user.getFirstAttribute("email")).thenReturn("bob@second.com");

            IdentityProviderModel idp = mockIdp("corp-saml", "Corp SAML", true);
            Map<String, String> config = new java.util.HashMap<>();
            config.put("home.idp.discovery.domains", "first.com##second.com##third.com");
            when(idp.getConfig()).thenReturn(config);
            when(realm.getIdentityProvidersStream()).thenReturn(Stream.of(idp));

            authenticator.action(context);

            verify(context).forceChallenge(any(Response.class));
            verify(context, never()).attempted();
        }

        @Test
        void disabledIdp_notConsideredForDomainMatch() {
            setupBasicMocks();
            setupEventMocks();
            MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
            params.putSingle("username", "bob@example.com");
            when(context.getHttpRequest()).thenReturn(httpRequest);
            when(httpRequest.getDecodedFormParameters()).thenReturn(params);
            when(userProvider.getUserByUsername(realm, "bob@example.com")).thenReturn(user);
            when(userProvider.getFederatedIdentitiesStream(realm, user)).thenReturn(Stream.empty());
            when(user.getFirstAttribute("email")).thenReturn("bob@example.com");

            IdentityProviderModel disabledIdp = mockIdp("corp-saml", "Corp SAML", false);
            when(realm.getIdentityProvidersStream()).thenReturn(Stream.of(disabledIdp));

            authenticator.action(context);

            verify(context).attempted();
            verify(context, never()).forceChallenge(any());
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
