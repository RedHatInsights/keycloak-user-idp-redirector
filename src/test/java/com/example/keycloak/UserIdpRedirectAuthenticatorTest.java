package com.example.keycloak;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
import java.util.stream.Stream;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.withSettings;

@ExtendWith(MockitoExtension.class)
class UserIdpRedirectAuthenticatorTest {

    @Mock
    private AuthenticationFlowContext context;

    @Mock
    private KeycloakSession session;

    @Mock
    private RealmModel realm;

    @Mock
    private UserModel user;

    @Mock
    private UserProvider userProvider;

    @Mock
    private AuthenticationSessionModel authSession;

    @Mock
    private RootAuthenticationSessionModel rootAuthSession;

    @Mock
    private ClientModel client;

    @Mock
    private UriInfo uriInfo;

    private UserIdpRedirectAuthenticator authenticator;

    @BeforeEach
    void setup() {
        authenticator = new UserIdpRedirectAuthenticator();
    }

    private void setupBasicMocks() {
        when(context.getSession()).thenReturn(session);
        when(context.getRealm()).thenReturn(realm);
        when(session.users()).thenReturn(userProvider);
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

        // Mock UriBuilder for secure URL construction
        UriBuilder uriBuilder = mock(UriBuilder.class, RETURNS_SELF);
        lenient().when(uriInfo.getBaseUriBuilder()).thenReturn(uriBuilder);
        lenient().when(uriBuilder.build()).thenReturn(URI.create("http://localhost:8080/realms/test-realm/broker/github/login?client_id=test-client&tab_id=test-tab-id"));
    }

    @Test
    void testAuthenticateWithNoUser() {
        // Given
        when(context.getUser()).thenReturn(null);

        // When
        authenticator.authenticate(context);

        // Then
        verify(context).attempted();
        verify(context, never()).forceChallenge(any());
    }

    @Test
    void testAuthenticateWithNoFederatedIdentities() {
        // Given
        setupBasicMocks();
        when(context.getUser()).thenReturn(user);
        when(userProvider.getFederatedIdentitiesStream(realm, user))
            .thenReturn(Stream.empty());

        // When
        authenticator.authenticate(context);

        // Then
        verify(context).attempted();
        verify(context, never()).forceChallenge(any());
    }

    @Test
    void testAuthenticateWithSingleFederatedIdentity() {
        // Given
        setupFullMocks();
        when(context.getUser()).thenReturn(user);

        FederatedIdentityModel identity = mock(FederatedIdentityModel.class);
        when(identity.getIdentityProvider()).thenReturn("github");

        IdentityProviderModel idpModel = mock(IdentityProviderModel.class);
        when(idpModel.isEnabled()).thenReturn(true);
        when(realm.getIdentityProviderByAlias("github")).thenReturn(idpModel);

        when(userProvider.getFederatedIdentitiesStream(realm, user))
            .thenReturn(Stream.of(identity));

        // When
        authenticator.authenticate(context);

        // Then
        verify(context).forceChallenge(any(Response.class));
        verify(context, never()).attempted();
    }

    @Test
    void testAuthenticateWithMultipleFederatedIdentities() {
        // Given
        setupFullMocks();
        when(context.getUser()).thenReturn(user);

        // Set iteration order non-deterministic - use lenient
        FederatedIdentityModel identity1 = mock(FederatedIdentityModel.class, withSettings().lenient());
        lenient().when(identity1.getIdentityProvider()).thenReturn("github");

        FederatedIdentityModel identity2 = mock(FederatedIdentityModel.class, withSettings().lenient());
        lenient().when(identity2.getIdentityProvider()).thenReturn("google");

        IdentityProviderModel idpModel = mock(IdentityProviderModel.class);
        lenient().when(idpModel.isEnabled()).thenReturn(true);
        lenient().when(realm.getIdentityProviderByAlias("github")).thenReturn(idpModel);
        lenient().when(realm.getIdentityProviderByAlias("google")).thenReturn(idpModel);

        when(userProvider.getFederatedIdentitiesStream(realm, user))
            .thenReturn(Stream.of(identity1, identity2));

        // When
        authenticator.authenticate(context);

        // Then
        // Should redirect to one of them (first in iteration order)
        verify(context).forceChallenge(any(Response.class));
        verify(context, never()).attempted();
    }

    @Test
    void testAuthenticateWithDisabledIdp() {
        // Given
        setupFullMocks();
        when(context.getUser()).thenReturn(user);

        FederatedIdentityModel identity = mock(FederatedIdentityModel.class);
        when(identity.getIdentityProvider()).thenReturn("github");

        IdentityProviderModel idpModel = mock(IdentityProviderModel.class);
        when(idpModel.isEnabled()).thenReturn(false);
        when(realm.getIdentityProviderByAlias("github")).thenReturn(idpModel);

        when(userProvider.getFederatedIdentitiesStream(realm, user))
            .thenReturn(Stream.of(identity));

        // When
        authenticator.authenticate(context);

        // Then
        verify(context).attempted();
        verify(context, never()).forceChallenge(any());
    }

    @Test
    void testAuthenticateWithNonexistentIdp() {
        // Given
        setupFullMocks();
        when(context.getUser()).thenReturn(user);

        FederatedIdentityModel identity = mock(FederatedIdentityModel.class);
        when(identity.getIdentityProvider()).thenReturn("deleted-idp");

        when(realm.getIdentityProviderByAlias("deleted-idp")).thenReturn(null);

        when(userProvider.getFederatedIdentitiesStream(realm, user))
            .thenReturn(Stream.of(identity));

        // When
        authenticator.authenticate(context);

        // Then
        verify(context).attempted();
        verify(context, never()).forceChallenge(any());
    }

    @Test
    void testRequiresUser() {
        // When/Then
        assert authenticator.requiresUser();
    }

    @Test
    void testConfiguredFor() {
        // When/Then
        assert authenticator.configuredFor(session, realm, user);
    }

    @Test
    void testAction() {
        // When
        authenticator.action(context);

        // Then
        verify(context).attempted();
    }

    @Test
    void testSetRequiredActions() {
        // When
        authenticator.setRequiredActions(session, realm, user);

        // Then - should not throw, no-op
    }

    @Test
    void testClose() {
        // When
        authenticator.close();

        // Then - should not throw, no-op
    }
}
