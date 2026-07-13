package com.example.keycloak;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class UserIdpRedirectAuthenticatorFactoryTest {

    private UserIdpRedirectAuthenticatorFactory factory;

    @BeforeEach
    void setup() {
        factory = new UserIdpRedirectAuthenticatorFactory();
    }

    @Test
    void testGetId() {
        assertEquals("user-idp-redirector", factory.getId());
    }

    @Test
    void testGetDisplayType() {
        assertEquals("User IDP Redirector", factory.getDisplayType());
    }

    @Test
    void testIsConfigurable() {
        assertFalse(factory.isConfigurable());
    }

    @Test
    void testIsUserSetupAllowed() {
        assertFalse(factory.isUserSetupAllowed());
    }

    @Test
    void testGetHelpText() {
        assertEquals(
            "Redirects users to their linked Identity Provider after username entry",
            factory.getHelpText()
        );
    }

    @Test
    void testGetReferenceCategory() {
        assertNull(factory.getReferenceCategory());
    }

    @Test
    void testGetRequirementChoices() {
        AuthenticationExecutionModel.Requirement[] requirements = factory.getRequirementChoices();
        assertEquals(3, requirements.length);
        assertTrue(containsRequirement(requirements, AuthenticationExecutionModel.Requirement.REQUIRED));
        assertTrue(containsRequirement(requirements, AuthenticationExecutionModel.Requirement.ALTERNATIVE));
        assertTrue(containsRequirement(requirements, AuthenticationExecutionModel.Requirement.DISABLED));
    }

    @Test
    void testGetConfigProperties() {
        assertTrue(factory.getConfigProperties().isEmpty());
    }

    @Test
    void testCreate() {
        KeycloakSession session = mock(KeycloakSession.class);
        Authenticator authenticator = factory.create(session);
        assertNotNull(authenticator);
        assertInstanceOf(UserIdpRedirectAuthenticator.class, authenticator);
    }

    @Test
    void testInit() {
        // Should not throw
        factory.init(null);
    }

    @Test
    void testPostInit() {
        // Should not throw
        factory.postInit(null);
    }

    @Test
    void testClose() {
        // Should not throw
        factory.close();
    }

    private boolean containsRequirement(
        AuthenticationExecutionModel.Requirement[] requirements,
        AuthenticationExecutionModel.Requirement target
    ) {
        for (AuthenticationExecutionModel.Requirement req : requirements) {
            if (req == target) {
                return true;
            }
        }
        return false;
    }
}
