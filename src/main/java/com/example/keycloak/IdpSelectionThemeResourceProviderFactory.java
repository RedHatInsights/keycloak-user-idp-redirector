package com.example.keycloak;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.theme.ThemeResourceProvider;
import org.keycloak.theme.ThemeResourceProviderFactory;

public class IdpSelectionThemeResourceProviderFactory implements ThemeResourceProviderFactory {

    public static final String PROVIDER_ID = "idp-selection-theme-resources";

    private static final IdpSelectionThemeResourceProvider INSTANCE = new IdpSelectionThemeResourceProvider();

    @Override
    public ThemeResourceProvider create(KeycloakSession session) {
        return INSTANCE;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
