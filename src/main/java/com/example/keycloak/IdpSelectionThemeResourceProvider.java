package com.example.keycloak;

import org.keycloak.theme.ThemeResourceProvider;

import java.io.InputStream;
import java.net.URL;

public class IdpSelectionThemeResourceProvider implements ThemeResourceProvider {

    @Override
    public URL getTemplate(String name) {
        return getClass().getResource("/theme-resources/templates/" + name);
    }

    @Override
    public InputStream getResourceAsStream(String path) {
        return getClass().getResourceAsStream("/theme-resources/" + path);
    }

    @Override
    public void close() {
    }
}
