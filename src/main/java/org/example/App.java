package org.example;

import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.KerberosConfig;
import org.apache.hc.client5.http.auth.StandardAuthScheme;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.auth.KerberosSchemeFactory;
import org.apache.hc.client5.http.impl.auth.SPNegoSchemeFactory;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.client5.http.auth.AuthSchemeFactory;
import org.apache.hc.client5.http.SystemDefaultDnsResolver;

import java.io.Serializable;
import java.security.Principal;
import java.util.Arrays;

public class App {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: kerb-client <url>");
            System.exit(1);
        }

        String url = args[0];

        // Allow the JVM to use the system ticket cache (e.g. from kinit)
        System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");

        // Register SPNEGO and Kerberos auth scheme factories
        Registry<AuthSchemeFactory> authSchemeRegistry = RegistryBuilder.<AuthSchemeFactory>create()
                .register(StandardAuthScheme.SPNEGO, new SPNegoSchemeFactory(
                        KerberosConfig.custom()
                                .setStripPort(KerberosConfig.Option.ENABLE)
                                .setUseCanonicalHostname(KerberosConfig.Option.DEFAULT)
                                .build(),
                        SystemDefaultDnsResolver.INSTANCE))
                .register(StandardAuthScheme.KERBEROS, KerberosSchemeFactory.DEFAULT)
                .build();

        // Use default credentials from the platform (Windows AD ticket cache or kinit on Linux)
        BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(
                new AuthScope(null, -1),
                new UseJaasCredentials());

        // Prefer SPNEGO negotiation
        RequestConfig requestConfig = RequestConfig.custom()
                .setTargetPreferredAuthSchemes(Arrays.asList(StandardAuthScheme.SPNEGO))
                .build();

        try (CloseableHttpClient httpClient = HttpClientBuilder.create()
                .setDefaultAuthSchemeRegistry(authSchemeRegistry)
                .setDefaultCredentialsProvider(credentialsProvider)
                .setDefaultRequestConfig(requestConfig)
                .build()) {

            HttpGet request = new HttpGet(url);
            System.out.println("Requesting: " + url);

            try (ClassicHttpResponse response = httpClient.executeOpen(null, request, null)) {
                System.out.println("Status: " + response.getCode() + " " + response.getReasonPhrase());

                HttpEntity entity = response.getEntity();
                if (entity != null) {
                    System.out.println(EntityUtils.toString(entity));
                }
            }
        }
    }

    /**
     * Credentials implementation that defers to the JAAS/native login context,
     * letting the SPNEGO scheme use the platform's default Kerberos credentials
     * (Windows AD ticket cache or kinit on Linux/macOS).
     */
    private static class UseJaasCredentials implements org.apache.hc.client5.http.auth.Credentials, Serializable {
        @Override
        public Principal getUserPrincipal() {
            return null;
        }

        @Override
        public char[] getPassword() {
            return null;
        }
    }
}
