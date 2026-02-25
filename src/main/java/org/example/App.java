package org.example;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;

import java.net.InetAddress;
import java.net.URI;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class App {

    private static final Oid SPNEGO_OID;
    private static final int MAX_SPNEGO_ROUNDS = 5;

    static {
        try {
            SPNEGO_OID = new Oid("1.3.6.1.5.5.2");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: kerb-client <url>");
            System.exit(1);
        }

        String url = args[0];

        System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
        System.setProperty("sun.security.krb5.debug", "true");
        System.setProperty("sun.security.spnego.debug", "true");

        LoginContext loginContext = new LoginContext("kerb-client", null, null, jaasConfig());
        loginContext.login();
        Subject subject = loginContext.getSubject();

        System.out.println("Logged in as: " + subject.getPrincipals());

        Subject.doAs(subject, (PrivilegedExceptionAction<Void>) () -> {
            doRequest(url);
            return null;
        });

        loginContext.logout();
    }

    private static void doRequest(String url) throws Exception {
        URI uri = URI.create(url);
        String canonicalHost = InetAddress.getByName(uri.getHost()).getCanonicalHostName();
        GSSManager manager = GSSManager.getInstance();
        GSSName servicePrincipal = manager.createName(
                "HTTP/" + canonicalHost, GSSName.NT_HOSTBASED_SERVICE);

        GSSContext gssContext = manager.createContext(
                servicePrincipal,
                SPNEGO_OID,
                null,
                GSSContext.DEFAULT_LIFETIME);
        gssContext.requestMutualAuth(true);
        gssContext.requestCredDeleg(false);

        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            byte[] inToken = new byte[0];

            for (int round = 0; round < MAX_SPNEGO_ROUNDS; round++) {
                byte[] outToken = gssContext.initSecContext(inToken, 0, inToken.length);

                HttpGet request = new HttpGet(url);
                if (outToken != null && outToken.length > 0) {
                    request.setHeader("Authorization",
                            "Negotiate " + Base64.getEncoder().encodeToString(outToken));
                }

                System.out.println("Requesting: " + url + " (round " + round + ")");

                try (ClassicHttpResponse response = httpClient.executeOpen(null, request, null)) {
                    int status = response.getCode();
                    System.out.println("Status: " + status + " " + response.getReasonPhrase());

                    if (status != 401) {
                        HttpEntity entity = response.getEntity();
                        if (entity != null) {
                            System.out.println(EntityUtils.toString(entity));
                        }
                        return;
                    }

                    String serverToken = extractNegotiateToken(response);
                    if (serverToken == null) {
                        throw new RuntimeException(
                                "Server returned 401 without a Negotiate challenge token");
                    }
                    inToken = Base64.getDecoder().decode(serverToken);
                }
            }
            throw new RuntimeException("SPNEGO handshake did not complete in "
                    + MAX_SPNEGO_ROUNDS + " rounds");
        } finally {
            gssContext.dispose();
        }
    }

    private static String extractNegotiateToken(ClassicHttpResponse response) {
        for (Header header : response.getHeaders("WWW-Authenticate")) {
            String value = header.getValue();
            if (value.regionMatches(true, 0, "Negotiate ", 0, 10) && value.length() > 10) {
                return value.substring(10).trim();
            }
        }
        return null;
    }

    private static Configuration jaasConfig() {
        boolean isWindows = System.getProperty("os.name", "").toLowerCase().contains("win");

        return new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                Map<String, String> options = new HashMap<>();
                options.put("isInitiator", "true");
                options.put("doNotPrompt", "true");
                options.put("useTicketCache", "true");
                options.put("principal", "*");
                options.put("refreshKrb5Config", "true");

                if (isWindows) {
                    options.put("ticketCache", "MSLSA:");
                } else {
                    options.put("renewTGT", "true");
                }

                return new AppConfigurationEntry[]{
                        new AppConfigurationEntry(
                                "com.sun.security.auth.module.Krb5LoginModule",
                                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                                options)
                };
            }
        };
    }
}
