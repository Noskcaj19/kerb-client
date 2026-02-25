package org.example;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

public class App {
    private static final Oid SPNEGO_OID = oid("1.3.6.1.5.5.2");
    private static final Oid KRB5_OID = oid("1.2.840.113554.1.2.2");

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: java -jar spnego-client-1.0-SNAPSHOT.jar <url>");
            System.exit(1);
        }

        String targetUrl = args[0];
        URI uri = URI.create(targetUrl);
        String host = uri.getHost();

        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("URL must include a host: " + targetUrl);
        }

        Subject subject = loginWithCurrentSession();

        String authorizationHeader;
        try {
            authorizationHeader = Subject.doAs(subject, (PrivilegedExceptionAction<String>) () -> {
                byte[] token = createSpnegoToken(host);
                return "Negotiate " + Base64.getEncoder().encodeToString(token);
            });
        } catch (PrivilegedActionException e) {
            throw unwrap(e);
        }

        HttpRequest request = HttpRequest.newBuilder(uri)
                .header("Accept", "application/json")
                .header("Authorization", authorizationHeader)
                .GET()
                .build();

        HttpClient client = HttpClient.newHttpClient();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        System.out.println("HTTP " + response.statusCode());
        response.headers().map().forEach((k, v) -> System.out.println(k + ": " + String.join(",", v)));
        System.out.println();
        System.out.println(response.body());
    }

    private static byte[] createSpnegoToken(String host) throws Exception {
        String servicePrincipal = "HTTP/" + host.toLowerCase();
        GSSManager manager = GSSManager.getInstance();
        GSSName serverName = manager.createName(servicePrincipal, GSSName.NT_HOSTBASED_SERVICE);
        GSSCredential clientCred = manager.createCredential(
                null,
                GSSCredential.DEFAULT_LIFETIME,
                KRB5_OID,
                GSSCredential.INITIATE_ONLY
        );

        GSSContext context = manager.createContext(serverName, SPNEGO_OID, clientCred, GSSContext.DEFAULT_LIFETIME);
        context.requestMutualAuth(true);
        context.requestCredDeleg(false);

        try {
            byte[] token = context.initSecContext(new byte[0], 0, 0);
            if (token == null || token.length == 0) {
                throw new IllegalStateException("SPNEGO did not produce an initial token");
            }
            return token;
        } finally {
            context.dispose();
        }
    }

    private static Subject loginWithCurrentSession() throws LoginException {
        System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
        LoginContext loginContext = new LoginContext("SpnegoClient", null, (CallbackHandler) null, new WindowsAdConfiguration());
        loginContext.login();
        return loginContext.getSubject();
    }

    private static Exception unwrap(PrivilegedActionException e) {
        Exception nested = e.getException();
        return nested != null ? nested : e;
    }

    private static Oid oid(String value) {
        try {
            return new Oid(value);
        } catch (Exception e) {
            throw new IllegalStateException("Invalid OID: " + value, e);
        }
    }

    private static final class WindowsAdConfiguration extends Configuration {
        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            Map<String, String> options = new HashMap<>();
            options.put("useTicketCache", "true");
            options.put("renewTGT", "true");
            options.put("doNotPrompt", "true");
            options.put("isInitiator", "true");

            return new AppConfigurationEntry[] {
                    new AppConfigurationEntry(
                            "com.sun.security.auth.module.Krb5LoginModule",
                            AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                            options
                    )
            };
        }
    }
}
