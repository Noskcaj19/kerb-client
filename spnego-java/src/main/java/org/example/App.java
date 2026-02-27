package org.example;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.Locale;
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

        // Let JGSS pull credentials from the current OS-authenticated session.
        System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
        if (isWindows()) {
            // On Windows, prefer native SSPI/LSA credential access over FILE ccaches.
            System.setProperty("sun.security.jgss.native", "true");
            System.setProperty("sun.security.spnego.msinterop", "true");
        }
        byte[] token = createSpnegoToken(host);
        String authorizationHeader = "Negotiate " + Base64.getEncoder().encodeToString(token);

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

        try {
            return initToken(manager.createContext(serverName, SPNEGO_OID, null, GSSContext.DEFAULT_LIFETIME));
        } catch (Exception defaultCredsError) {
            // Linux AD joins commonly expose tickets via FILE/DIR/KCM caches; this path uses that cache explicitly.
            GSSCredential cacheCred = manager.createCredential(
                    null,
                    GSSCredential.DEFAULT_LIFETIME,
                    KRB5_OID,
                    GSSCredential.INITIATE_ONLY
            );

            try {
                return initToken(manager.createContext(serverName, SPNEGO_OID, cacheCred, GSSContext.DEFAULT_LIFETIME));
            } catch (Exception cacheCredsError) {
                cacheCredsError.addSuppressed(defaultCredsError);
                throw cacheCredsError;
            }
        }
    }

    private static byte[] initToken(GSSContext context) throws Exception {
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

    private static boolean isWindows() {
        String osName = System.getProperty("os.name", "");
        return osName.toLowerCase(Locale.ROOT).contains("win");
    }

    private static Oid oid(String value) {
        try {
            return new Oid(value);
        } catch (Exception e) {
            throw new IllegalStateException("Invalid OID: " + value, e);
        }
    }
}
