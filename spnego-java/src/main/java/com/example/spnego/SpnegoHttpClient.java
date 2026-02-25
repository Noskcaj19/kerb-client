package com.example.spnego;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

public class SpnegoHttpClient {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: java -jar spnego-client.jar <url>");
            System.exit(1);
        }

        String url = args[0];

        // Allow the GSS framework to obtain credentials from the system
        // (Windows AD ticket cache) without requiring explicit JAAS subject
        System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");

        // Programmatic JAAS configuration — uses the OS Kerberos ticket cache
        Configuration.setConfiguration(new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                Map<String, String> options = new HashMap<>();
                options.put("useTicketCache", "true");
                options.put("doNotPrompt", "true");
                return new AppConfigurationEntry[]{
                        new AppConfigurationEntry(
                                "com.sun.security.auth.module.Krb5LoginModule",
                                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                                options
                        )
                };
            }
        });

        LoginContext lc = new LoginContext("spnego-client");
        lc.login();
        Subject subject = lc.getSubject();

        Subject.doAs(subject, (PrivilegedExceptionAction<Void>) () -> {
            URI uri = URI.create(url);
            String host = uri.getHost();

            // Build the SPNEGO token for the target HTTP service
            GSSManager manager = GSSManager.getInstance();
            Oid spnegoOid = new Oid("1.3.6.1.5.5.2"); // SPNEGO
            GSSName serverName = manager.createName(
                    "HTTP@" + host, GSSName.NT_HOSTBASED_SERVICE);
            GSSContext context = manager.createContext(
                    serverName, spnegoOid, null, GSSContext.DEFAULT_LIFETIME);
            context.requestMutualAuth(true);
            context.requestCredDeleg(false);

            byte[] token = context.initSecContext(new byte[0], 0, 0);
            String authHeader = "Negotiate " + Base64.getEncoder().encodeToString(token);

            // Send the request with the pre-built Authorization header
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(uri)
                    .header("Authorization", authHeader)
                    .header("Accept", "application/json")
                    .GET()
                    .build();

            HttpResponse<String> response =
                    client.send(request, HttpResponse.BodyHandlers.ofString());

            System.out.println("HTTP " + response.statusCode());
            System.out.println(response.body());

            context.dispose();
            return null;
        });

        lc.logout();
    }
}
