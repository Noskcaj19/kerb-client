tpackage org.example;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.core5.http.ClassicHttpResponse;
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

import java.net.URI;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class App {

    private static final Oid SPNEGO_OID;

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

        // Allow the JVM to use the system ticket cache (Windows AD or kinit)
        System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
        // Enable JVM-level Kerberos and SPNEGO debug output
        System.setProperty("sun.security.krb5.debug", "true");
        System.setProperty("sun.security.spnego.debug", "true");

        // Log in via JAAS using the native ticket cache (Windows LSA or kinit file cache)
        LoginContext loginContext = new LoginContext("kerb-client", null, null, jaasConfig());
        loginContext.login();
        Subject subject = loginContext.getSubject();

        System.out.println("Logged in as: " + subject.getPrincipals());

        // Run the HTTP request as the authenticated subject
        Subject.doAs(subject, (PrivilegedExceptionAction<Void>) () -> {
            URI uri = URI.create(url);
            String spnegoToken = generateSpnegoToken(uri.getHost());

            try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
                HttpGet request = new HttpGet(url);
                request.setHeader("Authorization", "Negotiate " + spnegoToken);

                System.out.println("Requesting: " + url);

                try (ClassicHttpResponse response = httpClient.executeOpen(null, request, null)) {
                    System.out.println("Status: " + response.getCode() + " " + response.getReasonPhrase());

                    HttpEntity entity = response.getEntity();
                    if (entity != null) {
                        System.out.println(EntityUtils.toString(entity));
                    }
                }
            }
            return null;
        });

        loginContext.logout();
    }

    private static Configuration jaasConfig() {
        return new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                Map<String, String> options = new HashMap<>();
                options.put("useTicketCache", "true");
                options.put("doNotPrompt", "true");
                options.put("renewTGT", "true");

                return new AppConfigurationEntry[]{
                        new AppConfigurationEntry(
                                "com.sun.security.auth.module.Krb5LoginModule",
                                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                                options)
                };
            }
        };
    }

    private static String generateSpnegoToken(String host) throws Exception {
        GSSManager manager = GSSManager.getInstance();

        GSSName servicePrincipal = manager.createName(
                "HTTP/" + host, GSSName.NT_HOSTBASED_SERVICE);

        GSSContext context = manager.createContext(
                servicePrincipal,
                SPNEGO_OID,
                null, // use the credential from the JAAS subject
                GSSContext.DEFAULT_LIFETIME);

        context.requestMutualAuth(false);
        context.requestCredDeleg(false);

        byte[] token = context.initSecContext(new byte[0], 0, 0);
        context.dispose();

        return Base64.getEncoder().encodeToString(token);
    }
}
