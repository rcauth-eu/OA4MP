package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.NewClientNotifier;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.storage.BaseClient;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.util.mail.MailUtil;

import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/12/17 at  2:06 PM
 */
public class OA2NewClientNotifier extends NewClientNotifier {
    public static final String SCOPES = "scopes";
    public static final String REFRESH_LIFETIME = "refreshLifetime";
    public static final String REFRESH_ENABLED = "refreshEnabled";
    public static final String ISSUER = "issuer";
    public static final String SIGN_TOKEN_OK = "signTokens";
    public static final String LDAP_CONFIGURATION = "ldapConfiguration";
    public static final String CALLBACK = "callback";


    public OA2NewClientNotifier(MailUtil mailUtil, MyLoggingFacade loggingFacade) {
        super(mailUtil, loggingFacade);
    }

    @Override
    protected Map<String, String> getReplacements(BaseClient client) {
        Map<String, String> replacements = super.getReplacements(client);
        replacements.remove(FAILURE_URI); // don't need for OA2 clients.
        if (client instanceof OA2Client) {
            OA2Client oa2Client = (OA2Client) client;
            replacements.put(SCOPES, String.valueOf(oa2Client.getScopes()));
            replacements.put(CALLBACK, String.valueOf(oa2Client.getCallbackURIs()));
            replacements.put(REFRESH_ENABLED, Boolean.toString(oa2Client.isRTLifetimeEnabled()));
            if (oa2Client.isRTLifetimeEnabled()) {
                replacements.put(REFRESH_LIFETIME, Long.toString(oa2Client.getRtLifetime()));
            } else {
                replacements.put(REFRESH_LIFETIME, "n/a");
            }
            replacements.put(SIGN_TOKEN_OK, Boolean.toString(oa2Client.isSignTokens()));
            if (oa2Client.getLdaps() == null || oa2Client.getLdaps().isEmpty()) {
                replacements.put(LDAP_CONFIGURATION, "(none)");

            } else {
                LDAPConfigurationUtil ldapConfigurationUtil = new LDAPConfigurationUtil();
                replacements.put(LDAP_CONFIGURATION, ldapConfigurationUtil.toJSON(oa2Client.getLdaps()).toString(2));
            }
            if (oa2Client.getIssuer() == null) {
                replacements.put(ISSUER, "(none)");
            } else {
                replacements.put(ISSUER, oa2Client.getIssuer());
            }
        } else if (client instanceof AdminClient) {
            AdminClient adminClient = (AdminClient) client;
            replacements.put(SCOPES, ADMIN_NA);
            replacements.put(CALLBACK, ADMIN_NA);
            replacements.put(REFRESH_ENABLED, ADMIN_NA);
            replacements.put(REFRESH_LIFETIME, ADMIN_NA);
            replacements.put(SIGN_TOKEN_OK, ADMIN_NA);
            replacements.put(LDAP_CONFIGURATION, ADMIN_NA);
            if (adminClient.getIssuer() == null) {
                replacements.put(ISSUER, "(none)");
            } else {
                replacements.put(ISSUER, adminClient.getIssuer());
            }
        } else {
            loggingFacade.warn("Found unexpected client type in OA2NewClientNotifier: "+client.getClass().getName());
        }
        return replacements;
    }


}
