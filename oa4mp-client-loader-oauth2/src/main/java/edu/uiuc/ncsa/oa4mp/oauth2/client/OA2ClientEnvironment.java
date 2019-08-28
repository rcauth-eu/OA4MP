package edu.uiuc.ncsa.oa4mp.oauth2.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStore;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.client.DelegationService;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;

import javax.inject.Provider;
import java.net.URI;
import java.util.Collection;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/25/13 at  4:23 PM
 */
public class OA2ClientEnvironment extends ClientEnvironment {

    
    public OA2ClientEnvironment(URI accessTokenUri,
                                URI authorizationUri,
                                URI callback,
                                long certLifetime,
                                String clientId,
                                DelegationService delegationService,
                                URI resourceServerUri,
                                TokenForge tokenForge,
                                AssetStore assetStore,
                                boolean showRedirectPage,
                                String errorPagePath,
                                String redirectPagePath,
                                String successPagePath,
                                boolean oidcEnabled,
                                boolean showIDToken) {
        super(accessTokenUri,
                authorizationUri,
                callback,
                certLifetime,
                clientId,
                delegationService,
                null, null, null,
                resourceServerUri,
                tokenForge,
                assetStore, showRedirectPage,
                errorPagePath, redirectPagePath, successPagePath);
        info("oidcEnabled? " + oidcEnabled);
        this.oidcEnabled = oidcEnabled;
        this.showIDToken = showIDToken;
    }

    public OA2ClientEnvironment(MyLoggingFacade logger, Map<String, String> constants,
                                URI accessTokenUri,
                                URI authorizationUri,
                                URI callback,
                                URI initializeURI,
                                URI resourceServerUri,
                                long certLifetime,
                                String clientId,
                                String skin,
                                boolean enableAssetCleanup,
                                long maxAssetLifetime,
                                long keypairLifetime,
                                AssetProvider assetProvider,
                                Provider<Client> clientProvider,
                                Provider<TokenForge> tokenForgeProvider,
                                Provider<DelegationService> delegationServiceProvider,
                                Provider<AssetStore> assetStoreProvider,
                                boolean showRedirectPage,
                                boolean requestProxies,
                                String errorPagePath,
                                String redirectPagePath,
                                String successPagePath,
                                String secret,
                                Collection<String> scopes,
                                String wellKnownURI,
                                boolean oidcEnabled,
                                boolean showIDToken) {
        super(logger,
                constants,
                accessTokenUri,
                authorizationUri,
                callback,
                initializeURI,
                resourceServerUri,
                certLifetime,
                clientId,
                null,
                null,
                skin,
                enableAssetCleanup,
                maxAssetLifetime,
                keypairLifetime,
                assetProvider,
                clientProvider,
                tokenForgeProvider,
                delegationServiceProvider,
                assetStoreProvider,
                showRedirectPage,
                errorPagePath,
                redirectPagePath,
                successPagePath
                );
        this.requestProxies = requestProxies;
        this.secret = secret;
        this.scopes = scopes;
        this.wellKnownURI = wellKnownURI;
        this.oidcEnabled = oidcEnabled;
        this.showIDToken = showIDToken;
    }
    Collection<String> scopes = null;
    public Collection<String> getScopes(){
        return scopes;
    }
    String secret;

    public String getWellKnownURI() {
        return wellKnownURI;
    }

    String wellKnownURI = null;
    @Override
    public Client getClient() {
        if (client == null) {
            client = cp.get();
            client.setIdentifier(new BasicIdentifier(getClientId()));
            client.setSecret(secret);
        }
        return client;
    }

    boolean oidcEnabled = true;
    public boolean isOidcEnabled(){
        return oidcEnabled;
    }
    public void setScopes(Collection<String> scopes) {
        this.scopes = scopes;
    }

    /**
     * If the user enables showing the ID token, then information to be displayed on the success page will be
     * put in to the response.
     * @return
     */
    public boolean isShowIDToken() {
        return showIDToken;
    }

    boolean showIDToken = false;

    protected boolean requestProxies = false;

    public boolean isRequestProxies() {
        return requestProxies;
    }
}
