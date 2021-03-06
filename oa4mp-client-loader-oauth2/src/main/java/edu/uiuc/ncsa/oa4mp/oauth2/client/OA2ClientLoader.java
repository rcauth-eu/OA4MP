package edu.uiuc.ncsa.oa4mp.oauth2.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientXMLTags;
import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPServiceProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.client.loader.AbstractClientLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.*;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.TypedProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.delegation.client.DelegationService;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.oauth_2_0.OA2ConfigurationLoaderUtils;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2TokenForge;
import edu.uiuc.ncsa.security.oauth_2_0.client.*;
import org.apache.commons.configuration.tree.ConfigurationNode;

import javax.inject.Provider;
import java.net.URI;
import java.util.Collection;
import java.util.HashMap;

import static edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment.CALLBACK_URI_KEY;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/4/13 at  4:34 PM
 */
public class OA2ClientLoader<T extends ClientEnvironment> extends AbstractClientLoader<T> {
    public static final String PROXY_ENDPOINT = "getproxy";

    public OA2ClientLoader(ConfigurationNode node) {
        super(node);
    }

    @Override
    public String getVersionString() {
        return "OA4MP Client OAuth 2 configuration loader, version " + VERSION_NUMBER;
    }

    public OA4MPServiceProvider getServiceProvider() {
        return new OA2MPServiceProvider(load());
    }

    private boolean scopesParsed=false;
    protected Collection<String> scopes = null;

    public Collection<String> getScopes() throws IllegalAccessException, InstantiationException, ClassNotFoundException {
        if (!scopesParsed) {
            scopesParsed=true;
            scopes = OA2ConfigurationLoaderUtils.getScopes(cn);
        }
        return scopes;
    }

    /**
     * Factory method. Override this to create the actual instance as needed.
     *
     * @param tokenForgeProvider
     * @param clientProvider
     * @param constants
     * @return
     */
    public T createInstance(Provider<TokenForge> tokenForgeProvider,
                            Provider<Client> clientProvider,
                            HashMap<String, String> constants) {
        try {
            return (T) new OA2ClientEnvironment(
                    myLogger, constants,
                    getAccessTokenURI(),
                    getAuthorizeURI(),
                    getCallback(),
                    getInitiateURI(),
                    getAssetURI(),
                    checkCertLifetime(),
                    getId(),
                    getSkin(),
                    isEnableAssetCleanup(),
                    getMaxAssetLifetime(),
                    getKeypairLifetime(),
                    getAssetProvider(),
                    clientProvider,
                    tokenForgeProvider,
                    getDSP(),
                    getAssetStoreProvider(),
                    isShowRedirectPage(),
                    requestProxies(),
                    getErrorPagePath(),
                    getRedirectPagePath(),
                    getSuccessPagePath(),
                    getSecret(),
                    getScopes(),
                    getWellKnownURI(),
                    isOIDCEnabled(),
                    isShowIDToken()
            );
        } catch (Throwable e) {
            throw new GeneralException("Unable to create client environment", e);
        }
    }

    private AssetProvider assetProvider = null;

    @Override
    public AssetProvider getAssetProvider() {
        if (assetProvider == null) {
            assetProvider = new OA2AssetProvider();
        }
        return assetProvider;
    }

    private boolean wellKnownURIparsed = false;
    private String wellKnownURI = null;

    public String getWellKnownURI() {
        if (!wellKnownURIparsed) {
            wellKnownURIparsed=true;
            wellKnownURI = getCfgValue("wellKnownUri");
            if (wellKnownURI == null)
                warn("No wellKnownURI is defined, can NOT verify ID tokens");
        }
        return wellKnownURI;

    }

    private Boolean showIDToken = null;

    public boolean isShowIDToken() {
        if (showIDToken == null) {
            String showIDTokenValue=getCfgValue(ClientXMLTags.SHOW_ID_TOKEN);
            if (showIDTokenValue==null) {
                // NOTE: showIDToken is used only by OA2ReadyServlet via isShowIDToken() and used for debug purposes only.
                showIDToken = Boolean.FALSE; // default
                info("No value for " + ClientXMLTags.SHOW_ID_TOKEN + " is configured, using default \"" + showIDToken + "\"");
            } else {
                // Note: parseBoolean() only knows true, anything else becomes false.
                showIDToken = Boolean.parseBoolean(showIDTokenValue);
                debug("Value for "+ClientXMLTags.SHOW_ID_TOKEN+" parsed as "+showIDToken);
            }
        }
        return showIDToken;
    }

    private Boolean oidcEnabled = null;

    public boolean isOIDCEnabled() {
        if (oidcEnabled == null) {
            String oidcEnabledValue=getCfgValue(ClientXMLTags.OIDC_ENABLED);
            if (oidcEnabledValue==null) {
                oidcEnabled=Boolean.TRUE; // default
                warn("No value for "+ClientXMLTags.OIDC_ENABLED+" is configured, using default \""+oidcEnabled+"\"");
            } else {
                // Note: parseBoolean() only knows true, anything else becomes false.
                oidcEnabled = Boolean.parseBoolean(oidcEnabledValue);
                debug("Value for "+ClientXMLTags.OIDC_ENABLED+" parsed as "+oidcEnabled);
            }
        }
        return oidcEnabled;
    }

    private boolean assetURIparsed = false;
    private URI assetURI = null;

    @Override
    protected URI getAssetURI(){
        if(assetURIparsed == false) {
            assetURIparsed=true;
            assetURI = super.getAssetURI();
        }
        return assetURI;
    }

    protected URI getProxyAssetURI() {
        String x = getCfgValue(ClientXMLTags.ASSET_URI);
        checkProtocol(x);
        return createServiceURI(x, getBaseURI(), PROXY_ENDPOINT);
    }

    private boolean accessTokenURIparsed = false;
    private URI accessTokenURI = null;

    @Override
    protected URI getAccessTokenURI(){
        if(!accessTokenURIparsed) {
            accessTokenURIparsed=true;
            accessTokenURI = super.getAccessTokenURI();
        }
        return accessTokenURI;
    }

    @Override
    protected Provider<AssetStore> getAssetStoreProvider() {
        if (assetStoreProvider == null) {
            MultiAssetStoreProvider masp = new MultiAssetStoreProvider(cn, isDefaultStoreDisabled(), loggerProvider.get());
            OA2AssetSerializationKeys keys = new OA2AssetSerializationKeys();
            OA2AssetConverter assetConverter = new OA2AssetConverter(keys, getAssetProvider());
            assetStoreProvider = masp;
            masp.addListener(new FSAssetStoreProvider(cn, getAssetProvider(), assetConverter));
            masp.addListener(new OA2SQLAssetStoreProvider(cn, ClientXMLTags.POSTGRESQL_STORE, getPgConnectionPoolProvider(),
                    getAssetProvider(), assetConverter));
            masp.addListener(new OA2SQLAssetStoreProvider(cn, ClientXMLTags.MYSQL_STORE, getMySQLConnectionPoolProvider(),
                    getAssetProvider(), assetConverter));
            masp.addListener(new OA2SQLAssetStoreProvider(cn, ClientXMLTags.MARIADB_STORE, getMariaDBConnectionPoolProvider(),
                    getAssetProvider(), assetConverter));
            // and a memory store, So only if one is requested it is available.
            masp.addListener(new TypedProvider<MemoryAssetStore>(cn, ClientXMLTags.MEMORY_STORE, ClientXMLTags.ASSET_STORE) {
                @Override
                public Object componentFound(CfgEvent configurationEvent) {
                    if (checkEvent(configurationEvent)) {
                        return get();
                    }
                    return null;
                }

                @Override
                public MemoryAssetStore get() {
                    return new MemoryAssetStore(getAssetProvider());
                }
            });
        }
        return assetStoreProvider;
    }

    // Note: currently called only once, if changes we probably want to cache
    protected String getErrorPagePath() {
        return getCfgValue(ClientXMLTags.ERROR_PAGE_PATH);
    }

    // Note: currently called only once, if changes we probably want to cache
    protected String getSecret() {
        return getCfgValue(ClientXMLTags.SECRET_KEY);
    }


    // Note: currently called only once, if changes we probably want to cache
    protected String getSuccessPagePath() {
        return getCfgValue(ClientXMLTags.SUCCESS_PAGE_PATH);
    }

    // Note: currently called only once, if changes we probably want to cache
    protected String getRedirectPagePath() {
        return getCfgValue(ClientXMLTags.REDIRECT_PAGE_PATH);
    }


    // Note: currently called only once, if changes we probably want to cache
    protected boolean isShowRedirectPage() {
        String temp = getCfgValue(ClientXMLTags.SHOW_REDIRECT_PAGE);
        if (temp == null || temp.length() == 0) return false;
        return Boolean.parseBoolean(getCfgValue(ClientXMLTags.SHOW_REDIRECT_PAGE));

    }

    private Boolean requestProxies = null;
    protected boolean requestProxies() {
        if(requestProxies == null) {
            String temp = getCfgValue(ClientXMLTags.REQUEST_PROXIES);
            if (temp == null || temp.length() == 0)
                requestProxies=false;
            else
                requestProxies=Boolean.parseBoolean(getCfgValue(ClientXMLTags.REQUEST_PROXIES));
        }
        return requestProxies;
    }

    @Override
    public T createInstance() {

        Provider<TokenForge> tokenForgeProvider = new Provider<TokenForge>() {
            @Override
            public TokenForge get() {
                return new OA2TokenForge(getId());
            }
        };

        Provider<Client> clientProvider = new Provider<Client>() {
            @Override
            public Client get() {
                return new Client(BasicIdentifier.newID(getId()));
            }
        };

        // sets constants specific to this protocol.
        HashMap<String, String> constants = new HashMap<String, String>();
        constants.put(CALLBACK_URI_KEY, OA2Constants.REDIRECT_URI);
        constants.put(ClientEnvironment.FORM_ENCODING, OA2Constants.FORM_ENCODING);
        // Note: this one gets replaced by the next one. We would need
        // it for the implicit flow. In any case, there isn't a constant
        // in ClientEnvironment available.
//      constants.put(ClientEnvironment.TOKEN, OA2Constants.ACCESS_TOKEN);
        constants.put(ClientEnvironment.TOKEN, OA2Constants.AUTHORIZATION_CODE);
        // no verifier in this protocol.

        // Note: via our constructor calling LoggingConfigLoader() we've
        // already setup myLogger, and it's good to also set its debug flag
        // before calling createInstance().
        loadDebug();
        boolean debugOn = DebugUtil.isEnabled();
        myLogger.setDebugOn(debugOn);
        info("Debugging is " + (debugOn ? "on" : "off"));

        T t = createInstance(tokenForgeProvider, clientProvider, constants);
//      loadDebug();
//      t.setDebugOn(DebugUtil.isEnabled());
//      t.info("Debugging is " + (t.isDebugOn() ? "on" : "off"));
        return t;
    }

    @Override
    protected Provider<DelegationService> getDSP() {
        if (dsp == null) {
            if ( requestProxies() ) {

                dsp = new Provider<DelegationService>() {
                    @Override
                    public DelegationService get() {
                        return new DS2(new AGServer2(createServiceClient(getAuthzURI())), // as per spec, request for AG comes through authz endpoint.
                                new ATServer2(createServiceClient(getAccessTokenURI()), getWellKnownURI(), isOIDCEnabled()),
                                new PPServer2(createServiceClient(getProxyAssetURI())),
                                new UIServer2(createServiceClient(getUIURI())),
                                new RTServer2(createServiceClient(getAccessTokenURI()), getWellKnownURI(), isOIDCEnabled()) // as per spec, refresh token server is at same endpoint as access token server.
                        );
                    }
                };

            } else {

                dsp = new Provider<DelegationService>() {
                    @Override
                    public DelegationService get() {
                        return new DS2(new AGServer2(createServiceClient(getAuthzURI())), // as per spec, request for AG comes through authz endpoint.
                                new ATServer2(createServiceClient(getAccessTokenURI()), getWellKnownURI(), isOIDCEnabled()),
                                new PAServer2(createServiceClient(getAssetURI())),
                                new UIServer2(createServiceClient(getUIURI())),
                                new RTServer2(createServiceClient(getAccessTokenURI()), getWellKnownURI(), isOIDCEnabled()) // as per spec, refresh token server is at same endpoint as access token server.
                        );
                    }
                };

            }
        }
        return dsp;
    }

    // Note: currently called only once, if changes we probably want to cache
    protected URI getUIURI() {
        return createServiceURI(getCfgValue(ClientXMLTags.USER_INFO_URI), getCfgValue(ClientXMLTags.BASE_URI), USER_INFO_ENDPOINT);
    }

    // Note: currently called only once, if changes we probably want to cache
    protected URI getAuthzURI() {
        return createServiceURI(getCfgValue(ClientXMLTags.AUTHORIZE_TOKEN_URI), getCfgValue(ClientXMLTags.BASE_URI), AUTHORIZE_ENDPOINT);
    }
    protected URI getRevocationURI() {
        return createServiceURI(getCfgValue(ClientXMLTags.REVOCATION_URI), getCfgValue(ClientXMLTags.BASE_URI), AUTHORIZE_ENDPOINT);
    }
    @Override
    public HashMap<String, String> getConstants() {
        throw new NotImplementedException("Error: This method is not implemented.");
    }
}
