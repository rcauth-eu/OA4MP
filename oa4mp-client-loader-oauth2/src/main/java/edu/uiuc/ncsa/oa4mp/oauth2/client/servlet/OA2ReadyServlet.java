package edu.uiuc.ncsa.oa4mp.oauth2.client.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.client.AssetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientEnvironment;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2MPService;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.impl.AuthorizationGrantImpl;
import edu.uiuc.ncsa.security.oauth_2_0.*;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATResponse2;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATServer2;
import edu.uiuc.ncsa.security.servlet.JSPUtil;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import edu.uiuc.ncsa.security.util.pkcs.KeyUtil;
import net.sf.json.JSONObject;
import net.sf.json.util.JSONUtils;
import org.apache.commons.codec.binary.Base64;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.security.cert.X509Certificate;

/**
 * A very, very simple (as in stupid) ready servlet. This is the target of the callback uri supplied in
 * the initial request. <br><br>This example is intended to show control flow rather than be a polished application.
 * Feel free to boilerplate from it as needed. Do not deploy this in production environments.
 * <p>Created by Jeff Gaynor<br>
 * <p/>
 * on 2/10/12 at  1:43 PM
 */

public class OA2ReadyServlet extends ClientServlet {
    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        if (request.getParameterMap().containsKey(OA2Constants.ERROR)) {
            throw new OA2RedirectableError(request.getParameter(OA2Constants.ERROR),
                    request.getParameter(OA2Constants.ERROR_DESCRIPTION),
                    request.getParameter(OA2Constants.STATE));
        }
        // Get the cert itself. The server itself does a redirect using the callback to this servlet
        // (so it is the portal that actually is invoking this method after the authorization
        // step.) The token and verifier are peeled off and used
        // to complete the request.
        info("2.a. Getting token and verifier.");
        String token = request.getParameter(CONST(ClientEnvironment.TOKEN));
        String state = request.getParameter(OA2Constants.STATE);
        if (token == null) {
            warn("2.a. The token is " + (token == null ? "null" : token) + ".");
            GeneralException ge = new GeneralException("Error: This servlet requires parameters for the token and possibly verifier.");
            request.setAttribute("exception", ge);
            JSPUtil.fwd(request, response, getCE().getErrorPagePath());
            return;
        }
        info("2.a Token found.");
        OA2ClientEnvironment oa2ce = (OA2ClientEnvironment) getCE();

        AuthorizationGrant grant = new AuthorizationGrantImpl(URI.create(token));
        info("2.a. Getting the cert(s) from the service");
        String identifier = clearCookie(request, response);
        OA2Asset asset = null;
        if (identifier == null) {
            asset = (OA2Asset) getCE().getAssetStore().getByToken(BasicIdentifier.newID(token));
            if (asset != null) {
                identifier = asset.getIdentifierString();
            }
        }
        AssetResponse assetResponse = null;
        OA2MPService oa2MPService = (OA2MPService) getOA4MPService();
        String rawAT = null;
        UserInfo ui = null;
        boolean getCerts = (oa2ce).getScopes().contains(OA2Scopes.SCOPE_MYPROXY);
        if (identifier == null) {
            // Since this is a demo servlet, we don't blow up if there is no identifier found, just can't save anything.
            String msg = "Error: no cookie found. Cannot save certificates";
            warn(msg);
            debug("No cookie found");
            //if(asset == null) asset = new OA2Asset(BasicIdentifier.newID())
            ATResponse2 atResponse2 = oa2MPService.getAccessToken(asset, grant);
            rawAT = atResponse2.getAccessToken().getToken(); // save it here since we have it
            ui = oa2MPService.getUserInfo(atResponse2.getAccessToken().toString());
            if (getCerts) {
                assetResponse = oa2MPService.getCert(asset, atResponse2);
            }
        } else {
            asset = (OA2Asset) getCE().getAssetStore().get(identifier);
            if (asset.getState() == null || !asset.getState().equals(state)) {
                // Just a note: This is most likely to arise when the server's authorize-init.jsp has been
                // changed or replaced and the hidden field for the state (passed to the form, then passed back
                // and therefore not stored on the server anyplace) is missing.
                warn("The expected state from the server was \"" + asset.getState() + "\", but instead \"" + state + "\" was returned. Transaction aborted.");
                throw new IllegalArgumentException("Error: The state returned by the server is invalid.");
            }
            ATResponse2 atResponse2 = oa2MPService.getAccessToken(asset, grant);
            rawAT = atResponse2.getAccessToken().getToken(); // save it here since we have it

            //  ui = oa2MPService.getUserInfo(atResponse2.getAccessToken().getToken());
            ui = oa2MPService.getUserInfo(identifier);
            if (getCerts) {
                assetResponse = oa2MPService.getCert(asset, atResponse2);
            }
            // The general case is to do the call with the identifier if you want the asset store managed.
            //assetResponse = getOA4MPService().getCert(token, null, BasicIdentifier.newID(identifier));
        }
        ServletDebugUtil.trace(this,"show ID token? " + oa2ce.isShowIDToken());
        // Now to display the id token. This only exists if this is an OIDC server, so that is a requirement here.
        if (oa2ce.isOidcEnabled() && oa2ce.isShowIDToken()) {

            ATServer2 atServer2 = (ATServer2) oa2ce.getDelegationService().getAtServer();

            JSONWebKeys jsonWebKeys = atServer2.getJsonWebKeys();
            ServletDebugUtil.trace(this, "JSON webkeys = " + jsonWebKeys);
            // So this client is to show the information for the ID Token. Since this is extra, we have to recover it.

            ServletDebugUtil.trace(this, "ID Token store = " + ATServer2.getIDTokenStore());
            ServletDebugUtil.trace(this, "ID Token store size = "  + ATServer2.getIDTokenStore().size());
            ServletDebugUtil.trace(this, "ID Token store contains key \"" + rawAT + "\"? " + ATServer2.getIDTokenStore().containsKey(rawAT));


            ATServer2.IDTokenEntry tokenEntry = ATServer2.getIDTokenStore().get(rawAT);
            ServletDebugUtil.trace(this, "TokenEntry = " + tokenEntry);

            setJWTInfo(request, tokenEntry.rawToken, jsonWebKeys);

        }else{
            setJWTInfo(request, null, null); // sets the fields to "(none)"

        }
        // Again, we take the first returned cert to peel off some information to display. This
        // just proves we got a response.

        info("2.b. Done! Displaying success page.");
        if (getCerts) {
            if (assetResponse.getX509Certificates() == null) {
                request.setAttribute("certSubject", "(no cert returned)");
            } else {
                X509Certificate cert = assetResponse.getX509Certificates()[0];
                // Rest of this is putting up something for the user to see
                request.setAttribute("certSubject", cert.getSubjectDN());
                request.setAttribute("cert", CertUtil.toPEM(assetResponse.getX509Certificates()));
                request.setAttribute("username", assetResponse.getUsername());
                // FIX OAUTH-216. Note that this is displayed on the client's success page.
                if (asset.getPrivateKey() != null) {
                    request.setAttribute("privateKey", KeyUtil.toPKCS1PEM(asset.getPrivateKey()));
                } else {
                    request.setAttribute("privateKey", "(none)");
                }

            }
        } else {
            request.setAttribute("certSubject", "(no cert requested)");
        }

        if (ui != null) {
            String output = JSONUtils.valueToString(ui.toJSon(), 1, 0);
            request.setAttribute("userinfo", output);
        } else {
            request.setAttribute("userinfo", "no user info returned.");
        }
        // Fix in cases where the server request passes through Apache before going to Tomcat.

        String contextPath = request.getContextPath();
        if (!contextPath.endsWith("/")) {
            contextPath = contextPath + "/";
        }
        request.setAttribute("action", contextPath);
        info("2.a. Completely finished with delegation.");


        response.setCharacterEncoding("UTF-8");
        JSPUtil.fwd(request, response, getCE().getSuccessPagePath());
        return;
    }

    protected void setJWTInfo(HttpServletRequest request, String rawJWT, JSONWebKeys jsonWebKeys) {
        if (rawJWT == null || rawJWT.isEmpty()) {
            request.setAttribute("id_token", "(none)");
        } else {
            String[] atParts = JWTUtil.decat(rawJWT);
            String h = atParts[JWTUtil.HEADER_INDEX];
            JSONObject header = null;

            String p = atParts[JWTUtil.PAYLOAD_INDEX];
            header = JSONObject.fromObject(new String(Base64.decodeBase64(h)));

            JSONObject payload = JSONObject.fromObject(new String(Base64.decodeBase64(p)));
            request.setAttribute("id_token", rawJWT);
            request.setAttribute("id_payload", payload.toString(2));

            request.setAttribute("id_header", header.toString(2));
            JSONWebKey webKey = jsonWebKeys.get(header.get(JWTUtil.KEY_ID));
            String keyPEM = KeyUtil.toX509PEM(webKey.publicKey);
            request.setAttribute("id_public_key", keyPEM);

        }
    }
}
