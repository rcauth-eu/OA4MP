package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;


import edu.uiuc.ncsa.myproxy.MPSingleConnectionProvider;
import edu.uiuc.ncsa.myproxy.MyProxyConnectable;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.OA2ClaimsUtil;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractAuthorizationServlet;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.servlet.PresentableState;
import net.sf.json.JSONObject;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.Map;

import static org.apache.commons.lang.StringEscapeUtils.escapeHtml;


/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/7/14 at  11:44 AM
 */
public class OA2AuthorizationServer extends AbstractAuthorizationServlet {
    @Override
    protected AccessToken getAccessToken(HttpServletRequest request) {
        throw new NotImplementedException("No access token is available");
    }

    public String AUTHORIZATION_REFRESH_TOKEN_LIFETIME_KEY = "AuthRTL";
    public String AUTHORIZED_ENDPOINT = "/authorized";
    public String AUTHORIZATION_REFRESH_TOKEN_LIFETIME_VALUE = "rtLifetime";

    protected String scopesToString(OA2ServiceTransaction t){
        String scopeString = "";
        for(String x : t.getScopes()){
            scopeString = scopeString + x + " ";
        }
        return scopeString;

    }
    @Override
    protected void setClientRequestAttributes(AuthorizedState aState) {
        super.setClientRequestAttributes(aState);
        HttpServletRequest request = aState.getRequest();

        OA2ServiceTransaction t = (OA2ServiceTransaction) aState.getTransaction();
        request.setAttribute("clientScopes", escapeHtml(scopesToString(t)));

    }

    /**
     * This class is needed to pass information between servlets, where one servlet
     * calls another.
     */
    static class MyHttpServletResponseWrapper
            extends HttpServletResponseWrapper {

        private StringWriter sw = new StringWriter();

        public MyHttpServletResponseWrapper(HttpServletResponse response) {
            super(response);
        }

        int internalStatus = 0;

        @Override
        public void setStatus(int sc) {
            internalStatus = sc;
            super.setStatus(sc);
            if (!(200 <= sc && sc < 300)) {
                setExceptionEncountered(true);
            }
        }


        public int getStatus() {
            return internalStatus;
        }

        public PrintWriter getWriter() throws IOException {
            return new PrintWriter(sw);
        }

        public ServletOutputStream getOutputStream() throws IOException {
            throw new UnsupportedOperationException();
        }

        public String toString() {
            return sw.toString();
        }

        /**
         * If in the course of processing an exception is encountered, set this to be true. This class
         * is made to be passed between servlets and the results harvested, but if one of the servlets encounters
         * an exception, that is handled with a redirect (in OAuth 2) so nothing ever gets propagated back up the
         * stack to show that. This should be checked to ensure that did not happen.
         *
         * @return
         */
        boolean isExceptionEncountered() {
            return exceptionEncountered;
        }

        void setExceptionEncountered(boolean exceptionEncountered) {
            this.exceptionEncountered = exceptionEncountered;
        }

        boolean exceptionEncountered = false;
    }

    protected OA2AuthorizedServletUtil getInitUtil() {
        return new OA2AuthorizedServletUtil(this);
    }

    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        //printAllParameters(request);

        Map<String, String> map = getFirstParameters(request);

        if (map.containsKey(OA2Constants.RESPONSE_TYPE)) {
            // Means this is an initial request. Pass it along to the init util to
            // unscramble it.
            MyHttpServletResponseWrapper wrapper = new MyHttpServletResponseWrapper(response);
            OA2AuthorizedServletUtil init = getInitUtil();
//              JSPUtil.fwd(request, wrapper, AUTHORIZED_ENDPOINT);
            init.doDelegation(request, wrapper);
            if (wrapper.isExceptionEncountered()) {
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, wrapper.toString(), wrapper.getStatus());
            } // something happened someplace else and the exception was handled.
            String content = wrapper.toString();
            // issue now is that the nonce was registered in the init servlet (as it should be for OA1)
            // and now it will be rejected ever more.
            JSONObject j = JSONObject.fromObject(content);
            // protect against null code and state!!
            Object code = j.get("code");
            if (code != null)
                request.setAttribute("code", code.toString());
            Object state = j.get("state");
            if (state != null)
                request.setAttribute("state", state.toString());
        }
        super.doIt(request, response);

    }


    @Override
    public void prepare(PresentableState state) throws Throwable {
        super.prepare(state);
        if (state.getState() == AUTHORIZATION_ACTION_START) {
            state.getRequest().setAttribute(AUTHORIZATION_REFRESH_TOKEN_LIFETIME_KEY, AUTHORIZATION_REFRESH_TOKEN_LIFETIME_KEY);
        }
        if (state.getState() == AUTHORIZATION_ACTION_OK) {
            AuthorizedState authorizedState = (AuthorizedState) state;
            ((OA2ServiceTransaction) authorizedState.getTransaction()).setAuthTime(new Date());

        }
    }


    @Override
    public void present(PresentableState state) throws Throwable {
        super.present(state);

    }

    @Override
    protected void createRedirect(HttpServletRequest request, HttpServletResponse response, ServiceTransaction trans) throws Throwable {
        String rawrtl = request.getParameter(AUTHORIZATION_REFRESH_TOKEN_LIFETIME_KEY);
        OA2ServiceTransaction st2 = (OA2ServiceTransaction) trans;
        try {
            if (rawrtl != null) {
                st2.setRefreshTokenLifetime(Long.parseLong(rawrtl) * 1000);
            }
        } catch (Throwable t) {
            st2.setRefreshTokenLifetime(0L);
        }
        super.createRedirect(request, response, trans);
        // At this point, all authentication has been done, everything is set up and the next stop in the flow is the
        // redirect back to the client.
        OA2ClaimsUtil claimsUtil = new OA2ClaimsUtil((OA2SE) getServiceEnvironment(), st2);
        claimsUtil.createBasicClaims(request, (OA2ServiceTransaction) trans);
    }

    @Override
    public String createCallback(ServiceTransaction trans, Map<String, String> params) {

        String cb = trans.getCallback().toString();
        URI uri= URI.create(cb);
        // Only allow non-https for localhost
        if (!uri.getScheme().toLowerCase().equals("https") && !uri.getHost().toLowerCase().equals("localhost")) {
            throw new GeneralException("Error: Unsupported callback protocol for \"" + cb + "\". Must be https");
        }
        String idStr = trans.getIdentifierString();
        try {
            cb = cb + (cb.indexOf("?") == -1 ? "?" : "&") + OA2Constants.AUTHORIZATION_CODE + "=" + URLEncoder.encode(idStr, "UTF-8");
            if (params.containsKey(OA2Constants.STATE)) {
                cb = cb + "&" + OA2Constants.STATE + "=" + URLEncoder.encode(params.get(OA2Constants.STATE), "UTF-8");
            }

        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return cb;
    }

    /**
     * Spec says we do the cert request in the authorization servlet.
     *
     * @param trans
     * @param statusString
     * @throws Throwable
     */
    @Override
    protected void doRealCertRequest(ServiceTransaction trans, String statusString) throws Throwable {
        // do nix here in this protocol.

    }


    @Override
    protected void setupMPConnection(ServiceTransaction trans, String username, String password) throws GeneralSecurityException {
        if (((OA2SE) getServiceEnvironment()).isTwoFactorSupportEnabled()) {
            // Stash username and password in an bogus MyProxy logon instance.
            MyMyProxyLogon myProxyLogon = new MyMyProxyLogon();
            myProxyLogon.setUsername(username);
            myProxyLogon.setPassphrase(password);
            MyProxyConnectable mpc = new MPSingleConnectionProvider.MyProxyLogonConnection(myProxyLogon);
            mpc.setIdentifier(trans.getIdentifier());
            getMyproxyConnectionCache().add(mpc);
        } else {
            createMPConnection(trans.getIdentifier(), username, password, trans.getLifetime());
            if (hasMPConnection(trans.getIdentifier())) {
                getMPConnection(trans.getIdentifier()).close();
            }
        }
    }
}

