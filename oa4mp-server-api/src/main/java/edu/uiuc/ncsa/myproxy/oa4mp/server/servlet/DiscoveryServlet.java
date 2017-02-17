package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import net.sf.json.JSONObject;
import net.sf.json.util.JSONUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/12/16 at  1:04 PM
 */
public class DiscoveryServlet extends MyProxyDelegationServlet {

    public static final String AUTHORIZATION_ENDPOINT = "authorization_endpoint";
    public static final String REGISTRATION_ENDPOINT = "registration_endpoint";
    public static final String DISCOVERY_PATH = ".well-known";

    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        throw new NotImplementedException("Not implemented in discovery");
    }

    public String getDiscoveryPagePath() {
        return discoveryPagePath;
    }

    public void setDiscoveryPagePath(String discoveryPagePath) {
        this.discoveryPagePath = discoveryPagePath;
    }

    protected String discoveryPagePath = "/well-known.jsp";

    protected JSONObject setValues(HttpServletRequest httpServletRequest, JSONObject jsonObject) {
        if (jsonObject == null) {
            jsonObject = new JSONObject();
        }
        String requestURI = getRequestURI(httpServletRequest);
        if (!isEmpty(getServiceEnvironment().getAuthorizationServletConfig().getAuthorizationURI())) {
            jsonObject.put(AUTHORIZATION_ENDPOINT, getServiceEnvironment().getAuthorizationServletConfig().getAuthorizationURI());
        } else {
            jsonObject.put(AUTHORIZATION_ENDPOINT, requestURI + "/authorize");
        }
        jsonObject.put(REGISTRATION_ENDPOINT, requestURI + "/register");
        return jsonObject;
    }

    @Override
    protected void doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        JSONObject jsonObject = new JSONObject();
        jsonObject = setValues(httpServletRequest, jsonObject);
        String out = JSONUtils.valueToString(jsonObject, 1, 0);
        httpServletResponse.setHeader("Content-Type", "application/json;charset=UTF-8");
        PrintWriter printWriter = httpServletResponse.getWriter();
        printWriter.write(out);
        printWriter.close();
        printWriter.flush();
        //httpServletRequest.setAttribute(DISCOVERY_CONTENT, out);
        //JSPUtil.fwd(httpServletRequest, httpServletResponse, getDiscoveryPagePath());
    }
    protected static String getRequestURI(HttpServletRequest request, boolean includePort) {
        int port=request.getServerPort();
        String scheme=request.getScheme();
        String requestURI;
        // Don't add port when we use a default port
        if ( (includePort==false) ||
             (scheme.equals("https") && port==443) ||
             (scheme.equals("http")  && port==80) )
        {
            requestURI =   scheme + "://" + request.getServerName() + request.getRequestURI();
        } else {
            requestURI =   scheme + "://" + request.getServerName() + ":" + port + request.getRequestURI();
        }
        // Strip off request.getServletPath() from requestURI.
        // NOTE: getServletPath() is typically the endpoint as
        // defined in web.xml, so not per se at the end of the URI.
        String servletPath=request.getServletPath();
        if (servletPath.length()>0 && requestURI.endsWith(servletPath)) {
            requestURI = requestURI.substring(0, requestURI.length()-servletPath.length());
        }
        // Also need to strip off trailing /
        if (requestURI.endsWith("/")) {
            requestURI = requestURI.substring(0, requestURI.length() - 1);
        }
        if (0 < requestURI.indexOf("/token")) {
            // Strip off /token which is end of requestURI for getting claims
            requestURI = requestURI.substring(0, requestURI.indexOf("/token"));
        } else if (0 < requestURI.indexOf("/.well-known")) {
            // Strip off /.well-known.
            // NOTE that this would be the servletPath, but not typically at
            // the end of the URI (e.g. followed by openid-configuration)
            requestURI = requestURI.substring(0, requestURI.indexOf("/.well-known"));
        }
        return requestURI;
    }
    protected static String getRequestURI(HttpServletRequest request) {
        return getRequestURI(request, true);
    }
}
