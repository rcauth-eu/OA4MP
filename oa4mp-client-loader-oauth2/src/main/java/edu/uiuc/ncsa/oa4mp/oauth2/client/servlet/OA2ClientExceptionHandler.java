package edu.uiuc.ncsa.oa4mp.oauth2.client.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientExceptionHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2RedirectableError;
import edu.uiuc.ncsa.security.servlet.JSPUtil;
import edu.uiuc.ncsa.security.servlet.ServiceClientHTTPException;
import net.sf.json.JSONObject;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Set;
import java.util.StringTokenizer;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/12/15 at  1:16 PM
 */
public class OA2ClientExceptionHandler extends ClientExceptionHandler {

    public OA2ClientExceptionHandler(ClientServlet clientServlet, MyLoggingFacade myLogger) {
        super(clientServlet, myLogger);
    }

    @Override
    public void handleException(Throwable t, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        if (t instanceof OA2RedirectableError) {
            OA2RedirectableError oa2RedirectableError = (OA2RedirectableError) t;
            getLogger().warn("Got redirectable error: " + oa2RedirectableError.getMessage() +
                    ", error=" + oa2RedirectableError.getError() +
                    ", description=" + oa2RedirectableError.getDescription() +
                    ", state=" + oa2RedirectableError.getState());
            request.setAttribute(OA2Constants.ERROR, oa2RedirectableError.getError());
            request.setAttribute(OA2Constants.ERROR_DESCRIPTION, oa2RedirectableError.getDescription());
            request.setAttribute(OA2Constants.STATE, oa2RedirectableError.getState());
        } else if (t instanceof ServiceClientHTTPException) {
            // This can be thrown by the service client when a bad response comes back from the server.
            // If there really is server problem, this tries to get a human readable error page.
            // parse the body. It should be of the form
            // error=....
            // error_description=...
            // separated by a line feed.
            ServiceClientHTTPException tt = (ServiceClientHTTPException) t;
            getLogger().warn(t.getClass().getSimpleName() + ": " + t.getMessage() + ", http status code = " + tt.getStatus());

            if (!tt.hasContent()) {
                // can't do anything
                defaultSCXresponse(tt, request);
            } else {
                try {
                    parseContent(tt.getContent(), request);
                } catch (GeneralException xx) {
                    defaultSCXresponse(tt, request);
                }
            }
        } else {
            // fall through. We got some exception from someplace and have to manage it.
            // This is really last ditch.
            getLogger().warn(t.getClass().getSimpleName() + ": " + t.getMessage());
            logStackTrace(t); // again, something is wrong, possibly with the configuration so more info is better.
            request.setAttribute(OA2Constants.ERROR, t.getClass().getSimpleName());
            request.setAttribute(OA2Constants.ERROR_DESCRIPTION, t.getMessage());
        }

        // Note: we might want to distinguish between failures, especially in case of ServiceClientHTTPException,
        // but that is hard and in practise we just return the client-error.jsp
        response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        request.setAttribute("action", getNormalizedContextPath());  // sets return action on error page to this web app.
        getLogger().debug("Forwarding to "+clientServlet.getCE().getErrorPagePath());
        JSPUtil.fwd(request, response, clientServlet.getCE().getErrorPagePath());
    }

    /**
     * logs the stacktrace on error level to the logger.
     * @param t Throwable that is being handled
     */
    private void logStackTrace(Throwable t) {
        StringWriter errors = new StringWriter();
        t.printStackTrace(new PrintWriter(errors));
        getLogger().error(errors.toString());
    }

    /**
     * This will parse the standard error response from an OIDC server.
     * It will try to figure out whether the content looks like an HTML response,
     * a JSON response or other and parse accordingly.
     *
     * @param content server response.
     * @param request request to be sent to the error page.
     */
    protected void parseContent(String content, HttpServletRequest request) {
        // Content is either HTML page with lines KEY: "VALUE" or it's a json
        // This will take the payload and parse it as follows. The assumption is that it is of the form
        // X0=Y0
        // X1=Y1
        // X2=Y2
        // etc. where X's are standard OIDB error indicators (e.g. error_description, state) and Y's are the value
        // These are set in the response as attributes, so there is no limit on them.
        boolean hasValidContent = false;
        if (content.startsWith("{")) {
            // Looks like a JSON, try to parse as such
            JSONObject errObject = JSONObject.fromObject(content);
            // put the key/values in request, they will be used on the error page
            Set hset = errObject.keySet();
            for (Object obj : hset) {
                if (obj instanceof String) {
                    String key = (String) obj;
                    // Note: JSON error description is plain text, not URLEncoded
                    request.setAttribute(key, errObject.get(key).toString());
                    hasValidContent = true; // we manage to parse at least one key
                }
            }
        } else {
            if (! content.startsWith("<html>")) {
                // Neither HTML nor JSON, should not happen. Will still try to parse as HTML
                getLogger().warn("Server response has unknown content type, will try to parse.");
            }
            // Parse as HTML page: look for lines without htmltag, then KEY: "VALUE"
            StringTokenizer st = new StringTokenizer(content, "\n");
            while (st.hasMoreElements()) {
                String currentLine = st.nextToken();
                if (currentLine.startsWith("<")) // skip lines with HTML tags
                    continue;

                StringTokenizer clST = new StringTokenizer(currentLine, ": ");
                if (!clST.hasMoreTokens() || clST.countTokens() != 2)
                    continue;

                String key = clST.nextToken();
                String val = clST.nextToken();
                // value is normally put between with "
                if (val.startsWith("\"") && val.endsWith("\""))
                    val = val.substring(1, val.length()-1);

                try {
                    // Note: values are urlencoded in this case (to prevent issues with newlines and the like)
                    // Add URLdecoded value
                    request.setAttribute(key, URLDecoder.decode(val, "UTF-8").replaceAll("\n", ", "));
                } catch (UnsupportedEncodingException xx) {
                    // ok, try it without decoding it. (This case should never really happen)
                    request.setAttribute(key, val);
                }
                hasValidContent = true;
            }
        }

        if (!hasValidContent) {
            getLogger().warn("Body or error was not parseable, raw response = \"" + content + "\"");
            throw new GeneralException();
        }
    }

    /**
     * Used in cases the response from the server cannot be parsed.
     *
     * @param tt
     * @param request
     */
    protected void defaultSCXresponse(ServiceClientHTTPException tt, HttpServletRequest request) {
        request.setAttribute(OA2Constants.ERROR, tt.getClass().getSimpleName());
        // When the HTTP status is 0 this is probably not caused by a remote service error
        if (tt.getStatus()>0)
            request.setAttribute(OA2Constants.ERROR_DESCRIPTION, "Status code=" + tt.getStatus() + ", message=\"" + tt.getMessage() + "\"");
        else
            request.setAttribute(OA2Constants.ERROR_DESCRIPTION, tt.getMessage());
        // Don't set the state parameter as we don't have it in any case:
        // it's mandatory when the client sends it, but then must be the value send by the client
        //request.setAttribute(OA2Constants.STATE, "(none)");

    }
}
