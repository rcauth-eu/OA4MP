package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.UnknownClientException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.ExceptionWrapper;
import edu.uiuc.ncsa.security.delegation.server.UnapprovedClientException;
import edu.uiuc.ncsa.security.oauth_2_0.*;
import edu.uiuc.ncsa.security.servlet.ExceptionHandler;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/12/15 at  3:16 PM
 */
public class OA2ExceptionHandler implements ExceptionHandler {
    MyLoggingFacade logger;

    @Override
    public MyLoggingFacade getLogger() {
        return logger;
    }

    public OA2ExceptionHandler(MyLoggingFacade logger) {
        this.logger = logger;
    }

    @Override
    public void handleException(Throwable t, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        if (t instanceof ExceptionWrapper) {
            // In this case we are getting this as a response after a forward to another servlet and have to unpack it.
            t = t.getCause();
        }

        if (t == null) {
            // really messed up, should never ever happen
            t = new OA2GeneralError(OA2Errors.SERVER_ERROR, "Internal error", HttpStatus.SC_INTERNAL_SERVER_ERROR);
            logger.error("Error: Throwable is null");
            logStackTrace(t);
        }

        // Log the message as warning
        logger.warn(t.getClass().getSimpleName() + ": " + t.getMessage());

        // If there is really a servlet exception (defined as a bonafide unrecoverable state, like storage is down or
        // no client_id, e.g.) then pass back the servlet exception and let the container handle it. At some point we might just
        // want to have a pretty page for this.
        if (t instanceof ServletException) {
            logStackTrace(t);
            response.setStatus(500);
            throw (ServletException) t;
        }

        if (t instanceof OA2GeneralError) {
            handleOA2Error((OA2GeneralError) t, response);
            return;
        }

        if(t instanceof OA2ATException){
            handleOA2Error((OA2ATException)t, response);
            return;
        }
        if (t instanceof OA2RedirectableError) {
            handleOA2Error((OA2RedirectableError) t, response);
            return;
        }
        // The next couple of exceptions can be thrown when there is no client (so the callback uri cannot be verified
        if ((t instanceof UnknownClientException) || (t instanceof UnapprovedClientException)) {
            // Even though we cannot verify the callback, that is also not going
            // to be used here, since we call handleOA2Error(OA2GeneralError, HttpServletResponse), see below
            handleOA2Error(new OA2GeneralError(OA2Errors.INVALID_REQUEST, t.getMessage(), HttpStatus.SC_BAD_REQUEST), response);
            return;
        }
        // Typically can be thrown when some required arguments are missing
        if (t instanceof IllegalArgumentException) {
            logStackTrace(t);
            handleOA2Error(new OA2GeneralError(OA2Errors.INVALID_REQUEST, t.getMessage(), HttpStatus.SC_BAD_REQUEST), response);
            return;
        }
        if (t instanceof GeneralException) {
            logStackTrace(t);
            handleOA2Error(new OA2GeneralError(OA2Errors.SERVER_ERROR, t.getMessage(), HttpStatus.SC_INTERNAL_SERVER_ERROR), response);
            return;
        }
        // If we're here we received another type of exception.
        logStackTrace(t);
        handleOA2Error(new OA2GeneralError(OA2Errors.SERVER_ERROR, "Got unexpected exception", HttpStatus.SC_INTERNAL_SERVER_ERROR), response);
    }

    /**
     * logs the stacktrace on error level to the logger.
     * @param t Throwable that is being handled
     */
    private void logStackTrace(Throwable t) {
        StringWriter errors = new StringWriter();
        t.printStackTrace(new PrintWriter(errors));
        logger.error(errors.toString());
    }

    protected String encode(String x) throws UnsupportedEncodingException {
        return URLEncoder.encode(x, "UTF-8");
    }

    /**
     * Handles errors of type {@link OA2GeneralError}, which are intended to be human-readable.
     * NOTE: if the format here changes, the parsing in
     * edu.uiuc.ncsa.oa4mp.oauth2.client.servlet.OA2ClientExceptionHandler needs changing too.
     * @param oa2GeneralError exception to handle
     * @param response response to be returned to the client
     * @throws IOException in case of write errors
     * @see #handleException(Throwable, HttpServletRequest, HttpServletResponse)
     */
    protected void handleOA2Error(OA2GeneralError oa2GeneralError, HttpServletResponse response) throws IOException {
        response.setStatus(oa2GeneralError.getHttpStatus());
        response.setHeader("Content-Type", "text/html;charset=UTF-8");
        PrintWriter writer = response.getWriter();
        writer.println("<html>\n<title>Server Error</title>\n<h1>Server Error</h1>");
        writer.println(OA2Constants.ERROR + ": \"" + encode(oa2GeneralError.getError()) + "\"\n<br>");
        writer.println(OA2Constants.ERROR_DESCRIPTION + ": \"" + encode(oa2GeneralError.getDescription()) + "\"\n<br>");
        writer.println("</html>");
        writer.flush();
        writer.close();
    }

    // Fix for CIL-332: This should now send JSON with the correct http status.
    /**
     * Handles errors of type {@link OA2ATException}, which are intended to be human-readable.
     * NOTE: if the format here changes, the parsing in
     * edu.uiuc.ncsa.oa4mp.oauth2.client.servlet.OA2ClientExceptionHandler needs changing too.
     * @param oa2ATException exception to handle
     * @param response response to be returned to the client
     * @throws IOException in case of write errors
     * @see #handleException(Throwable, HttpServletRequest, HttpServletResponse)
     */
    protected void handleOA2Error(OA2ATException oa2ATException, HttpServletResponse response) throws IOException {
        response.setStatus(oa2ATException.getStatusCode());
        response.setHeader("Content-Type", "application/json;charset=UTF-8");
        JSONObject jsonObject = new JSONObject();
        jsonObject.put(OA2Constants.ERROR, oa2ATException.getError());
        jsonObject.put(OA2Constants.ERROR_DESCRIPTION, oa2ATException.getDescription());
        PrintWriter writer = response.getWriter();

        writer.write(jsonObject.toString());
        writer.flush();
        writer.close();
    }

    protected void handleOA2Error(OA2RedirectableError oa2RedirectableError, HttpServletResponse response) throws IOException {
        // Fixes OAUTH-174, better handling of errors on the server side, making it all spec. compliant.
        if (oa2RedirectableError.getCallback() == null) {
            // Except here, since there is no callback possible if it is not included in the first place.
            //    throw new IllegalStateException("No callback has been specified in the request. Cannot process error notification.");
            // Convert to a general error
            handleOA2Error(new OA2GeneralError(oa2RedirectableError), response);
            return;
        }
        // Check is the response has been wrapped in a helper class and do a wee bit of management on said class.
        OA2AuthorizationServer.MyHttpServletResponseWrapper wrapper = null;
        if (response instanceof OA2AuthorizationServer.MyHttpServletResponseWrapper) {
            wrapper = (OA2AuthorizationServer.MyHttpServletResponseWrapper) response;
            // set this so that other components know a redirect occurred and can handle that themselves (usually by just returning).
            wrapper.setExceptionEncountered(true);
        }
        String cb = oa2RedirectableError.getCallback().toString();
        boolean hasQM = (0 < cb.indexOf("?")); // CIL-407 FIX
        cb = cb + (hasQM?"&":"?") + OA2Constants.ERROR + "=" + oa2RedirectableError.getError() + "&" +
                URLEncoder.encode(OA2Constants.ERROR_DESCRIPTION, "UTF-8") + "=" +
                URLEncoder.encode(oa2RedirectableError.getDescription(), "UTF-8");
        //CIL-312 fix.
        String state = oa2RedirectableError.getState();
        state = state == null ? "" : state;
        cb = cb + "&" + OA2Constants.STATE + "=" + URLEncoder.encode(state, "UTF-8");

        // It is possible that there is no state, in which case, the state variable will be null and you will get and NPE
        // from the encoder. Return empty state if there was none.
        response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
        response.sendRedirect(cb);
        return;
    }
}
