<%--
  User: Jeff Gaynor
  Date: May 27, 2011
  Time: 10:36:41 AM
  Properties included:
     field names:
        * clientName
        * clientEmail
        * clientHomeUrl
        * clientErrorUrl
        * clientPublicKey
        * action
        * request
     Control flow:
        * actionToTake = url to invoke on submitting this form
        * action = name of hidden field containing the request property
        * request = contents of field with the state of this
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ include file="assets/includes/start.html" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<form action="/oidc2fca/register" method="post">
    <p>NCSA Two Factor OAuth Client Registration Form</p>

    <p> This page allows you to register your NCSA Two Factor
        OAuth client.
        Your request will be evaluated for approval. For more information,
        please make sure you read the
        <a href="http://grid.ncsa.illinois.edu/myproxy/oauth/client/manuals/registering-with-a-server.xhtml"
           target="_blank">Client Registration Document</a>.
    </p>

    <table>
        <tr>
            <td>Client Name:</td>
            <td><input type="text" size="25" name="${clientName}" value="${clientNameValue}"/></td>
        </tr>
        <tr>
            <td>Contact email:</td>
            <td><input type="text" size="25" name="${clientEmail}" value="${clientEmailValue}"/></td>
        </tr>
        <tr>
            <td>Home URL:</td>
            <td><input type="text" size="25" name="${clientHomeUrl}" value="${clientHomeUrlValue}"/></td>
        </tr>
        <tr>
            <td>Callback URLs:</td>
            <td>
                    <textarea id="${callbackURI}" rows="10" cols="80"
                              name="${callbackURI}">${callbackURIValue}</textarea>
            </td>
        </tr>
        <tr>
            <td>Scopes:</td>
            <td>
                <c:forEach items="${scopes}" var="scope">
                    <input type="checkbox"
                           name="chkScopes"
                           value="${scope}"
                        <c:set var="xxx" scope="session" value="${scope}"/>
                           <c:if test="${xxx == 'openid'}">checked="checked"</c:if>
                            >${scope}&nbsp;
                </c:forEach>
            </td>
        </tr>
        <tr>
            <td ${rtFieldVisible}>Refresh Token lifetime:</td>
            <td ${rtFieldVisible}><input type="text" size="25" name="${rtLifetime}" value="${rtLifetimeValue}"/>(in
                seconds - leave blank for no refresh tokens.)
            </td>
        </tr>
        <tr>
            <td>Issuer (optional):</td>
            <td><input type="text" size="25" name="${issuer}" value="${issuerValue}"/></td>
        </tr>
        <tr>
            <td><input type="submit" value="submit"/></td>
        </tr>
        <tr>
            <td colspan="2"><b><font color="red">${retryMessage}</font></b></td>
        </tr>
    </table>
    <input type="hidden" id="status" name="${action}"
           value="${request}"/>
</form>

<%@ include file="assets/includes/end.html" %>
