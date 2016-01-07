package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.myproxy.MPConnectionProvider;
import edu.uiuc.ncsa.myproxy.MyProxyConnectable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.ConnectionException;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.MyX509Certificates;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import edu.uiuc.ncsa.security.util.pkcs.MyPKCS10CertRequest;
import edu.uiuc.ncsa.security.util.pkcs.ProxyUtil;

import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedList;

/**
 * This is the super class of the servlet that is supposed to retrieve a cert. This happens at different
 * times in different protocols. This will retrieve the cert and assumes that there is an {@link MyProxyConnectable}
 * that has been found and is cached. This will close the connection at the end of the request.
 * If the client should get a limited proxy, that will be done here as well.<br/>
 * Finally, if the DN from the cert is to be returned as the username in the final call to the service,
 * that will be set here.
 * <p>Created by Jeff Gaynor<br>
 * on 2/6/14 at  11:30 AM
 */
public abstract class CRServlet extends MyProxyDelegationServlet {

    /**
     * Indirection call. If your extension to this class needs to do any
     * prep work before calling {@link #doCertRequest(edu.uiuc.ncsa.security.delegation.server.ServiceTransaction, String)}
     * put it here. And this should contain the actual call to that method. This is called in the authorization leg
     * and the getCert call. You should point this at the {@link #doCertRequest(ServiceTransaction, String)} method
     * here which does all the dirty work of tracking down the connection and getting the cert. So, depending on your
     * protocol you will have only one of two places where this is fully implemented.
     */
    abstract protected void doRealCertRequest(ServiceTransaction trans, String statusString) throws Throwable;

    /**
     * There are various requirements for transmitting the access token, so specific methods have to be used.
     *
     * @param request
     * @return
     */
    abstract protected AccessToken getAccessToken(HttpServletRequest request);

    protected void doCertRequest(ServiceTransaction trans,
                                 String statusString
    ) throws Throwable {
        if (!hasMPConnection(trans)) {
            throw new ConnectionException("Error: There is no currently active MyProxy connection.");
        }
        MyPKCS10CertRequest localCertRequest = trans.getCertReq();

        KeyPair keyPair = null;
        if (trans.getClient().isProxyLimited()) {
            // NOTE: we will create a new keypair and CSR for the extra limited proxy
            // while we use the original CSR for doing the myproxy call
            info("3.b. starting proxy limited for " + trans.getClient().getIdentifier() + ". Generating keypair and cert request.");
            try {
                keyPair = getServiceEnvironment().getKeyPair();
                localCertRequest = CertUtil.createCertRequest(keyPair);
            } catch (GeneralSecurityException e) {
                error("3.b. " + e.getMessage());
            }

        }
        // This will do the myproxy callout
        LinkedList<X509Certificate> certs = getX509Certificates(trans, localCertRequest, statusString);
        debug("3.b. Got cert from server, count=" + certs.size());
        // If we want limited proxies, add another proxy delegation, since
        // myproxy GET cannot produce a limited proxy.
        // Use the original CSR and sign with the new private key which now
        // belongs to the cert retrieved from the myproxy.
        if (trans.getClient().isProxyLimited()) {
            info("3.b. Limited proxy for client " + trans.getClient().getIdentifier() + ", creating limited cert and signing it.");
            X509Certificate[] certList = ProxyUtil.generateProxy(trans.getCertReq(), keyPair.getPrivate(), certs.toArray(new X509Certificate[0]), trans.getLifetime(), true);
            certs = new LinkedList<>();
            Collections.addAll(certs, certList);
        }
        debug("3.b. Preparing to return cert chain of " + certs.size() + " to client.");
        MyX509Certificates myCerts = new MyX509Certificates(certs);
        trans.setProtectedAsset(myCerts);

        // Not clear why userName is retrieved
//      String userName = trans.getUsername();

        if (getServiceEnvironment().getAuthorizationServletConfig().isReturnDnAsUsername()) {
            String userName;
            if (myCerts.getX509Certificates().length > 0) {
                X500Principal x500Principal = myCerts.getX509Certificates()[0].getSubjectX500Principal();
                userName = x500Principal.getName();
                if (getServiceEnvironment().getAuthorizationServletConfig().isConvertDNToGlobusID()) {
                    // use local copy of JGlobus's CertificateUtil.toGlobusID(String dn)
                    userName = toGlobusID(userName);
                }

                debug(statusString + ": USERNAME = " + userName);
            } else {
                userName = "no_certificates_found";
            }
            trans.setUsername(userName);
            info("3.c. Set username returned to client to first certificate's DN: " + userName);
        }

        // Not clear why userName is set, it's either set in the if clause above, or is unchanged
//      trans.setUsername(userName); // Fixes OAUTH-102 username might not be set in some cases, so just reset it here.

        // Our response is a simple ok, since otherwise exceptions are thrown. No need to set this since that is the default.
        trans.setVerifier(MyProxyDelegationServlet.getServiceEnvironment().getTokenForge().getVerifier());
        getServiceEnvironment().getTransactionStore().save(trans);
        if (hasMPConnection(trans.getIdentifier())) {
            // It can happen (especially in cases of manual testing when there is considerable time between calls)
            // that the connection goes away. This prevents a bogus failure in that case.
            getMPConnection(trans.getIdentifier()).close();
        }
    }


    /**
     * Loops through the facade looking for the active connection and calls it.
     *
     * @param transaction
     * @param localCertRequest
     * @param statusString
     * @return
     * @throws GeneralSecurityException
     */
    protected LinkedList<X509Certificate> getX509Certificates(ServiceTransaction transaction,
                                                              MyPKCS10CertRequest localCertRequest,
                                                              String statusString) throws GeneralSecurityException {

        MyProxyConnectable mpc = getMPConnection(transaction);
        mpc.setLifetime(transaction.getLifetime());
        LinkedList<X509Certificate> certs = mpc.getCerts(localCertRequest);

        if (certs.isEmpty()) {
            info(statusString + "Error: MyProxy service returned no certs.");
            throw new GeneralException("Error: MyProxy service returned no certs.");
        }

        info(statusString + "Got cert from MyProxy.");
        return certs;
    }

    /**
     * Returns a working MyProxy connection or it fails.
     *
     * @param identifier
     * @param userName
     * @param password
     * @return
     * @throws GeneralSecurityException
     */
    protected MyProxyConnectable createMPConnection(Identifier identifier,
                                                    String userName,
                                                    String password,
                                                    long lifetime) throws GeneralSecurityException {
        return createMPConnection(identifier, userName, password, lifetime, null); // no loa
    }

    protected MyProxyConnectable createMPConnection(Identifier identifier,
                                                    String userName,
                                                    String password,
                                                    long lifetime,
                                                    String loa) throws GeneralSecurityException {
        MPConnectionProvider facades = new MPConnectionProvider(getMyLogger(), MyProxyDelegationServlet.getServiceEnvironment().getMyProxyServices());
        MyProxyConnectable mpc = facades.findConnection(identifier, userName, password, loa, lifetime);
        // Note: mpc is actually MyProxyConnection which cannot be cast to MyProxyLogonConnection
//        DebugUtil.dbg(this,((MPSingleConnectionProvider.MyProxyLogonConnection)mpc).getMyProxyLogon().toString());
        info("Adding connection to myproxy: "+mpc.toString());
        getMyproxyConnectionCache().add( mpc);
        return mpc;
    }

    /**
     * Converts DN of the form "CN=A, OU=B, O=C" into Globus
     * format "/CN=A/OU=B/O=C".<BR>
     * This function might return incorrect Globus-formatted ID when one of
     * the RDNs in the DN contains commas.
     * <P>
     * NOTE: this is copy/paste from
     * <A href="https://github.com/jglobus/JGlobus/blame/master/ssl-proxies/src/main/java/org/globus/gsi/util/CertificateUtil.java">JGlobus</A>
     * @see #toGlobusID(String, boolean)
     *
     * @param dn the DN to convert to Globus format.
     * @return the converted DN in Globus format.
     */
    public static String toGlobusID(String dn) {
        return toGlobusID(dn, true);
    }

    /**
     * Converts DN of the form "CN=A, OU=B, O=C" into Globus
     * format "/CN=A/OU=B/O=C" or "/O=C/OU=B/CN=A" depending on the
     * <code>noreverse</code> option. If <code>noreverse</code> is true
     * the order of the DN components is not reveresed - "/CN=A/OU=B/O=C" is
     * returned. If <code>noreverse</code> is false, the order of the
     * DN components is reversed - "/O=C/OU=B/CN=A" is returned. <BR>
     * This function might return incorrect Globus-formatted ID when one of
     * the RDNs in the DN contains commas.
     * <P>
     * NOTE: this is copy/paste from
     * <A href="https://github.com/jglobus/JGlobus/blame/master/ssl-proxies/src/main/java/org/globus/gsi/util/CertificateUtil.java">JGlobus</A>
     *
     * @param dn the DN to convert to Globus format.
     * @param noreverse the direction of the conversion.
     * @return the converted DN in Globus format.
     */
    public static String toGlobusID(String dn, boolean noreverse) {
        if (dn == null) {
            return null;
        }

        StringBuilder buf = new StringBuilder();

        String[] tokens = dn.split(",");
        if (noreverse) {
            for (int i = 0; i < tokens.length; i++) {
                String token = tokens[i].trim();
                if (!token.isEmpty()) {
                    buf.append("/");
                    buf.append(token.trim());
                }
            }
        } else {
            for (int i = tokens.length - 1; i >= 0; i--) {
                String token = tokens[i].trim();
                if (!token.isEmpty()) {
                    buf.append("/");
                    buf.append(token.trim());
                }
            }
        }

        return buf.toString();
    }

}
