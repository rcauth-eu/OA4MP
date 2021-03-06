package edu.uiuc.ncsa.myproxy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.ProtocolException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.security.auth.login.FailedLoginException;

import org.apache.commons.codec.binary.Base64;


import edu.uiuc.ncsa.myproxy.exception.MyProxyException;
import edu.uiuc.ncsa.myproxy.exception.MyProxyNoUserException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
//import edu.uiuc.ncsa.security.util.pkcs.KeyUtil;
import edu.uiuc.ncsa.security.util.pkcs.ProxyUtil;

import eu.emi.security.authn.x509.impl.CertificateUtils;

public class MyProxy extends MyProxyLogon {

    public MyProxy() {
        super();
    }

    public MyProxy(MyLoggingFacade myLoggingFacade) {
        super(myLoggingFacade);
    }

    public MyProxy(MyLoggingFacade myLoggingFacade, String serverDN) {
        super(myLoggingFacade, serverDN);
    }

    protected final static String COMMAND = "COMMAND=";
    protected final static String INFO_COMMAND = "2";
    protected final static String PUT_COMMAND = "1";
    protected final static String STORE_COMMAND = "5";

    protected static final String CRED            = "CRED_";
    protected static final String OWNER           = "OWNER=";
    protected static final String START_TIME      = "START_TIME=";
    protected static final String END_TIME        = "END_TIME=";
    protected static final String DESC            = "DESC=";
    protected static final String RETRIEVER       = "RETRIEVER=";
    protected static final String RENEWER         = "RENEWER=";
    protected static final String TRUSTROOTS      = "TRUSTED_CERTS=";

    protected static final String CRED_START_TIME = CRED + START_TIME;
    protected static final String CRED_END_TIME   = CRED + END_TIME;
    protected static final String CRED_OWNER      = CRED + OWNER;
    protected static final String CRED_DESC       = CRED + DESC;
    protected static final String CRED_RETRIEVER  = CRED + RETRIEVER;
    protected static final String CRED_RENEWER    = CRED + RENEWER;
    protected static final String CRED_NAME       = CRED + "NAME=";

    public static String LINE_SEP;
    public static byte[] LINE_SEP_BYTES;

    protected String retriever;
    protected String renewer;

    static {
        LINE_SEP = System.getProperty("line.separator");
        LINE_SEP_BYTES = LINE_SEP.getBytes();
    }

    public void setRetriever(String retriever) {
        this.retriever = retriever;
    }

    public String getRetriever() {
        return retriever;
    }

    public void setRenewer(String renewer) {
        this.renewer = renewer;
    }

    public String getRenewer() {
        return renewer;
    }

    public void store() throws Throwable {

        if (this.state != State.CONNECTED) {
            this.connect();
        }

        this.socketOut.write('0');
        this.socketOut.flush();

        this.socketOut.write(VERSION.getBytes());
        this.socketOut.write('\n');
        this.socketOut.write(COMMAND.getBytes());
        this.socketOut.write(STORE_COMMAND.getBytes());
        this.socketOut.write('\n');
        this.socketOut.write(USERNAME.getBytes());
        this.socketOut.write(this.username.getBytes());
        this.socketOut.write('\n');
        this.socketOut.write(PASSPHRASE.getBytes());
        this.socketOut.write("".getBytes());
        this.socketOut.write('\n');
        this.socketOut.write(LIFETIME.getBytes());
        this.socketOut.write(Integer.toString(this.lifetime).getBytes());
        this.socketOut.write('\n');

        if ( this.retriever != null && ! this.retriever.isEmpty() ) {
            this.socketOut.write(RETRIEVER.getBytes());
            this.socketOut.write(this.retriever.getBytes());
            this.socketOut.write('\n');
        }

        if ( this.renewer != null && ! this.renewer.isEmpty() ) {
            this.socketOut.write(RENEWER.getBytes());
            this.socketOut.write(this.renewer.getBytes());
            this.socketOut.write('\n');
        }

        this.socketOut.flush();

        this.state = State.LOGGEDON;

    }

    public void doStore(X509Certificate[] chain, PrivateKey pKey) throws MyProxyException {

        try {

            // close any previously opened connection
            if (this.state == State.LOGGEDON) {
                this.disconnect();
            }

            // open new connection and send STORE request parameters
            store();
            handleResponse();

            // send certificate , private key and the rest of the chain.
            if (chain.length < 1) {
                throw new MyProxyException("No Certificate chain provided to the STORE method!");
            }

            if ( this.mlf != null ) {
                mlf.debug("----------- Uploading proxy with MyProxy STORE -----------");

                mlf.debug( CertUtil.toPEM(chain[0]) );
                //mlf.debug( KeyUtil.toPKCS1PEM(pKey) );
                for (int i=1; i < chain.length; i++) {
                    mlf.debug( CertUtil.toPEM(chain[i]) );
                }
                mlf.debug("----------- Uploading proxy with MyProxy STORE -----------");
            }

            this.socketOut.write( CertUtil.toPEM(chain[0]).getBytes() );
            this.socketOut.write(LINE_SEP_BYTES);

            // NOTE: we need to STORE the private key encrypted, otherwise the
            // GET to retrieve a delegation will fail!!
            // Hence we'll use canl-java's CertificateUtils.savePrivateKey()
            // instead of security-lib's KeyUtil.toPKCS1PEM() which would
            // essentially just write pKey.getEncoded() (which is pretty much
            // how it is internally stored in a RSAPrivateCrtKeyImpl (actually
            // a PKCS8Key).

            // NOTE: calling CertificateUtils.savePrivateKey() directly with
            // this.socketOut somehow leads to a SEGV in myproxy-server. Using
            // a ByteArrayOutputStream as intermediary works fine.
            // A buffer of 2k is typically sufficient for the private key.
            NullableByteArrayOutputStream baos = new NullableByteArrayOutputStream(2048);
            // Write out as RSA with DES-EDE3-CBC (triple-DES)
            CertificateUtils.savePrivateKey(baos, pKey, CertificateUtils.Encoding.PEM, "DES-EDE3-CBC", this.passphrase.toCharArray(), true);
            // Write out the private key to the MyProxy socket (no need for a newline here)
            this.socketOut.write(baos.toByteArray());
            // Clear the internal buffer of the BAOS
            baos.reset();

            for (int i=1; i < chain.length; i++) {
                this.socketOut.write( CertUtil.toPEM(chain[i]).getBytes() );
                this.socketOut.write(LINE_SEP_BYTES);
            }

            this.socketOut.flush();

            handleResponse();

        } catch (Throwable t) {
            handleMyProxyException(t,"Failed to execute STORE command");
        }
        finally {
            this.state = State.DONE;
        }

    }

    public void put() throws Throwable {

        if (this.state != State.CONNECTED) {
            this.connect();
        }

        this.socketOut.write('0');
        this.socketOut.flush();

        this.socketOut.write(VERSION.getBytes());
        this.socketOut.write('\n');
        this.socketOut.write(COMMAND.getBytes());
        this.socketOut.write(PUT_COMMAND.getBytes());
        this.socketOut.write('\n');
        this.socketOut.write(USERNAME.getBytes());
        this.socketOut.write(this.username.getBytes());
        this.socketOut.write('\n');
        this.socketOut.write(PASSPHRASE.getBytes());
        this.socketOut.write(this.passphrase.getBytes());
        this.socketOut.write('\n');
        this.socketOut.write(LIFETIME.getBytes());
        this.socketOut.write(Integer.toString(this.lifetime).getBytes());
        this.socketOut.write('\n');

        if ( this.retriever != null && ! this.retriever.isEmpty() ) {
            this.socketOut.write(RETRIEVER.getBytes());
            this.socketOut.write(this.retriever.getBytes());
            this.socketOut.write('\n');
        }

        if ( this.renewer != null && ! this.renewer.isEmpty() ) {
            this.socketOut.write(RENEWER.getBytes());
            this.socketOut.write(this.renewer.getBytes());
            this.socketOut.write('\n');
        }

        this.socketOut.flush();

        this.state = State.LOGGEDON;

    }


    public void doPut(X509Certificate[] chain, PrivateKey pKey) throws MyProxyException {

        try {

            // close any previously opened connection
            if (this.state == State.LOGGEDON) {
                this.disconnect();
            }

            // open new connection and send PUT request parameters
            put();
            handleResponse();

            // read CSR from MyProxy
            byte[] csr = readAll(this.socketIn);

            if ( this.mlf != null ) {
                mlf.debug("----------- CSR from MyProxy PUT -----------");
                mlf.debug(new String(Base64.encodeBase64(csr)));
                mlf.debug("----------- CSR from MyProxy PUT -----------");
            }

            // generate proxy from CSR
            mlf.debug("Generating proxy with lifetime (seconds) : " + lifetime );
            X509Certificate[] proxy = ProxyUtil.generateProxy(csr, pKey, chain, ((long)lifetime) * 1000, false);

            if ( this.mlf != null ) {
                mlf.debug("----------- Generated Proxy for MyProxy PUT -----------");
                mlf.debug( CertUtil.toPEM(proxy) );
                mlf.debug("----------- Generated Proxy for MyProxy PUT -----------");
            }

            // send back proxy chain
            byte proxyCount = (byte) proxy.length;

            this.socketOut.write(proxyCount);
            for ( X509Certificate c : proxy ) {
                this.socketOut.write( c.getEncoded() );
            }

            this.socketOut.flush();

            handleResponse();

        } catch (Throwable t) {
            handleMyProxyException(t,"Failed to execute PUT command");
        }
        finally {
            this.state = State.DONE;
        }
    }


    public void info() throws IOException, GeneralSecurityException, MyProxyNoUserException  {

        if (this.state != State.CONNECTED) {
            this.connect();
        }

        this.socketOut.write('0');
        this.socketOut.flush();

        this.socketOut.write(VERSION.getBytes());
        this.socketOut.write('\n');
        this.socketOut.write(COMMAND.getBytes());
        this.socketOut.write(INFO_COMMAND.getBytes());
        this.socketOut.write('\n');
        this.socketOut.write(USERNAME.getBytes());
        this.socketOut.write(this.username.getBytes());
        this.socketOut.write('\n');
        this.socketOut.write(PASSPHRASE.getBytes());
        this.socketOut.write("PASSPHRASE".getBytes());
        this.socketOut.write('\n');
        this.socketOut.write(LIFETIME.getBytes());
        this.socketOut.write("0".getBytes());
        this.socketOut.write('\n');
        this.socketOut.flush();

        this.state = State.LOGGEDON;

    }

    public MyProxyCredentialInfo[] doInfo() throws MyProxyException {

        try {
            // close any previously opened connection
            if (this.state == State.LOGGEDON) {
                this.disconnect();
            }
            // open new connection and set INFO request parameters
            info();
            InputStream reply = handleResponse();


            String line = null;
            String value = null;
            Map credMap = new HashMap();
            MyProxyCredentialInfo info = new MyProxyCredentialInfo();

            while( (line = readLine(reply)) != null ) {

                if (line.startsWith(CRED_START_TIME)) {
                    value = line.substring(CRED_START_TIME.length());
                    info.setStartTime(Long.parseLong(value) * 1000);
                } else if (line.startsWith(CRED_END_TIME)) {
                    value = line.substring(CRED_END_TIME.length());
                    info.setEndTime(Long.parseLong(value) * 1000);
                } else if (line.startsWith(CRED_OWNER)) {
                    info.setOwner(line.substring(CRED_OWNER.length()));
                } else if (line.startsWith(CRED_NAME)) {
                    info.setName(line.substring(CRED_NAME.length()));
                } else if (line.startsWith(CRED_DESC)) {
                    info.setDescription(line.substring(CRED_DESC.length()));
                } else if (line.startsWith(CRED_RENEWER)) {
                    info.setRenewers(line.substring(CRED_RENEWER.length()));
                } else if (line.startsWith(CRED_RETRIEVER)) {
                    info.setRetrievers(line.substring(CRED_RETRIEVER.length()));
                } else if (line.startsWith(CRED)) {
                    int pos = line.indexOf('=', CRED.length());
                    if (pos == -1) {
                        continue;
                    }
                    value = line.substring(pos+1);

                    if (matches(line, pos+1, OWNER)) {
                        String name = getCredName(line, pos, OWNER);
                        getCredentialInfo(credMap, name).setOwner(value);
                    } else if (matches(line, pos+1, START_TIME)) {
                        String name = getCredName(line, pos, START_TIME);
                        getCredentialInfo(credMap, name).setStartTime(Long.parseLong(value) * 1000);
                    } else if (matches(line, pos+1, END_TIME)) {
                        String name = getCredName(line, pos, END_TIME);
                        getCredentialInfo(credMap, name).setEndTime(Long.parseLong(value) * 1000);
                    } else if (matches(line, pos+1, DESC)) {
                        String name = getCredName(line, pos, DESC);
                        getCredentialInfo(credMap, name).setDescription(value);
                    } else if (matches(line, pos+1, RENEWER)) {
                        String name = getCredName(line, pos, RENEWER);
                        getCredentialInfo(credMap, name).setRenewers(value);
                    } else if (matches(line, pos+1, RETRIEVER)) {
                        String name = getCredName(line, pos, RETRIEVER);
                        getCredentialInfo(credMap, name).setRetrievers(value);
                    }
                }
            }

            MyProxyCredentialInfo[] creds = new MyProxyCredentialInfo[1 + credMap.size()];
            creds[0] = info; // default creds at position 0

            if (credMap.size() > 0) {
                int i = 1;
                Iterator iter = credMap.entrySet().iterator();
                while(iter.hasNext()) {
                    Map.Entry entry = (Map.Entry)iter.next();
                    creds[i++] = (MyProxyCredentialInfo)entry.getValue();
                }
            }

            return creds;

        }
        catch (FailedLoginException e) {
            if (e.getMessage().contains("no credentials found for user")) {
                throw new MyProxyNoUserException("User unknown in MyProxy Store",e);
            } else {
                handleMyProxyException(e,"Failed to execute INFO command");
            }
        }
        catch (Throwable t) {
            handleMyProxyException(t,"Failed to execute INFO command");
        }
        finally {
            this.state = State.DONE;
        }

        return null;

    }

    protected void handleMyProxyException(Throwable t, String message) throws MyProxyException {

        if ( t instanceof MyProxyException ) {
            throw (MyProxyException) t;
        } else {
            throw new MyProxyException(message,t);
        }

    }

    protected InputStream handleResponse() throws IOException, FailedLoginException {

        String line = readLine(this.socketIn);
        if (line == null) {
            throw new EOFException();
        }
        if (!line.equals(VERSION)) {
            throw new ProtocolException("bad MyProxy protocol VERSION string: "
                    + line);
        }
        line = readLine(this.socketIn);
        if (line == null) {
            throw new EOFException();
        }
        if (!line.startsWith(RESPONSE)
                || line.length() != RESPONSE.length() + 1) {
            throw new ProtocolException(
                    "bad MyProxy protocol RESPONSE string: " + line);
        }
        char response = line.charAt(RESPONSE.length());
        if (response == '1') {
            StringBuffer errString;

            errString = new StringBuffer("MyProxy logon failed");
            while ((line = readLine(this.socketIn)) != null) {
                if (line.startsWith(ERROR)) {
                    errString.append('\n');
                    errString.append(line.substring(ERROR.length()));
                }
            }
            throw new FailedLoginException(errString.toString());
        } else if (response == '2') {
            throw new ProtocolException(
                    "MyProxy authorization RESPONSE not implemented");
        } else if (response != '0') {
            throw new ProtocolException(
                    "unknown MyProxy protocol RESPONSE string: " + line);
        }

        /* always consume the entire message */
        int avail = this.socketIn.available();
        byte [] b = new byte[avail];
        if (avail > 0) this.socketIn.read(b);

        ByteArrayInputStream inn = new ByteArrayInputStream(b);
        return inn;

    }

    protected byte[] readAll(InputStream is) throws IOException {

        int c;
        int i = 0;
        byte[] data = null;

        for (c = is.read(); is.available() > 0 ; c = is.read()) {

            if ( data == null ) {
                i = 0;
                data = new byte[is.available()+1];
            }

            data[i] = (byte) c;
            i++;
        }

        data[i] = (byte) c;
        return data;
    }

    protected boolean matches(String line, int pos, String arg) {
        return line.regionMatches(true,
                                  pos - arg.length(),
                                  arg,
                                  0,
                                  arg.length());
    }

    protected String getCredName(String line, int pos, String arg) {
        return line.substring(CRED.length(), pos-arg.length());
    }

    protected MyProxyCredentialInfo getCredentialInfo(Map map, String name) {
        MyProxyCredentialInfo info = (MyProxyCredentialInfo)map.get(name);
        if (info == null) {
            info = new MyProxyCredentialInfo();
            info.setName(name);
            map.put(name, info);
        }
        return info;
    }

    /**
     * ByteArrayOutputStream that clears the internal buffer on reset
     */
    private class NullableByteArrayOutputStream extends ByteArrayOutputStream {
        public NullableByteArrayOutputStream(int size) {
            super(size);
        }

        /**
         * {@link ByteArrayOutputStream#reset()} does not clean the internal buffer,
         * but just resets the counter, this version first 'nullifies' the buffer.
         */
        @Override
        public void reset(){
            for (int i=0; i<buf.length; i++)
                buf[i]=0;
            // Now reset the counter (we could also just set count=0)
            super.reset();
        }

    }
}
