package edu.uiuc.ncsa.myproxy;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.LinkedList;

import edu.uiuc.ncsa.myproxy.exception.MyProxyCertExpiredException;
import edu.uiuc.ncsa.myproxy.exception.MyProxyException;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.ConnectionException;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.util.pkcs.MyPKCS10CertRequest;

public class MyProxyConnection implements MyProxyConnectable {

	protected MyProxy myproxy;
	
	public MyProxyConnection(MyProxy myproxy) {
		this.myproxy = myproxy;
	}
	
	@Override
	public void doPut(X509Certificate[] chain, PrivateKey privateKey) throws MyProxyException {	
		resetConnection();
		this.myproxy.doPut(chain, privateKey);
	}
	
	@Override
	public void doStore(X509Certificate[] chain, PrivateKey privateKey) throws MyProxyException {
		resetConnection();
		this.myproxy.doStore(chain, privateKey);
	}
	
	@Override
	public MyProxyCredentialInfo doInfo() throws MyProxyException {
		
		MyProxyCredentialInfo[] info = null;
		
		resetConnection();
		
		info = myproxy.doInfo();			
		
        if ( info.length > 1 ) {
        	throw new MyProxyException("Undefined behaviour! More then one certificate registered under single username");
        }
        
        long now = System.currentTimeMillis();
        if (info[0].getEndTime() < now) {	        	
        	throw new MyProxyCertExpiredException("User certificate expired in Credential Store!");
        }			
		
        return info[0];
    
	}	
	
    protected Identifier identifier;

    @Override
    public Identifier getIdentifier() {
        return identifier;
    }

    @Override
    public String getIdentifierString() {
        if (identifier == null) return null;
        return identifier.toString();
    }

    @Override
    public void setIdentifier(Identifier identifier) {
        this.identifier = identifier;
    }
    
    

    @Override
    public void close() {
        try {
        	myproxy.disconnect();
        } catch (Throwable e) {
            throw new ConnectionException("Error: disconnecting from myproxy", e);
        }

    }

    @Override
    public void open() {
        try {
        	myproxy.connect();
        	//do not send any commands just yet because this connection can be 
        	//used for other commands, not just logon
        	//myproxy.logon();
        } catch (Throwable e) {
            throw new ConnectionException("Error: connecting to myproxy", e);
        }
    }

    @Override
    public LinkedList<X509Certificate> getCerts(byte[] pkcs10CertRequest) {
        try {
        	
        	resetConnection();
        	
        	myproxy.getCredentials(pkcs10CertRequest);
            LinkedList<X509Certificate> certList = new LinkedList<X509Certificate>();
            certList.addAll(myproxy.getCertificates());
            return certList;
        } catch (Throwable e) {
            if ( e instanceof MyProxyException ) {
            	throw (MyProxyException) e;
            } else {
            	throw new MyProxyException("Failed to execute GET command",e);
            }
        }
    }
    
    @Override
    public LinkedList<X509Certificate> getCerts(MyPKCS10CertRequest pkcs10CertRequest) {
    	return getCerts(pkcs10CertRequest.getEncoded());
    }

    
    protected void resetConnection() {
    	
    	try {
        	if ( myproxy.isLoggedOn() ) {
        		close();
        	}
    	} catch(Throwable t) {
    		myproxy.mlf.error("Failed to reset MyProxy connection!");
    	}
    	
    }
    
    @Override
    public void setRetriever(String retriever) {
    	myproxy.setRetriever(retriever);   	
    }
    
    @Override
    public void setRenewer(String renewer) {
    	myproxy.setRenewer(renewer);
    }
    
    @Override
    public void setVoname(String voname) {
    	myproxy.setVoname(voname);
    }
    
    @Override
    public void setVomses(String vomses) {	
    	myproxy.setVomses(vomses);
    }
    
    @Override
    public void setLifetime(long certLifetime) {
    	
    	int newLifetime = (int) (certLifetime / 1000);
    	myproxy.setLifetime(newLifetime);
    }

    @Override
    public String toString() {
        String out =  getClass().getSimpleName() + "[";
        if(myproxy == null){
            out = out + "(no myproxy logon)";
        }else {
            out = out + "lifetime=" + myproxy.getLifetime() +
                    ", port=" + myproxy.getPort() +
                    ", host="+ myproxy.getHost();
        }
          return out + "]";
    }


    @Override
    public Identifiable clone() {
        return null;
    }



	
}
