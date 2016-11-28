package edu.uiuc.ncsa.myproxy.exception;

public class MyProxyVOMSException extends MyProxyException {

	// VOMS server down
	// VOMS server does not recognize user
	
	public MyProxyVOMSException(String msg) {
		super(msg);
	}
	
    public MyProxyVOMSException(String msg, Throwable ex) {
        super(msg, ex);
    }		
	
    @Override
    public String getMessage() {
    	return super.getMessage() + " (this can occur in case the contacted VOMS server is down OR it fails to recognize the user )";
    }
}
