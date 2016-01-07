package edu.uiuc.ncsa.myproxy.exception;

public class MyProxyNoUserException extends MyProxyException {

    public MyProxyNoUserException(String msg) {
        super(msg);
    }

    public MyProxyNoUserException(String msg, Throwable ex) {
        super(msg, ex);
    }

}
