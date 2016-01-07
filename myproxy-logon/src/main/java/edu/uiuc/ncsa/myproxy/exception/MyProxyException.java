package edu.uiuc.ncsa.myproxy.exception;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

public class MyProxyException extends GeneralException {

    //MyProxy operation failed!

    public MyProxyException(String msg) {
        super(msg);
    }

    public MyProxyException(String msg, Throwable ex) {
        super(msg,ex);
    }

    @Override
    public String getMessage() {
        return "MyProxy Failure! " + super.getMessage();
    }

}
