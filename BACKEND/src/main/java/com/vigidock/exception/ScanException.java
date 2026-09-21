package com.vigidock.exception;

public class ScanException extends VigiDockException {
    public ScanException(String message) {
        super(message);
    }

    public ScanException(String message, Throwable cause) {
        super(message, cause);
    }
}

