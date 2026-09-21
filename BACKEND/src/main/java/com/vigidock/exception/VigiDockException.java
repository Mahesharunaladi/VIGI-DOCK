package com.vigidock.exception;

public class VigiDockException extends RuntimeException {
    public VigiDockException(String message) {
        super(message);
    }

    public VigiDockException(String message, Throwable cause) {
        super(message, cause);
    }
}

