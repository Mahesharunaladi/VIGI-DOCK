package com.vigidock.exception;

public class AnsibleExecutionException extends RuntimeException {
    public AnsibleExecutionException(String message) { super(message); }
    public AnsibleExecutionException(String message, Throwable cause) { super(message, cause); }
}
