package com.auth.authentication.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {


        @ExceptionHandler(BadCredentialsException.class)
        @ResponseStatus(HttpStatus.BAD_REQUEST)
        public ErrorResponce handleAuthenticationException(BadCredentialsException ex) {
                return  new ErrorResponce(Status.BAD_REQUEST, "Credentials don't match our records");
        }

        @ExceptionHandler(AccessDeniedException.class)
        public ResponseEntity<Object> handleAccessDeniedException(AccessDeniedException ex) {
                return new ResponseEntity<>(Map.of("error", "Forbidden: You don't have permission to access this resource"), HttpStatus.FORBIDDEN);
        }

        @ExceptionHandler(EmailAlreadyExistsException.class)
        @ResponseStatus(HttpStatus.BAD_REQUEST)
        public ErrorResponce handleEmailAlreadyExistsException(EmailAlreadyExistsException e) {
        return new ErrorResponce(Status.BAD_REQUEST,e.getMessage()); // or use a custom error response object
        }
        // Catch-all for unknown endpoints (404)
        @ExceptionHandler(NoHandlerFoundException.class)
        @ResponseStatus(HttpStatus.NOT_FOUND)
        public ErrorResponce handleNoHandlerFoundException(NoHandlerFoundException e) {
                return  new ErrorResponce(Status.NOT_FOUND,"Route not found: " + e.getRequestURL());
        }
        @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
        @ResponseStatus(HttpStatus.BAD_REQUEST)
        public ErrorResponce handleNoHandlerFoundException(HttpRequestMethodNotSupportedException e) {
                return  new ErrorResponce(Status.BAD_REQUEST,"Unsupported Method : " + e.getMethod());
        }
        @ExceptionHandler(HttpMessageNotReadableException.class)
        @ResponseStatus(HttpStatus.BAD_REQUEST)
        public ErrorResponce handleNoHandlerFoundException(HttpMessageNotReadableException e) {
                return  new ErrorResponce(Status.BAD_REQUEST,"Request body is required" );
        }
        @ExceptionHandler(Exception.class)
        public ResponseEntity<Map<String, Object>> handleGenericException(Exception ex) {
                Map<String, Object> responseBody = new HashMap<>();
                responseBody.put("error", "Unexpected Error");
                responseBody.put("message", ex.getMessage());

                return ResponseEntity
                        .status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(responseBody);
        }

}
