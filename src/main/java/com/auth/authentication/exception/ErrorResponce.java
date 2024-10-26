package com.auth.authentication.exception;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ErrorResponce {
    private Status status;
    private String message;
}
