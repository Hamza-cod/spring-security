package com.auth.authentication.service;

import com.auth.authentication.dto.request.LoginRequest;
import com.auth.authentication.dto.request.RegisterRequest;
import com.auth.authentication.dto.response.AuthResponse;

public interface AuthService {
    AuthResponse register(RegisterRequest request);
    AuthResponse login(LoginRequest request);

}
