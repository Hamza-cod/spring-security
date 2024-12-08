package com.auth.authentication.service;

import com.auth.authentication.dto.request.LoginRequest;
import com.auth.authentication.dto.request.RegisterRequest;
import com.auth.authentication.dto.response.AuthResponse;
import com.auth.authentication.entity.Role;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public interface AuthService {
    AuthResponse register(RegisterRequest request, Role role);
    AuthResponse login(LoginRequest request);

    AuthResponse refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException;
}
