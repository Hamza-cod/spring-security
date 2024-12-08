package com.auth.authentication.controller;

import com.auth.authentication.dto.request.LoginRequest;
import com.auth.authentication.dto.request.RegisterRequest;
import com.auth.authentication.dto.response.AuthResponse;
import com.auth.authentication.entity.Role;
import com.auth.authentication.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@AllArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final AuthService authService;
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody  RegisterRequest registerRequest){
        return ResponseEntity.ok(authService.register(registerRequest, Role.USER));
    }
    @PostMapping("/register/admin")
    public ResponseEntity<AuthResponse> registerAdmin(@RequestBody  RegisterRequest registerRequest){
        return ResponseEntity.ok(authService.register(registerRequest, Role.ADMIN));
    }
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest loginRequest){
        return ResponseEntity.ok(authService.login(loginRequest));
    }
    @PostMapping("/refresh-token")
    public AuthResponse refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        return authService.refreshToken(request, response);
    }
}
