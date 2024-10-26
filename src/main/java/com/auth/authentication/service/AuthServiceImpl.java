package com.auth.authentication.service;

import com.auth.authentication.dto.request.LoginRequest;
import com.auth.authentication.dto.request.RegisterRequest;
import com.auth.authentication.dto.response.AuthResponse;
import com.auth.authentication.entity.Role;
import com.auth.authentication.entity.User;
import com.auth.authentication.exception.EmailAlreadyExistsException;
import com.auth.authentication.repository.UserRepository;
import com.auth.authentication.service.security.JwtService;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService{
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Override
    public AuthResponse register(RegisterRequest request) {
        if(repository.findByEmail(request.getEmail()).isPresent()){
            throw new EmailAlreadyExistsException("Email already exists try to login");
        }
        var user = User.builder()
                .firstName(request.getFirstname())
                .lastName(request.getFirstname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        repository.save(user);
        var jwtToken = jwtService.generateToken(user);
        return new AuthResponse(jwtToken);
    }

    @Override
    public AuthResponse login(LoginRequest request) {
        try {
            // Attempt to authenticate the user
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );
        } catch (AuthenticationException e) {
            // Handle bad credentials exception
            throw new BadCredentialsException("Credentials don't match our records", e);
        }
        var user = repository.findByEmail(request.getEmail()).orElseThrow(() -> new BadCredentialsException("User not found"));
        var jwtToken = jwtService.generateToken(user);
        return new AuthResponse(jwtToken);
    }
}
