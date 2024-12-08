package com.auth.authentication.service;

import com.auth.authentication.dto.request.LoginRequest;
import com.auth.authentication.dto.request.RegisterRequest;
import com.auth.authentication.dto.response.AuthResponse;
import com.auth.authentication.entity.Role;
import com.auth.authentication.entity.Token;
import com.auth.authentication.entity.User;
import com.auth.authentication.exception.EmailAlreadyExistsException;
import com.auth.authentication.repository.TokenRepository;
import com.auth.authentication.repository.UserRepository;
import com.auth.authentication.service.security.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import org.apache.coyote.BadRequestException;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;

import static com.auth.authentication.entity.TokenType.ACCESS_TOKEN;
import static com.auth.authentication.entity.TokenType.REFRESH_TOKEN;

@Service
@AllArgsConstructor
@Transactional
public class AuthServiceImpl implements AuthService{
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final TokenRepository tokenRepository;

    @Override
    public AuthResponse register(RegisterRequest request,Role role) {
        if(repository.findByEmail(request.getEmail()).isPresent()){
            throw new EmailAlreadyExistsException("Email already exists try to login");
        }
        var user = User.builder()
                .firstName(request.getFirstname())
                .lastName(request.getFirstname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(role)
                .build();
        repository.save(user);
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        saveRefreshToken(user,refreshToken);
        removeOldTokenAndSaveNew(user,jwtToken);
        return new AuthResponse(jwtToken,refreshToken);
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
        removeOldTokenAndSaveNew(user,jwtToken);
        var refreshToken = jwtService.generateRefreshToken(user);
        saveRefreshToken(user,refreshToken);
        return new AuthResponse(jwtToken,refreshToken);
    }

    @Override
    public AuthResponse refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;
        if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
            throw  new BadRequestException("Refresh Token is required");
        }
        refreshToken = authHeader.substring(7);
        userEmail = jwtService.extractUsername(refreshToken);
        if (userEmail != null) {
            var user = this.repository.findByEmail(userEmail)
                    .orElseThrow();
            if (jwtService.isTokenValid(refreshToken, user)) {
                var accessToken = jwtService.generateToken(user);
                removeOldTokenAndSaveNew(user, accessToken);
                var authResponse = AuthResponse.builder()
                        .token(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                return authResponse;
            }
        }
        throw  new BadRequestException("Refresh Token is Not valid !!!");
    }

    private void removeOldTokenAndSaveNew(User user, String jwtToken){
        var optionalToken = tokenRepository.findByUserId(user.getId());
        if(optionalToken.isPresent()){
            tokenRepository.deleteOneById(optionalToken.get());
        }
        var token = Token.builder()
                .token(jwtToken)
                .type(ACCESS_TOKEN)
                .user(user)
                .build();
        tokenRepository.save(
                token
        );
    }
    private void saveRefreshToken(User user,String refreshToken){
        var optionalToken = tokenRepository.findRefreshTokenByUserId(user.getId());
        if(optionalToken.isPresent()){
            tokenRepository.deleteOneById(optionalToken.get());
        }
        var token = Token.builder()
                .token(refreshToken)
                .type(REFRESH_TOKEN)
                .user(user)
                .build();
        tokenRepository.save(
                token
        );
    }
}
