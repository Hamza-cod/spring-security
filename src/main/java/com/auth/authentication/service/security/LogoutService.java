package com.auth.authentication.service.security;

import com.auth.authentication.repository.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Transactional
public class LogoutService implements LogoutHandler {

    private final TokenRepository tokenRepository;

    @Override
    public void logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        if (authHeader == null ||!authHeader.startsWith("Bearer ") )  {
           throw  new AccessDeniedException("not authenticated");
        }
        jwt = authHeader.substring(7);
        var storedTokenId = tokenRepository.findByToken(jwt)
                .orElseThrow(()->new AccessDeniedException("not authenticated"));
        if (storedTokenId != null) {
            tokenRepository.deleteOneById(storedTokenId);
            SecurityContextHolder.clearContext();
        }
    }
}