package com.auth.authentication.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        // Check if there's an unhandled exception
        Throwable cause = (Throwable) request.getAttribute("javax.servlet.error.exception");

        if (cause != null) {
            // Log the exception (optional)
            System.err.println("Unhandled exception: " + cause.getMessage());

            // Return 500 Internal Server Error for unhandled exceptions
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Internal Server Error\",\"message\":\"" + cause.getMessage() + "\"}");
        } else {
            // Return 401 Unauthorized for authentication failures
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Unauthorized\",\"message\":\"Authentication is required.\"}");
        }
    }
}
