package com.auth.authentication.config;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final int MAX_REQUESTS = 5;
    private static final int TIME_WINDOW_IN_SECONDS = 1; // Request time window
    private static final int BLOCK_DURATION_IN_SECONDS = 20; // Block period after exceeding limits

    private final ConcurrentHashMap<String, RequestTracker> requestTrackers = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String clientKey = getClientKey(request);

        // Track requests for the client
        RequestTracker tracker = requestTrackers.computeIfAbsent(clientKey, key -> new RequestTracker());
        synchronized (tracker) {
            if (tracker.isBlocked()) {
                // If blocked, send 429 response
                response.setStatus(429);
                response.getWriter().write("Too many requests. Please try again later.");
                return;
            }

            if (!tracker.allowRequest()) {
                // Block the client if they exceed the limit
                tracker.block();
                response.setStatus(429);
                response.getWriter().write("Too many requests. You are temporarily blocked.");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private String getClientKey(HttpServletRequest request) {
        // Use IP address as a simple client identifier
        return request.getRemoteAddr();
    }

    // Inner class to track request counts and blocking state
    private static class RequestTracker {
        private Instant firstRequestTime = Instant.now();
        private int requestCount = 0;
        private Instant blockUntil = Instant.now();

        public synchronized boolean allowRequest() {
            Instant now = Instant.now();

            if (now.isBefore(blockUntil)) {
                return false; // Still blocked
            }

            if (Duration.between(firstRequestTime, now).getSeconds() > TIME_WINDOW_IN_SECONDS) {
                // Reset tracking if time window elapsed
                firstRequestTime = now;
                requestCount = 0;
            }

            requestCount++;
            return requestCount <= MAX_REQUESTS;
        }

        public synchronized void block() {
            blockUntil = Instant.now().plusSeconds(BLOCK_DURATION_IN_SECONDS);
        }

        public synchronized boolean isBlocked() {
            return Instant.now().isBefore(blockUntil);
        }
    }
}
