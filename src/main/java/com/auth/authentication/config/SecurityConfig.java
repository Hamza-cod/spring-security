package com.auth.authentication.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static com.auth.authentication.entity.Permission.*;
import static com.auth.authentication.entity.Role.*;
import static org.springframework.http.HttpMethod.*;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthFiler;
    private static final  String[] AUTH_WHITELIST = {
            "/api/v1/auth/**",
    };
    private final AuthenticationProvider authenticationProvider;
//    this for error responses
    private final CustomAuthenticationFailureHandler customAuthFailureHandler;
    private final CustomAuthenticationEntryPoint customAuthEntryPoint;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    private final LogoutHandler logoutHandler;
    private final RateLimitingFilter rateLimitingFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
         http.
                csrf(AbstractHttpConfigurer::disable)
                 .authorizeHttpRequests(req ->
                         req.requestMatchers(AUTH_WHITELIST)
                                 .permitAll()
                                 .requestMatchers("/api/v1/management/**").hasAnyRole(ADMIN.name(), MANAGER.name())
                                 .requestMatchers(GET, "/api/v1/management/**").hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())
                                 .requestMatchers(POST, "/api/v1/management/**").hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())
                                 .requestMatchers(PUT, "/api/v1/management/**").hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())
                                 .requestMatchers(DELETE, "/api/v1/management/**").hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())
                                 .anyRequest()
                                 .authenticated()
                 )
                 .exceptionHandling(ex -> ex.
                         authenticationEntryPoint(customAuthEntryPoint)
                         .accessDeniedHandler(customAccessDeniedHandler))
                .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFiler, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(rateLimitingFilter, JwtAuthenticationFilter.class)
                 .logout(logout ->
                         logout.logoutUrl("/api/v1/logout")
                                 .addLogoutHandler(logoutHandler)
                                 .logoutSuccessHandler((request, response, authentication) -> response.setStatus(HttpStatus.NO_CONTENT.value()))
                 )
        ;
        return http.build();
    }
}
