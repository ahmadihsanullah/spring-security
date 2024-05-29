package com.workshop.bouali.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

public class JwtAuthFilter extends OncePerRequestFilter {
    private final UserDetailsService userDetailsService;

    public JwtAuthFilter(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
            final String authHeader = request.getHeader(AUTHORIZATION);
            final String userEmail = null;
            final String jwtToken;

            if(authHeader == null || !authHeader.startsWith("Bearer")){
                filterChain.doFilter(request, response);
                return;
            }
            jwtToken = authHeader.substring(7);
            if(userEmail != null && SecurityContextHolder.getContext().getAuthentication()== null){
                UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
                final Boolean isTokenValid = null;
                if(isTokenValid){
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        filterChain.doFilter(request, response);
    }
}
