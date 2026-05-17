package com.example.starter.security;

import com.example.starter.service.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthTokenFilterTest {

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void doFilterInternalSetsAuthenticationWhenJwtIsValid() throws Exception {
        JwtUtils jwtUtils = mock(JwtUtils.class);
        UserDetailsServiceImpl userDetailsService = mock(UserDetailsServiceImpl.class);
        FilterChain filterChain = mock(FilterChain.class);
        AuthTokenFilter filter = new AuthTokenFilter(jwtUtils, userDetailsService);

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        User user = new User("alice", "password", java.util.List.of(() -> "ROLE_USER"));

        when(jwtUtils.getJwtFromCookies(request)).thenReturn("valid-jwt");
        when(jwtUtils.validateJwtToken("valid-jwt")).thenReturn(true);
        when(jwtUtils.getUserNameFromJwtToken("valid-jwt")).thenReturn("alice");
        when(userDetailsService.loadUserByUsername("alice")).thenReturn(user);

        filter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("alice");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternalSkipsAuthenticationWhenJwtIsInvalid() throws Exception {
        JwtUtils jwtUtils = mock(JwtUtils.class);
        UserDetailsServiceImpl userDetailsService = mock(UserDetailsServiceImpl.class);
        FilterChain filterChain = mock(FilterChain.class);
        AuthTokenFilter filter = new AuthTokenFilter(jwtUtils, userDetailsService);

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(jwtUtils.getJwtFromCookies(request)).thenReturn("invalid-jwt");
        when(jwtUtils.validateJwtToken("invalid-jwt")).thenReturn(false);

        filter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternalContinuesChainWhenJwtProcessingThrows() throws Exception {
        JwtUtils jwtUtils = mock(JwtUtils.class);
        UserDetailsServiceImpl userDetailsService = mock(UserDetailsServiceImpl.class);
        FilterChain filterChain = mock(FilterChain.class);
        AuthTokenFilter filter = new AuthTokenFilter(jwtUtils, userDetailsService);

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        doThrow(new RuntimeException("boom")).when(jwtUtils).getJwtFromCookies(request);

        filter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }
}

