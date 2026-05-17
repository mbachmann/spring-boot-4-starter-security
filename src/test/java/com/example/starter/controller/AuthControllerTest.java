package com.example.starter.controller;

import com.example.starter.model.entity.ERole;
import com.example.starter.model.entity.Role;
import com.example.starter.model.entity.User;
import com.example.starter.repository.RoleRepository;
import com.example.starter.repository.UserRepository;
import com.example.starter.security.JwtUtils;
import com.example.starter.service.UserDetailsImpl;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthenticationManager authenticationManager;

    @MockitoBean
    private UserRepository userRepository;

    @MockitoBean
    private RoleRepository roleRepository;

    @MockitoBean
    private PasswordEncoder encoder;

    @MockitoBean
    private JwtUtils jwtUtils;

    @Test
    void signinReturnsUserInfoAndJwtHeaders() throws Exception {
        UserDetailsImpl userDetails = new UserDetailsImpl(
            1L,
            "alice",
            "alice@example.com",
            "encoded-password",
            List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        Authentication authentication =
            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        when(authenticationManager.authenticate(any())).thenReturn(authentication);
        when(jwtUtils.generateJwtCookie(userDetails))
            .thenReturn(ResponseCookie.from("starter", "jwt-cookie").path("/api").httpOnly(true).build());
        when(jwtUtils.generateJwtToken(userDetails)).thenReturn("jwt-token");

        mockMvc.perform(post("/api/auth/signin")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "username": "alice",
                      "password": "password"
                    }
                    """))
            .andExpect(status().isOk())
            .andExpect(header().string(HttpHeaders.AUTHORIZATION, "jwt-token"))
            .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("starter=jwt-cookie")))
            .andExpect(jsonPath("$.id").value(1))
            .andExpect(jsonPath("$.username").value("alice"))
            .andExpect(jsonPath("$.email").value("alice@example.com"))
            .andExpect(jsonPath("$.jwtToken").value("jwt-token"))
            .andExpect(jsonPath("$.roles[0]").value("ROLE_USER"));
    }

    @Test
    void signinReturnsBadRequestWhenPayloadIsInvalid() throws Exception {
        mockMvc.perform(post("/api/auth/signin")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "username": "",
                      "password": ""
                    }
                    """))
            .andExpect(status().isBadRequest());
    }

    @Test
    void signupCreatesUserWhenUsernameAndEmailAreAvailable() throws Exception {
        Role userRole = new Role(ERole.ROLE_USER);
        when(userRepository.existsByUsername("new-user")).thenReturn(false);
        when(userRepository.existsByEmail("new-user@example.com")).thenReturn(false);
        when(roleRepository.findByName(ERole.ROLE_USER)).thenReturn(java.util.Optional.of(userRole));
        when(encoder.encode("secret123")).thenReturn("encoded-secret");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        mockMvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "username": "new-user",
                      "email": "new-user@example.com",
                      "password": "secret123"
                    }
                    """))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.message").value("User registered successfully!"));

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        assertThat(savedUser.getUsername()).isEqualTo("new-user");
        assertThat(savedUser.getEmail()).isEqualTo("new-user@example.com");
        assertThat(savedUser.getPassword()).isEqualTo("encoded-secret");
        assertThat(savedUser.getRoles()).containsExactly(userRole);
    }

    @Test
    void signupReturnsBadRequestWhenUsernameAlreadyExists() throws Exception {
        when(userRepository.existsByUsername("taken")).thenReturn(true);

        mockMvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "username": "taken",
                      "email": "taken@example.com",
                      "password": "secret123"
                    }
                    """))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.message").value("Error: Username is already taken!"));
    }

    @Test
    void signupReturnsBadRequestWhenEmailAlreadyExists() throws Exception {
        when(userRepository.existsByUsername("new-user")).thenReturn(false);
        when(userRepository.existsByEmail("taken@example.com")).thenReturn(true);

        mockMvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "username": "new-user",
                      "email": "taken@example.com",
                      "password": "secret123"
                    }
                    """))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.message").value("Error: Email is already in use!"));
    }

    @Test
    void signupReturnsBadRequestWhenPayloadIsInvalid() throws Exception {
        mockMvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "username": "ab",
                      "email": "not-an-email",
                      "password": "123"
                    }
                    """))
            .andExpect(status().isBadRequest());
    }

    @Test
    void signoutClearsJwtCookie() throws Exception {
        when(jwtUtils.getCleanJwtCookie())
            .thenReturn(ResponseCookie.from("starter", "").path("/api").build());

        mockMvc.perform(post("/api/auth/signout"))
            .andExpect(status().isOk())
            .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("starter=")))
            .andExpect(jsonPath("$.message").value("You've been signed out!"));
    }
}


