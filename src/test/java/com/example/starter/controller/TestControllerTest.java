package com.example.starter.controller;

import org.junit.jupiter.api.Test;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(TestController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import(TestControllerTest.MethodSecurityTestConfig.class)
class TestControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void publicEndpointsAreAccessibleWithoutAuthentication() throws Exception {
        mockMvc.perform(get("/api/test/all"))
            .andExpect(status().isOk())
            .andExpect(content().string("Public Content."));

        mockMvc.perform(post("/api/test/all"))
            .andExpect(status().isOk())
            .andExpect(content().string("Public Content Post."));
    }

    @Test
    void securedEndpointWithoutAuthenticationIsRejected() {
        assertThatThrownBy(() -> mockMvc.perform(get("/api/test/user")))
            .hasRootCauseInstanceOf(AuthenticationCredentialsNotFoundException.class);
    }

    @Test
    @WithMockUser(roles = "USER")
    void userEndpointAllowsUserRole() throws Exception {
        mockMvc.perform(get("/api/test/user"))
            .andExpect(status().isOk())
            .andExpect(content().string("User Content."));
    }

    @Test
    @WithMockUser(roles = "MODERATOR")
    void moderatorEndpointAllowsModeratorRole() throws Exception {
        mockMvc.perform(get("/api/test/mod"))
            .andExpect(status().isOk())
            .andExpect(content().string("Moderator Board."));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void adminEndpointAllowsAdminRole() throws Exception {
        mockMvc.perform(get("/api/test/admin"))
            .andExpect(status().isOk())
            .andExpect(content().string("Admin Board."));
    }

    @Test
    @WithMockUser(roles = "USER")
    void moderatorEndpointRejectsNonModeratorRole() throws Exception {
        mockMvc.perform(get("/api/test/mod"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "USER")
    void adminEndpointRejectsNonAdminRole() throws Exception {
        mockMvc.perform(get("/api/test/admin"))
            .andExpect(status().isUnauthorized());
    }

    @TestConfiguration
    @EnableMethodSecurity
    static class MethodSecurityTestConfig {
    }
}




