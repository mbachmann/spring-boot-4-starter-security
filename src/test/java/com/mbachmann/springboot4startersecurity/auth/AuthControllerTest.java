package com.mbachmann.springboot4startersecurity.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "security.jwt.secret=test-secret-key-test-secret-key-1234")
class AuthControllerTest {

    @Autowired
    private ObjectMapper objectMapper;

    @LocalServerPort
    private int port;

    private final HttpClient httpClient = HttpClient.newHttpClient();

    @Test
    void signupReturnsJwtAndAllowsAccessToProtectedProfile() throws Exception {
        String email = uniqueEmail();

        HttpResponse<String> signupResponse = post("/api/auth/signup", """
                {
                  "username": "alice",
                  "email": "%s",
                  "password": "password123"
                }
                """.formatted(email));

        assertEquals(201, signupResponse.statusCode());
        JsonNode response = objectMapper.readTree(signupResponse.body());
        assertEquals(email, response.get("email").asText());
        assertEquals("alice", response.get("username").asText());
        assertTrue(response.get("accessToken").asText().length() > 20);
        String token = response.get("accessToken").asText();

        HttpResponse<String> meResponse = get("/api/auth/me", token);
        assertEquals(200, meResponse.statusCode());

        JsonNode profile = objectMapper.readTree(meResponse.body());
        assertEquals(email, profile.get("email").asText());
        assertEquals("alice", profile.get("username").asText());
    }

    @Test
    void loginReturnsJwtForRegisteredUser() throws Exception {
        String email = uniqueEmail();
        register(email, "bob");

        HttpResponse<String> loginResponse = post("/api/auth/login", """
                {
                  "email": "%s",
                  "password": "password123"
                }
                """.formatted(email));

        assertEquals(200, loginResponse.statusCode());
        JsonNode response = objectMapper.readTree(loginResponse.body());
        assertEquals(email, response.get("email").asText());
        assertEquals("bob", response.get("username").asText());
        assertTrue(response.get("accessToken").asText().length() > 20);
    }

    @Test
    void signupRejectsDuplicateEmail() throws Exception {
        String email = uniqueEmail();
        register(email, "carol");

        HttpResponse<String> duplicateSignup = post("/api/auth/signup", """
                {
                  "username": "carol-2",
                  "email": "%s",
                  "password": "password123"
                }
                """.formatted(email));

        assertEquals(409, duplicateSignup.statusCode());
    }

    private void register(String email, String username) throws Exception {
        assertEquals(201, post("/api/auth/signup", """
                {
                  "username": "%s",
                  "email": "%s",
                  "password": "password123"
                }
                """.formatted(username, email)).statusCode());
    }

    private String uniqueEmail() {
        return UUID.randomUUID() + "@example.com";
    }

    private HttpResponse<String> post(String path, String body) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl() + path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get(String path, String token) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(baseUrl() + path)).GET();
        if (token != null) {
            request.header("Authorization", "Bearer " + token);
        }
        return httpClient.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private String baseUrl() {
        return "http://localhost:" + port;
    }
}
