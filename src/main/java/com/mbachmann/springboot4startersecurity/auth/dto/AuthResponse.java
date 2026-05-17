package com.mbachmann.springboot4startersecurity.auth.dto;

public record AuthResponse(String accessToken, String email, String username) {
}
