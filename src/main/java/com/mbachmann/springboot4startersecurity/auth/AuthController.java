package com.mbachmann.springboot4startersecurity.auth;

import com.mbachmann.springboot4startersecurity.auth.dto.AuthResponse;
import com.mbachmann.springboot4startersecurity.auth.dto.LoginRequest;
import com.mbachmann.springboot4startersecurity.auth.dto.SignupRequest;
import com.mbachmann.springboot4startersecurity.auth.dto.UserProfileResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/signup")
    @ResponseStatus(HttpStatus.CREATED)
    AuthResponse signup(@Valid @RequestBody SignupRequest request) {
        return authService.signup(request);
    }

    @PostMapping("/login")
    AuthResponse login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @GetMapping("/me")
    UserProfileResponse me(@AuthenticationPrincipal Jwt jwt) {
        return new UserProfileResponse(jwt.getSubject(), jwt.getClaimAsString("username"));
    }
}
