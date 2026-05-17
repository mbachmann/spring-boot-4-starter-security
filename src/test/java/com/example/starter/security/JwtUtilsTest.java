package com.example.starter.security;

import com.example.starter.service.UserDetailsImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JwtUtilsTest {

    private JwtUtils jwtUtils;

    @BeforeEach
    void setUp() {
        jwtUtils = new JwtUtils();
        ReflectionTestUtils.setField(jwtUtils, "jwtSecret", "01234567890123456789012345678901");
        ReflectionTestUtils.setField(jwtUtils, "jwtExpirationMs", 60000);
        ReflectionTestUtils.setField(jwtUtils, "jwtCookie", "starter");
    }

    @Test
    void generateAndValidateTokenFromUserDetailsWorks() {
        UserDetailsImpl userDetails = new UserDetailsImpl(
            7L,
            "alice",
            "alice@example.com",
            "password",
            List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        String token = jwtUtils.generateJwtToken(userDetails);

        assertThat(token).isNotBlank();
        assertThat(jwtUtils.validateJwtToken(token)).isTrue();
        assertThat(jwtUtils.getUserNameFromJwtToken(token)).isEqualTo("alice");
    }

    @Test
    void validateJwtTokenReturnsFalseForExpiredToken() {
        JwtUtils shortLivedJwtUtils = new JwtUtils();
        ReflectionTestUtils.setField(shortLivedJwtUtils, "jwtSecret", "01234567890123456789012345678901");
        ReflectionTestUtils.setField(shortLivedJwtUtils, "jwtExpirationMs", -1);
        ReflectionTestUtils.setField(shortLivedJwtUtils, "jwtCookie", "starter");

        UserDetailsImpl userDetails = new UserDetailsImpl(
            2L,
            "eve",
            "eve@example.com",
            "password",
            List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        String expiredToken = shortLivedJwtUtils.generateJwtToken(userDetails);

        assertThat(shortLivedJwtUtils.validateJwtToken(expiredToken)).isFalse();
    }

    @Test
    void generateBearerTokenHasExpectedPrefix() {
        UserDetailsImpl userDetails = new UserDetailsImpl(
            1L,
            "bob",
            "bob@example.com",
            "password",
            List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );

        String bearerToken = jwtUtils.generateBearerToken(userDetails);

        assertThat(bearerToken).startsWith("Bearer ");
        assertThat(jwtUtils.validateJwtToken(bearerToken.substring("Bearer ".length()))).isTrue();
    }

    @Test
    void getJwtFromServletCookiesReturnsCookieValue() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new jakarta.servlet.http.Cookie("starter", "cookie-token"));

        assertThat(jwtUtils.getJwtFromCookies(request)).isEqualTo("cookie-token");
    }

    @Test
    void getJwtFromServletCookiesReturnsNullWhenMissing() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        assertThat(jwtUtils.getJwtFromCookies(request)).isNull();
    }


    @Test
    void validateJwtTokenFromRequestUsesAuthorizationHeader() {
        UserDetailsImpl userDetails = new UserDetailsImpl(
            11L,
            "charlie",
            "charlie@example.com",
            "password",
            List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        String token = jwtUtils.generateJwtToken(userDetails);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);

        assertThat(jwtUtils.validateJwtToken(request)).isTrue();
    }

    @Test
    void validateJwtTokenReturnsFalseForMalformedToken() {
        assertThat(jwtUtils.validateJwtToken("not-a-jwt")).isFalse();
    }

    @Test
    void validateJwtTokenReturnsFalseWhenSignatureDoesNotMatch() {
        UserDetailsImpl userDetails = new UserDetailsImpl(
            21L,
            "frank",
            "frank@example.com",
            "password",
            List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        String token = jwtUtils.generateJwtToken(userDetails);

        JwtUtils differentSecretJwtUtils = new JwtUtils();
        ReflectionTestUtils.setField(differentSecretJwtUtils, "jwtSecret", "abcdefghijklmnopqrstuvwxyz123456");
        ReflectionTestUtils.setField(differentSecretJwtUtils, "jwtExpirationMs", 60000);
        ReflectionTestUtils.setField(differentSecretJwtUtils, "jwtCookie", "starter");

        assertThat(differentSecretJwtUtils.validateJwtToken(token)).isFalse();
    }

    @Test
    void validateJwtTokenFromRequestFallsBackToCookie() {
        UserDetailsImpl userDetails = new UserDetailsImpl(
            12L,
            "dana",
            "dana@example.com",
            "password",
            List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        String token = jwtUtils.generateJwtToken(userDetails);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new jakarta.servlet.http.Cookie("starter", token));

        assertThat(jwtUtils.validateJwtToken(request)).isTrue();
    }

    @Test
    void validateJwtTokenFromRequestReturnsFalseForMalformedBearerHeader() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer not-a-jwt");

        assertThat(jwtUtils.validateJwtToken(request)).isFalse();
    }

    @Test
    void getCleanJwtCookieBuildsCookieForApiPath() {
        var cleanCookie = jwtUtils.getCleanJwtCookie();

        assertThat(cleanCookie.toString()).contains("starter=");
        assertThat(cleanCookie.toString()).contains("Path=/api");
    }
}

