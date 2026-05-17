package com.mbachmann.springboot4startersecurity.auth;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class InMemoryUserService implements UserDetailsService {

    private final Map<String, AppUser> usersByEmail = new ConcurrentHashMap<>();

    AppUser register(String username, String email, String passwordHash) {
        String normalizedEmail = normalize(email);
        AppUser user = new AppUser(username, normalizedEmail, passwordHash);
        if (usersByEmail.putIfAbsent(normalizedEmail, user) != null) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email is already registered");
        }
        return user;
    }

    Optional<AppUser> findByEmail(String email) {
        return Optional.ofNullable(usersByEmail.get(normalize(email)));
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        AppUser user = findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("Unknown email: " + username));
        return User.withUsername(user.email())
                .password(user.passwordHash())
                .roles("USER")
                .build();
    }

    private String normalize(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }
}
