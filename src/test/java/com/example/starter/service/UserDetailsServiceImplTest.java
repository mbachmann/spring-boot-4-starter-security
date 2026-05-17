package com.example.starter.service;

import com.example.starter.model.entity.ERole;
import com.example.starter.model.entity.Role;
import com.example.starter.model.entity.User;
import com.example.starter.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserDetailsServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserDetailsServiceImpl userDetailsService;

    @Test
    void loadUserByUsernameReturnsMappedUserDetailsWhenUserExists() {
        User user = new User(1L, "alice", "alice@example.com", "encoded", Set.of(new Role(ERole.ROLE_USER)));
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));

        UserDetails userDetails = userDetailsService.loadUserByUsername("alice");

        assertThat(userDetails).isInstanceOf(UserDetailsImpl.class);
        UserDetailsImpl mapped = (UserDetailsImpl) userDetails;
        assertThat(mapped.getId()).isEqualTo(1L);
        assertThat(mapped.getUsername()).isEqualTo("alice");
        assertThat(mapped.getEmail()).isEqualTo("alice@example.com");
        assertThat(mapped.getAuthorities()).extracting("authority").containsExactly("ROLE_USER");
    }

    @Test
    void loadUserByUsernameThrowsWhenUserDoesNotExist() {
        when(userRepository.findByUsername("missing")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userDetailsService.loadUserByUsername("missing"))
            .isInstanceOf(UsernameNotFoundException.class)
            .hasMessage("User Not Found with username: missing");
    }
}

