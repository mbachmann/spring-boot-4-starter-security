package com.example.starter.config;

import com.example.starter.model.entity.ERole;
import com.example.starter.model.entity.Role;
import com.example.starter.model.entity.User;
import com.example.starter.repository.RoleRepository;
import com.example.starter.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SetupDataLoaderTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private SetupDataLoader setupDataLoader;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(setupDataLoader, "alreadySetup", false);
    }

    @Test
    void createRoleIfNotFoundReturnsExistingRoleWithoutSaving() {
        Role existing = new Role(1, ERole.ROLE_USER);
        when(roleRepository.findByName(ERole.ROLE_USER)).thenReturn(Optional.of(existing));

        Role result = setupDataLoader.createRoleIfNotFound(ERole.ROLE_USER);

        assertThat(result).isSameAs(existing);
        verify(roleRepository, never()).save(any(Role.class));
    }

    @Test
    void createRoleIfNotFoundCreatesRoleWhenMissing() {
        when(roleRepository.findByName(ERole.ROLE_MODERATOR)).thenReturn(Optional.empty());
        when(roleRepository.save(any(Role.class))).thenAnswer(invocation -> invocation.getArgument(0));

        Role result = setupDataLoader.createRoleIfNotFound(ERole.ROLE_MODERATOR);

        assertThat(result.getName()).isEqualTo(ERole.ROLE_MODERATOR);
        verify(roleRepository).save(any(Role.class));
    }

    @Test
    void createUserIfNotFoundReturnsExistingUserWithoutSaving() {
        User existing = new User("alice", "alice@example.com", "encoded");
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(existing));

        User result = setupDataLoader.createUserIfNotFound("alice", "alice@example.com", "raw", java.util.Set.of());

        assertThat(result).isSameAs(existing);
        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void createUserIfNotFoundEncodesPasswordAndSavesWhenMissing() {
        Role role = new Role(2, ERole.ROLE_USER);
        when(userRepository.findByUsername("bob")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("secret")).thenReturn("encoded-secret");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        User result = setupDataLoader.createUserIfNotFound("bob", "bob@example.com", "secret", java.util.Set.of(role));

        assertThat(result.getUsername()).isEqualTo("bob");
        assertThat(result.getEmail()).isEqualTo("bob@example.com");
        assertThat(result.getPassword()).isEqualTo("encoded-secret");
        assertThat(result.getRoles()).containsExactly(role);
    }

    @Test
    void onApplicationEventInitializesUsersOnceAndThenSkips() {
        Role adminRole = new Role(1, ERole.ROLE_ADMIN);
        Role userRole = new Role(2, ERole.ROLE_USER);
        Role moderatorRole = new Role(3, ERole.ROLE_MODERATOR);

        when(roleRepository.findByName(ERole.ROLE_ADMIN)).thenReturn(Optional.of(adminRole));
        when(roleRepository.findByName(ERole.ROLE_USER)).thenReturn(Optional.of(userRole));
        when(roleRepository.findByName(ERole.ROLE_MODERATOR)).thenReturn(Optional.of(moderatorRole));

        when(userRepository.findByUsername(anyString())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(anyString())).thenAnswer(invocation -> "enc-" + invocation.getArgument(0));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        setupDataLoader.onApplicationEvent(null);

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository, times(3)).save(userCaptor.capture());
        assertThat(userCaptor.getAllValues()).extracting(User::getUsername)
            .containsExactlyInAnyOrder("admin", "user", "moderator");
        assertThat(userCaptor.getAllValues()).extracting(User::getPassword)
            .containsExactlyInAnyOrder("enc-admin", "enc-user", "enc-moderator");
        assertThat((Boolean) ReflectionTestUtils.getField(setupDataLoader, "alreadySetup")).isTrue();

        clearInvocations(userRepository, roleRepository, passwordEncoder);
        setupDataLoader.onApplicationEvent(null);

        verify(userRepository, never()).save(any(User.class));
        verify(roleRepository, never()).save(any(Role.class));
    }
}

