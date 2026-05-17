package com.example.starter.repository;

import com.example.starter.model.entity.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Test
    void findByUsernameAndEmailReturnsSavedUser() {
        User savedUser = userRepository.save(new User("alice", "alice@example.com", "password"));

        assertThat(userRepository.findByUsername("alice"))
            .isPresent()
            .get()
            .extracting(User::getId, User::getUsername, User::getEmail)
            .containsExactly(savedUser.getId(), "alice", "alice@example.com");

        assertThat(userRepository.findByEmail("alice@example.com"))
            .isPresent()
            .get()
            .extracting(User::getId, User::getUsername, User::getEmail)
            .containsExactly(savedUser.getId(), "alice", "alice@example.com");
    }

    @Test
    void existsByUsernameAndEmailReturnExpectedFlags() {
        userRepository.save(new User("bob", "bob@example.com", "password"));

        assertThat(userRepository.existsByUsername("bob")).isTrue();
        assertThat(userRepository.existsByEmail("bob@example.com")).isTrue();
        assertThat(userRepository.existsByUsername("missing")).isFalse();
        assertThat(userRepository.existsByEmail("missing@example.com")).isFalse();
    }
}


