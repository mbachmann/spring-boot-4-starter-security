package com.example.starter.repository;

import com.example.starter.model.entity.ERole;
import com.example.starter.model.entity.Role;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class RoleRepositoryTest {

    @Autowired
    private RoleRepository roleRepository;

    @Test
    void findByNameReturnsSavedRoleForEachEnumValue() {
        roleRepository.save(new Role(ERole.ROLE_USER));
        roleRepository.save(new Role(ERole.ROLE_MODERATOR));
        roleRepository.save(new Role(ERole.ROLE_ADMIN));

        assertThat(roleRepository.findByName(ERole.ROLE_USER)).isPresent().get().extracting(Role::getName)
            .isEqualTo(ERole.ROLE_USER);
        assertThat(roleRepository.findByName(ERole.ROLE_MODERATOR)).isPresent().get().extracting(Role::getName)
            .isEqualTo(ERole.ROLE_MODERATOR);
        assertThat(roleRepository.findByName(ERole.ROLE_ADMIN)).isPresent().get().extracting(Role::getName)
            .isEqualTo(ERole.ROLE_ADMIN);
        assertThat(roleRepository.findByName(null)).isEmpty();
    }
}


