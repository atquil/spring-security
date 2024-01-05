package com.atquil.springSecurity.config.userConfig;

import com.atquil.springSecurity.entities.UserDetailsEntity;
import com.atquil.springSecurity.repo.UserDetailsRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * @author atquil
 */
@RequiredArgsConstructor
@Component
@Slf4j
public class InitialUserData implements CommandLineRunner {

    private final UserDetailsRepo userDetailsRepo;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        UserDetailsEntity manager = new UserDetailsEntity();
        manager.setUserName("Manager");
        manager.setPassword(passwordEncoder.encode("password"));
        manager.setRoles("ROLE_MANAGER");
        manager.setEmailId("manager@manager.com");

        UserDetailsEntity admin = new UserDetailsEntity();
        admin.setUserName("Admin");
        admin.setPassword(passwordEncoder.encode("password"));
        admin.setRoles("ROLE_ADMIN,ROLE_MANAGER");
        admin.setEmailId("admin@admin.com");

        UserDetailsEntity user = new UserDetailsEntity();
        user.setUserName("User");
        user.setPassword(passwordEncoder.encode("password"));
        user.setRoles("ROLE_USER");
        user.setEmailId("user@user.com");

        userDetailsRepo.saveAll(List.of(manager,admin,user));
    }
}
