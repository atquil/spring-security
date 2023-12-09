package com.atquil.springSecurity;

import com.atquil.springSecurity.entity.UserEntity;
import com.atquil.springSecurity.repo.UserRepo;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class SpringSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityApplication.class, args);
    }

    //Command line runner: After the application context, but before the application starts
    @Bean
    CommandLineRunner commandLineRunner(UserRepo userRepo, PasswordEncoder passwordEncoder){
        return args -> {
            UserEntity userEntity = new UserEntity();
            userEntity.setUsername("atquil");
            userEntity.setPassword(passwordEncoder.encode("password"));
            userEntity.setRoles("ROLE_USER,ROLE_ADMIN");
            userRepo.save(userEntity);
        };
    }
}
