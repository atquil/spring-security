package com.atquil.springSecurity;

import com.atquil.springSecurity.config.RSAKeyRecord;
import com.atquil.springSecurity.entities.UserInfoEntity;
import com.atquil.springSecurity.enums.UserRole;
import com.atquil.springSecurity.repo.UserInfoRepo;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
@EnableConfigurationProperties(RSAKeyRecord.class)
public class SpringSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityApplication.class, args);
    }

    @Bean
    CommandLineRunner commandLineRunner(UserInfoRepo userInfoRepo, PasswordEncoder passwordEncoder){
        return args -> {
            UserInfoEntity userInfoEntity = new UserInfoEntity();
            userInfoEntity.setUserName("Alpha");
            userInfoEntity.setPassword(passwordEncoder.encode("password"));
            userInfoEntity.setRole("ROLE_USER");
            userInfoEntity.setEmailId("abc@d.com");
            userInfoRepo.save(userInfoEntity);
        };
    }
}
