package com.atquil.springSecurity;

import com.atquil.springSecurity.config.JWTConfig.RSAKeyRecord;
import com.atquil.springSecurity.repo.UserDetailsRepo;
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
    CommandLineRunner commandLineRunner(UserDetailsRepo userDetailsRepo, PasswordEncoder passwordEncoder){
        return args -> {
    //Better to initial in saperate class.
//            UserDetailsEntity manager = new UserDetailsEntity();
//            manager.setUserName("Manager");
//            manager.setPassword(passwordEncoder.encode("password"));
//            manager.setRoles("ROLE_MANAGER");
//            manager.setEmailId("manager@manager.com");
//

//            userInfoRepo.save(manager);

        };
    }
}
