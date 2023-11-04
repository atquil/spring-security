package com.atquil.springSecurity.config;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author atquil
 */

@Configuration
@EnableWebSecurity // This will enable us to override the default security behaviour of spring security.
public class SecurityConfig {
        // Quick tip : Never disable CSRF withouth leaving session managment enable
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
                //Disable cross site request forgery
                .csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.disable())
                //Now this will dictate what we want to do with request : Authenticate any request
                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry ->
                        authorizationManagerRequestMatcherRegistry
                                .anyRequest()
                                .authenticated()
                    )
                // Let's work with session Management
                .sessionManagement((httpSecuritySessionManagementConfigurer ->
                        httpSecuritySessionManagementConfigurer
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)))
                //Now how you want , the login process to happen : We are using basic http login that we have by default
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    // Create a default user for now
    @Bean
    public InMemoryUserDetailsManager user(){
        return new InMemoryUserDetailsManager(
                User.withUsername("atquil")
                        .password("{noop}password") //encrypt the password.usng bean
                        .authorities("read")
                        .build()
        );
    }
}
