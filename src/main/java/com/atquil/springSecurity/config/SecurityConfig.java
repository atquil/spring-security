package com.atquil.springSecurity.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author atquil
 */

@Configuration
@EnableWebSecurity // This will enable us to override the default security behaviour of spring security.
@RequiredArgsConstructor
public class SecurityConfig {
        // Quick tip : Never disable CSRF withouth leaving session managment enable

    private final RSAKeyRecord rsaKeyRecord;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
                //Disable cross site request forgery
                .csrf(AbstractHttpConfigurer::disable)
                //Now this will dictate what we want to do with request : Authenticate any request
                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry ->
                        authorizationManagerRequestMatcherRegistry
                                .anyRequest()
                                .authenticated()
                )
                //Resource Server (Now we are using self-signed JWT resource server, but we can use external as well
                .oauth2ResourceServer(httpSecurityOAuth2ResourceServerConfigurer -> httpSecurityOAuth2ResourceServerConfigurer.jwt(Customizer.withDefaults()))
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


    @Bean
    JwtDecoder jwtDecoder(){
        return NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();
    }

    @Bean
    JwtEncoder jwtEncoder(){
        //Nimbus need a source
        JWK jwk = new RSAKey.Builder(rsaKeyRecord.rsaPublicKey()).privateKey(rsaKeyRecord.rsaPrivateKey()).build();
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwkSource);
    }

}
