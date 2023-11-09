# spring-security

### Setup Project :

Spring Initializer : https://start.spring.io/


## Steps: 


### Create JWT Token 

1. As we are creating asymetric JWT Token, create priate and public keys and save it in `resource/cert` folder

- Private Key for encryption
```
openssl genrsa -out keypair.pem 2048   
```
- Generate a public key from the private key that you just created
```
 openssl rsa -in keypair.pem -pubout -out publicKey.pem 

```
Now we need to format the private key (keypair.pem) in supported format (PKCS8 format)

```
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out private.pem
```

2.  Add the reference of those keys, from the properties file to be used in RSAKeyRecord. [Externalise the private and public key]

- Location of file in properties. 

```properties
rsa:
  rsa-private-key: classpath:certs/private.pem
  rsa-public-key: classpath:certs/publicKey.pem
```

- Inside `RSAKeyRecord.class` which holds, both public and private key that will be used by JWT

```java
@ConfigurationProperties(prefix = "rsa")
public record RSAKeyRecord (RSAPublicKey rsaPublicKey, RSAPrivateKey rsaPrivateKey){

}
```

- `EnableConfiguraitonProperties` will enable JWT to take Create a class through which you will access the key
- 
```java

@EnableConfigurationProperties(RSAKeyRecord.class)
@SpringBootApplication
public class SpringSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityApplication.class, args);
    }

}
```

3. As once `SecurityFilterChain` finds out it's using JWT, it will require a JWTDecoder to resolve the request. So let's add that 

- Create securityFilter chain 
```java

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    @Bean
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(csrf->csrf.disable())
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(
                        (ex) -> ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
                                .accessDeniedHandler(new BearerTokenAccessDeniedHandler()))
                .httpBasic(withDefaults()) 
                .build();
    }

}
```

- Encoder 
```java

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final RSAKeyRecord rsaKeyRecord;

    //.... Security filter chain config
    @Bean
    JwtDecoder jwtDecoder(){
        return NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();
    }
}
```

- Decoder

```java
@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final RSAKeyRecord rsaKeyRecord;

    //.... Security filter chain config
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

```

5. Now create a `service` to use JwtEncoder, to generate token, which will be used to get the API values

```java

@Service
@RequiredArgsConstructor
public class TokenGenerator {

    private final JwtEncoder jwtEncoder;

    public String generateToken(Authentication authentication) {
        Instant now = Instant.now();
        //Scope of the request, is what we get from authentication 
        String scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
        
        
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self") //we are self signing the jwt
                .issuedAt(now)
                .expiresAt(now.plus(1, ChronoUnit.HOURS)) // expires in hour
                .subject(authentication.getName())
                .claim("scope", scope) // whatever we have fixed the authority
                .build();
        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }
}
```

6. Now, let's create a API which will use it to generate the token.. 
```java
@RestController
@Slf4j
@RequiredArgsConstructor
public class TokenAPI {

    private final TokenGenerator tokenGenerator;

    @PostMapping("/token")
    public ResponseEntity<String> generateJWTToken(Authentication authentication){
        //This api will take value from basic authentication, and generate the token
        String token = tokenGenerator.generateToken(authentication);
        log.info("Token generated for {} :  {}", authentication.getName(),token);
        return ResponseEntity.ok(token);
    }
}
```

7. Let's create a dummy user

```java
@Configuration
public class UserInfoDetails {

    @Bean
    public InMemoryUserDetailsManager user(){
        return new InMemoryUserDetailsManager(
                User.withUsername("atquil")
                        .password("{noop}password")
                        .authorities("ADMIN")
                        .build()
        );
    }
}

```



8. Test the API in postman with `basic auth` to generate `token` which will be used by other API

![tokenGenerated.png](src%2Fmain%2Fresources%2Fimages%2FtokenGenerated.png)


9. Add some other API's which will be required to be access by token

```java
@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/user")
public class UserAPI {

    @GetMapping("/details")
    public ResponseEntity<String> getResponse(){
        return ResponseEntity.ok("I am the user");
    }

}

```
![getUserDetialsUsingToken.png](src%2Fmain%2Fresources%2Fimages%2FgetUserDetialsUsingToken.png)


** As we are using `httpBasic(withDefaults)` in security config it creates a problem. Though now you can generate token, but your API's can be accessed by both Basic and Token, but we want only token. **

### Create multiple filterChain to access the token using basic auth, and access the home page and user page using token

1. `SecurityConfig` modification using `@Order` which tell us in which order we need to read the file, lowest at top. 

- Create `tokenSecurityFilterChain` and `userSecurityFilterChain` 

```java

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final RSAKeyRecord rsaKeyRecord;

    //Let's first secure the /user api that must be accessed
//    @Bean
//    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
//        return httpSecurity
//                .csrf(csrf->csrf.disable())
//                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
//                .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
//                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .exceptionHandling(
//                        (ex) -> ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
//                                .accessDeniedHandler(new BearerTokenAccessDeniedHandler()))
//                .httpBasic(withDefaults())
//                .build();
//    }

    //Once apiSecurityFilterChain runs, it will try to find JWTDecoder bean, as to decode any request.


    //Using Basic security for granting access to token
    @Order(1)
    @Bean
    public SecurityFilterChain tokenSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
                .securityMatcher(new AntPathRequestMatcher("/token"))
                .csrf(csrf->csrf.disable())
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex -> {
                    ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint());
                    ex.accessDeniedHandler(new BearerTokenAccessDeniedHandler());
                })
                .httpBasic(withDefaults())
                .build();
    }


    @Order(2)
    @Bean
    public SecurityFilterChain userSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
                .securityMatcher(new AntPathRequestMatcher("/user/**"))
                .csrf(csrf->csrf.disable())
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
                .exceptionHandling(ex -> {
                    ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint());
                    ex.accessDeniedHandler(new BearerTokenAccessDeniedHandler());
                })
                .build();
    }


    @Bean
    JwtDecoder jwtDecoder(){
        return NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();
    }

    @Bean
    JwtEncoder jwtEncoder(){
        JWK jwk = new RSAKey.Builder(rsaKeyRecord.rsaPublicKey()).privateKey(rsaKeyRecord.rsaPrivateKey()).build();
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwkSource);
    }
}
```

- Token Generating using basic auth
![tokenGeneratingUsingBasicAuth.png](src%2Fmain%2Fresources%2Fimages%2FtokenGeneratingUsingBasicAuth.png)
- Not able to see the user details usign basic auth
![notAbleToAccessUsingBasicAuth.png](src%2Fmain%2Fresources%2Fimages%2FnotAbleToAccessUsingBasicAuth.png)
- Able to see the user details using token
![userUsingToken.png](src%2Fmain%2Fresources%2Fimages%2FuserUsingToken.png)

## Now let's also access the API from database user. 

- Configure h2-console 
```properties
    spring:
        h2:
            console:
                enabled: true
```
- Allow `h2-console` to be accessed without using any auth. 

```java
@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {
    // ......
    @Order(3)
    @Bean
    public SecurityFilterChain h2ConsoleSecurityFilterChainConfig(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
                .securityMatcher(new AntPathRequestMatcher(("/h2-console/**")))
                .authorizeHttpRequests(auth->auth.anyRequest().permitAll())
                .csrf(csrf -> csrf.ignoringRequestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")))
                .headers(headers -> headers.frameOptions(withDefaults()).disable())
                .build();
    }
    // ......
}
```
- Create a class `DatabaseCreation` to create a database for h2-console. Also add a user with encrypted password (You can directly connect with your db using properties file)

```java
@Configuration
public class UserInfoDetails {

//    @Bean
//    public InMemoryUserDetailsManager user(){
//        return new InMemoryUserDetailsManager(
//                User.withUsername("atquil")
//                        .password("{noop}password")
//                        .authorities("ADMIN")
//                        .build()
//        );
//    }

    @Bean
    EmbeddedDatabase datasource(){
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2) 
                .setName("atquilDB")
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }
    @Bean
    JdbcUserDetailsManager userDetailsManager(DataSource dataSource) {
        UserDetails userDetails = User.builder()
                .username("atquil")
                .password(passwordEncoder().encode("password"))
                .roles("ADMIN")
                .build();
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(userDetails);
        return jdbcUserDetailsManager;
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


}

```

Outputs
- Able to login in the h2-console, and see the new user is present there http://localhost:8080/h2-console
![userDetialsInH2-console.png](src%2Fmain%2Fresources%2Fimages%2FuserDetialsInH2-console.png)

- Now you can again call the api's to create token and use it to access the userDetails. 



