# spring-security
This tutorial will provide a step-by-step guide to implementing these features in your Spring Boot application.
You will learn how to configure Spring Security to work with JWT, define data models and associations for authentication and authorization,
use Spring Data JPA to interact with H2 Database, and create REST controllers. 
You will also learn how to handle exceptions, define payloads, and run and check your application.

The tutorial will cover the following topics:

* **Spring Security**: A powerful and highly customizable authentication and access-control framework.
* **OAuth JWT**: A secure and efficient way to handle authentication and authorization between different parties.
* **HttpOnly Cookie**: A cookie attribute that prevents client-side scripts from accessing the cookie.
* **AuthFilter**: A filter that intercepts requests and performs authentication and authorization checks.
* **H2 Database**: A lightweight and fast in-memory database that supports SQL and JDBC.
* **Login Logout**: A mechanism to authenticate and de-authenticate users.
RefreshToken Access Token: A technique to refresh the access token without requiring the user to re-authenticate.

OAuth2 and JWT serve different purposes. OAuth2 defines a protocol that specifies how tokens are transferred, while JWT defines a token format

## Part 1: Project Setup :

1. Spring Initializer : https://start.spring.io/
2. Dependency : `web`,  `lombock`, `validation`, `h2`, `jpa`, `oauth2`, `configuration-processor`
    ```
        implementation 'org.springframework.boot:spring-boot-starter-web'
        compileOnly 'org.projectlombok:lombok'
        annotationProcessor 'org.projectlombok:lombok'
        testImplementation 'org.springframework.boot:spring-boot-starter-test'
    
        //Validation
        implementation 'org.springframework.boot:spring-boot-starter-validation'
    
        //Database:
        runtimeOnly 'com.h2database:h2' // You can use any sql database
        implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    
        //security:
        //jwt
        implementation 'org.springframework.boot:spring-boot-starter-oauth2-resource-server'
        annotationProcessor 'org.springframework.boot:spring-boot-configuration-processor'
    ```

3. `application.yml` : Database Setup

    ```properties
    spring:
      h2:
        console:
          enabled: true
      datasource:
        url: jdbc:h2:mem:atquilDB
        username: sa
        password:
        driverClassName: org.h2.Driver
      jpa:
        spring.jpa.database-platform: org.hibernate.dialect.H2Dialect
        show-sql: true
        hibernate:
          ddl-auto: create-drop
    logging:
      level:
        org.springframework.security: trace 
    ```

## Part 2: Store User using JPA

1. Create a `UserInfoEntity` to store User details. 

    ```java
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Entity
    @Table(name="USER_INFO")
    public class UserInfoEntity {
        @Id
        @GeneratedValue
        private Long id;
    
        @Column(name = "USER_NAME")
        private String userName;
    
        @Column(nullable = false, name = "EMAIL_ID", unique = true)
        private String emailId;
    
        @Column(nullable = false, name = "PASSWORD")
        private String password;
        
        @Column(name = "MOBILE_NUMBER")
        private String mobileNumber;
    
        @Column(nullable = false, name = "ROLES")
        private String roles;

    }
    
    ```
2. Create a file `UserInfoRepo` in `repo` package, to create `jpa-mapping` using hibernate. 

    ```java
    @Repository
    public interface UserInfoRepo extends JpaRepository<UserInfoEntity,Long> {
    }
    ```

3. Create a `UserInfoConfig` class which implements `UserDetails` interface, which **provides core user information which is later encapsulated into Authentication objects.**

   ```java
   @RequiredArgsConstructor
   public class UserInfoConfig implements UserDetails {
       private final UserInfoEntity userInfoEntity;
       @Override
       public Collection<? extends GrantedAuthority> getAuthorities() {
           return Arrays
                   .stream(userInfoEntity
                           .getRoles()
                           .split(","))
                   .map(SimpleGrantedAuthority::new)
                   .toList();
       }
   
       @Override
       public String getPassword() {
           return userInfoEntity.getPassword();
       }
   
       @Override
       public String getUsername() {
           return userInfoEntity.getEmailId();
       }
   
       @Override
       public boolean isAccountNonExpired() {
           return true;
       }
   
       @Override
       public boolean isAccountNonLocked() {
           return true;
       }
   
       @Override
       public boolean isCredentialsNonExpired() {
           return true;
       }
   
       @Override
       public boolean isEnabled() {
           return true;
       }
   }
   ```
4. Create a `UserInfoManagerConfig` class that implements the `UserDetailsService` interface, used to **retrieve user-related data, using loadUserByUsername(), and returns `UserDetails`**. 

   ```java
   @Service
   @RequiredArgsConstructor
   public class UserInfoManagerConfig implements UserDetailsService {
   
       private final UserInfoRepo userInfoRepo;
       @Override
       public UserDetails loadUserByUsername(String emailId) throws UsernameNotFoundException {
           return userInfoRepo
                   .findByEmailId(emailId)
                   .map(UserInfoConfig::new)
                   .orElseThrow(()-> new UsernameNotFoundException("UserEmail: "+emailId+" does not exist"));
       }
   }
   
   ```
   
    - Add the missing method findByEmailId in `userInfoRepo`
    ```java
    @Repository
    public interface UserInfoRepo extends JpaRepository<UserInfoEntity,Long> {
        Optional<UserInfoEntity> findByEmailId(String emailId);
    }
    ```
5. Let's modify our Security Setting, to let it access the API using our User. Create a `SecurityConfig` file in config package. 

   ```java
   @Configuration
   @EnableWebSecurity
   @EnableMethodSecurity
   @RequiredArgsConstructor
   public class SecurityConfig  {
   
       private final UserInfoManagerConfig userInfoManagerConfig;
   
       @Order(1)
       @Bean
       public SecurityFilterChain apiSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
           return httpSecurity
                   .securityMatcher(new AntPathRequestMatcher("/api/**"))
                   .csrf(AbstractHttpConfigurer::disable)
                   .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                   .userDetailsService(userInfoManagerConfig)
                   .formLogin(withDefaults())
                   .httpBasic(withDefaults())
                   .build();
       }
   
       @Order(2)
       @Bean
       public SecurityFilterChain h2ConsoleSecurityFilterChainConfig(HttpSecurity httpSecurity) throws Exception{
           return httpSecurity
                   .securityMatcher(new AntPathRequestMatcher(("/h2-console/**")))
                   .authorizeHttpRequests(auth->auth.anyRequest().permitAll())
                   .csrf(csrf -> csrf.ignoringRequestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")))
                    // to display the h2Console in Iframe
                   .headers(headers -> headers.frameOptions(withDefaults()).disable())
                   .build();
       }
      
   }

   ```
   
6. Let's create a package called `userConfig` and add few users to the database using `CommandlineRunner`
   ```java
   @RequiredArgsConstructor
   @Component
   @Slf4j
   public class InitialUserInfo implements CommandLineRunner {
       private final UserInfoRepo userInfoRepo;
       private final PasswordEncoder passwordEncoder;
       @Override
       public void run(String... args) throws Exception {
           UserInfoEntity manager = new UserInfoEntity();
           manager.setUserName("Manager");
           manager.setPassword(passwordEncoder.encode("password"));
           manager.setRoles("ROLE_MANAGER");
           manager.setEmailId("manager@manager.com");
   
           UserInfoEntity admin = new UserInfoEntity();
           admin.setUserName("Admin");
           admin.setPassword(passwordEncoder.encode("password"));
           admin.setRoles("ROLE_ADMIN");
           admin.setEmailId("admin@admin.com");
   
           UserInfoEntity user = new UserInfoEntity();
           user.setUserName("User");
           user.setPassword(passwordEncoder.encode("password"));
           user.setRoles("ROLE_USER");
           user.setEmailId("user@user.com");
   
           userInfoRepo.saveAll(List.of(manager,admin,user));
       }
   
   }
   
   ```
   - As we need to encrypt the password, let's add this in **securityConfig**
   ```java
   @Bean
   PasswordEncoder passwordEncoder() {
   return new BCryptPasswordEncoder();
   }
   ```
7. Add the Endpoints to access in `controller` package: `DashboardController.java`
    - In simpler terms, **authentication is the process of checking if a user is who they claim to be**, while **principal is the user who has been verified**.
    ```java
    @RestController
    @RequestMapping("/api")
    @RequiredArgsConstructor
    public class DashboardController {
    
        @PreAuthorize("hasAnyRole('ROLE_MANAGER','ROLE_ADMIN','ROLE_USER')")
        @GetMapping("/welcome-message")
        public ResponseEntity<String> getFirstWelcomeMessage(Authentication authentication){
            return ResponseEntity.ok("Welcome to the JWT Tutorial:"+authentication.getName()+"with scope:"+authentication.getAuthorities());
        }
    
        @PreAuthorize("hasRole('ROLE_MANAGER')")
        @GetMapping("/manager-message")
        public ResponseEntity<String> getManagerData(Principal principal){
            return ResponseEntity.ok("Admin::"+principal.getName());
    
        }
    
        @PreAuthorize("hasRole('ROLE_ADMIN')")
        @PostMapping("/admin-message")
        public ResponseEntity<String> getAdminData(@RequestParam("message") String message, Principal principal){
            return ResponseEntity.ok("Admin::"+principal.getName()+" has this message:"+message);
    
        }
    
    }
    ```

8. Test the API in PostMan
   - http://localhost:8080/h2-console/ , to see if data exist in the database
   - http://localhost:8080/api/welcome-message : Accessed by all
   - http://localhost:8080/api/manager-message : Manager and Admin
   - http://localhost:8080/api/admin-message: Only Admin **Params**


## Part 3: Return _Jwt Access Token_ while authenticating, and add `Roles` and `Permissions`

1. **Generating Asymmetric Keys with OpenSSL** :
   You have the option to create asymmetric keys (public and private keys) using OpenSSL or utilize the provided files in the repository located at resources/certs.

   Using OpenSSL (Optional)
   If you choose to generate your own keys, follow these steps:

   - Create a `certs folder` in the resources directory and navigate to it:
      ```
      mkdir -p src/main/resources/certs
      cd src/main/resources/certs
      ```
   
   - Generate a KeyPair :
      This line generates an RSA private key with a length of 2048 bits using OpenSSL (openssl genrsa). 
      It then specifies the output file (-out keypair.pem) where the generated private key will be saved. 
      The significance lies in creating a private key that can be used for encryption, decryption, and digital signatures in asymmetric cryptography.
      ```
      openssl genrsa -out keypair.pem 2048   
      ```
   - Generate a Public Key from the Private Key: 
       This command extracts the public key from the previously generated private key (openssl rsa). 
       It reads the private key from the file specified by -in keypair.pem and outputs the corresponding public key (-pubout) to a file named publicKey.pem. 
       The significance is in obtaining the public key from the private key, which can be shared openly for encryption and verification purposes while keeping 
       the private key secure.
      ```
       openssl rsa -in keypair.pem -pubout -out publicKey.pem 
      
      ```
   - Format the Private Key (keypair.pem) in Supported Format (PKCS8 format):
       This line converts the private key generated in the first step (keypair.pem) into PKCS#8 format, a widely used standard for private key encoding (openssl pkcs8). 
       It specifies that the input key format is PEM (-inform PEM), the output key format is also PEM (-outform PEM), and there is no encryption applied (-nocrypt). 
       The resulting private key is saved in a file named private.pem. 
       The significance is in converting the private key into a standard format that is interoperable across different cryptographic systems and applications.
      ```
      openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out privateKey.pem
      ```
     
      **If you want to apply encryption to the private key while exporting it using OpenSSL, you can simply omit the -nocrypt option in the openssl pkcs8 command. By doing so, OpenSSL will prompt you to enter a passphrase that will be used to encrypt the private key**
      **Note:  encrypting the private key adds an extra layer of security, but it also means that you'll need to provide the passphrase whenever you want to use the private key for cryptographic operations.**
   
   - Add the reference of those keys, from the properties file to be used in RSAKeyRecord. [Externalise the private and public key]
     Inside `RSAKeyRecord.class` which holds, both public and private key that will be used by JWT
      ```java
       @ConfigurationProperties(prefix = "jwt")
       public record RSAKeyRecord (RSAPublicKey rsaPublicKey, RSAPrivateKey rsaPrivateKey){
      
       }
      ```
   - `EnableConfiguraitonProperties` to enable it to be found in properties file.
      ```java
      
      @EnableConfigurationProperties(RSAKeyRecord.class)
      @SpringBootApplication
      public class SpringSecurityApplication {
      
          public static void main(String[] args) {
              SpringApplication.run(SpringSecurityApplication.class, args);
          }
      
      }
      ```
   - Location of file in properties.
     ```properties
        jwt:
          rsa-private-key: classpath:certs/privateKey.pem
          rsa-public-key: classpath:certs/publicKey.pem
     ```
2. Let's modify `/api` to `sign-in` api, and return **accessToken**
   ```java
      @Configuration
      @EnableWebSecurity
      @EnableMethodSecurity
      @RequiredArgsConstructor
      public class SecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
      
          private final UserInfoManagerConfig userInfoManagerConfig;
          private final RSAKeyRecord rsaKeyRecord;
      
          @Order(1)
          @Bean
          public SecurityFilterChain signInSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
              return httpSecurity
                      .securityMatcher(new AntPathRequestMatcher("/sign-in/**"))
                      .csrf(csrf->csrf.disable())
                      .authorizeHttpRequests(auth ->
                              auth.anyRequest().authenticated())
                      .userDetailsService(userInfoManagerConfig)
                      .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                      .exceptionHandling(ex -> {
                          ex.authenticationEntryPoint((request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage()));
                      })
                      .httpBasic(withDefaults())
                      .build();
          }
          
          @Order(2)
          @Bean
          public SecurityFilterChain h2ConsoleSecurityFilterChainConfig(HttpSecurity httpSecurity) throws Exception{
              return httpSecurity
                      .securityMatcher(new AntPathRequestMatcher(("/h2-console/**")))
                      .authorizeHttpRequests(auth->auth.anyRequest().permitAll())
                      .csrf(csrf -> csrf.ignoringRequestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")))
                      .headers(headers -> headers.frameOptions(withDefaults()).disable())
                      .build();
          }
          @Bean
          PasswordEncoder passwordEncoder() {
              return new BCryptPasswordEncoder();
          }
          
      }
   
      
      ```

3. Let's create a `AuthController` , to receive the `api` 

   ```java
   @RestController
   @RequiredArgsConstructor
   @Slf4j
   public class AuthController {
   
       private final AuthService authService;
       @PostMapping("/sign-in")
       public ResponseEntity<?> authenticateUser(Authentication authentication, HttpServletResponse response){
   
           return ResponseEntity.ok(authService.getJwtTokensAfterAuthentication(authentication));
       }
   }
   ```
4. Let's create return type of AuthResponseDto required `AuthSerivce` to return **accessToken**

   ```java
   @Data
   @Builder
   @AllArgsConstructor
   @NoArgsConstructor
   public class AuthResponseDto {
   
       @JsonProperty("access_token")
       private String accessToken;
       
       @JsonProperty("access_token_expiry")
       private int accessTokenExpiry;
   
       @JsonProperty("token_type")
       private TokenType tokenType;
       
       @JsonProperty("user_name")
       private String userName;
   
   }
   ```
   - Token Type
   ```java
   public enum TokenType {
       Bearer
   }
   ```
   -Token Generator
   ```java
   @Service
      @RequiredArgsConstructor
      @Slf4j
      public class AuthService {
      
          private final UserInfoRepo userInfoRepo;
          private final JwtTokenGenerator jwtTokenGenerator;
          public AuthResponseDto getJwtTokensAfterAuthentication(Authentication authentication) {
              try
              {
                  //Return 500, as error to avoid guessing by malicious actors. 
      
                  var userInfoEntity = userInfoRepo.findByEmailId(authentication.getName())
                          .orElseThrow(()->{
                              log.error("[AuthService:userSignInAuth] User :{} not found",authentication.getName());
                              return new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,"Please Try Again ");});
      
      
                  String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
      
                  log.info("[AuthService:userSignInAuth] Access token for user:{}, has been generated",userInfoEntity.getUserName());
                  return  AuthResponseDto.builder()
                          .accessToken(accessToken)
                          .accessTokenExpiry(15 * 60)
                          .userName(userInfoEntity.getUserName())
                          .tokenType(TokenType.Bearer)
                          .build();
      
      
              }catch (Exception e){
                  log.error("[AuthService:userSignInAuth]Exception while authenticating the user due to :"+e.getMessage());
                  throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,"Please Try Again");
              }
          }
      }
   ```
   Let's add `JwtTokenGenerator` in jwtAuth

   ```java
   import java.time.temporal.ChronoUnit;    
   
   @Service
   @RequiredArgsConstructor
   @Slf4j
   public class JwtTokenGenerator {
   
   
       private final JwtEncoder jwtEncoder;
   
       public String generateAccessToken(Authentication authentication) {
   
           log.info("[JwtTokenGenerator:generateAccessToken] Token Creation Started for:{}", authentication.getName());
   
           Instant now = Instant.now();
   
           String roles = getRoles(authentication);
   
           String permissions = getPermissionsFromRoles(roles);
   
           JwtClaimsSet claims = getJwtClaimsSet(
                   15,
                   ChronoUnit.MINUTES,
                   authentication,
                   permissions);
   
           return getTokenValue(claims);
       }
       
       private static String getRoles(Authentication authentication) {
           return authentication.getAuthorities().stream()
                   .map(GrantedAuthority::getAuthority)
                   .collect(Collectors.joining(" "));
       }
   
       private static JwtClaimsSet getJwtClaimsSet(int duration,
                                                   ChronoUnit chronoUnit,
                                                   Authentication authentication,
                                                   String scope) {
           return JwtClaimsSet.builder()
                   .issuer("atquil")
                   .issuedAt(Instant.now())
                   .expiresAt(Instant.now().plus(duration, chronoUnit)) // Minutes
                   .subject(authentication.getName())
                   .claim("scope", scope) // whatever we have fixed the authority
                   .build();
       }
   
        //Jwt token encoder and decoder (below)
       private String getTokenValue(JwtClaimsSet claims) {
           return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
       }
   
       //Permissions for jwt
       private String getPermissionsFromRoles(String roles) {
           Set<String> permissions = new HashSet<>();
   
           if (roles.contains("ROLE_ADMIN")) {
               permissions.addAll(List.of("READ", "WRITE", "DELETE"));
           }
           if (roles.contains("ROLE_MANAGER")) {
               permissions.addAll(List.of("READ"));
           }
           if (roles.contains("ROLE_USER")) {
               permissions.add("READ");
           }
   
           return String.join(" ", permissions);
       }
   
   }
   ```
   
   Let's add `token encoder` and `decoder`
   ```java
   @Configuration
   @EnableWebSecurity
   @EnableMethodSecurity
   @RequiredArgsConstructor
   public class SecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
   
       private final UserInfoManagerConfig userInfoManagerConfig;
       private final RSAKeyRecord rsaKeyRecord;
       
       //.....
   
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
   - As Jwt token, looks for **`SCOPE_`** as a prefix for any **Authority**, thus we need to modify the Dashboard controller as well
   ```java
   @RestController
   @RequestMapping("/api")
   @RequiredArgsConstructor
   public class DashboardController {
       private final AdminService adminService;
       @GetMapping("/welcome-message")
       public ResponseEntity<String> getFirstWelcomeMessage(Authentication authentication){
           return ResponseEntity.ok("Welcome to the JWT Tutorial:"+authentication.getName()+"with scope:"+authentication.getAuthorities());
   
       }
   
       //@PreAuthorize("hasRole('ROLE_MANAGER')")
       @PreAuthorize("hasAuthority('SCOPE_READ')")
       @GetMapping("/manager-message")
       public ResponseEntity<String> getManagerData(Principal principal){
           return ResponseEntity.ok("Admin::"+principal.getName());
       }
   
       //@PreAuthorize("hasRole('ROLE_ADMIN')")
       @PreAuthorize("hasAuthority('SCOPE_WRITE')")
       @PostMapping("/admin-message")
       public ResponseEntity<String> getAdminData(@RequestParam("message") String message, Principal principal){
           return ResponseEntity.ok("Admin::"+principal.getName()+" has this message:"+message);
   
       }
   
       @PreAuthorize("hasAuthority('SCOPE_WRITE')")
       @GetMapping("/revoke-access")
       public ResponseEntity<String> revokeAccessForUser(@RequestParam("userEmail") String userEmail){
           return ResponseEntity.ok(adminService.revokeRefreshTokensForUser(userEmail));
   
       }
   }
   ```   
6. Now add `/api` config again in securityConfig, which will use `ouath2` for jwt access token
   ```java
       @Order(3)
       @Bean
       public SecurityFilterChain apiSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
           return httpSecurity
                   .securityMatcher(new AntPathRequestMatcher("/api/**"))
                   .csrf(csrf->csrf.disable())
                   .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                   .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
                   .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                   .addFilterBefore(new JwtAccessTokenFilter(rsaKeyRecord,jwtTokenUtils), UsernamePasswordAuthenticationFilter.class)
                   .exceptionHandling(ex -> {
                       log.error("[SecurityConfig:apiSecurityFilterChain] Exception due to :{}",ex);
                       ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint());
                       ex.accessDeniedHandler(new BearerTokenAccessDeniedHandler());
                   })
                   .build();
       }
   ```
7. Test the API for Authentication and Authorization: 
   - Authentication using `sign-in` api: `http://localhost:8080/sign-in`  with `username` and `password` will return json output
   ```json
   {
       "access_token": "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJhdHF1aWwiLCJzdWIiOiJhZG1pbkBhZG1pbi5jb20iLCJleHAiOjE3MDU0MTk0NTYsImlhdCI6MTcwNTQxOTE1Niwic2NvcGUiOiJST0xFX0FETUlOIn0.ZYsVYEMjscLAI4iXtfw3M7Iacge-D9LwYFA4hwjPqC8wkDJ2hMgKmulpCS1o4WvqhiC6Acm2jbrAStbvxwFpO__OO8S0s_pg059z-T94-O7em_ch17gqmRQi7G5upVJnBZpYql-ly9COgCpDpkMGlkC9a4l2_7JJks218CWmZ8JK29cGCUyKS21N45YDjiELWIxt7NiEVsh70W7GqgcAszPdZ6sIqzzEt_YIMtoNOPZ5jbSZvkicjBEsSnoJReBL044r__EZDW4g5oNPHiEGM9qSQC5aK7xyH7RJkumaVHjCw_cD8rDLlW1PpdIgMNozjb5kFBALvLfEex1ERlZNpg",
       "access_token_expiry": "60",
       "token_type": "Bearer",
       "user_name": "Admin"
   }
   ```
   - Use Access Token
     - `http://localhost:8080/api/welcome-message` 
     - `http://localhost:8080/api/admin-message` 

## Part 4: Adding JwtFilter - UseCase: User is removed, then also jwtAccessToken will work, so prevent it. 

1. Add filter for `/api` access

   ```java
      @Configuration
      @EnableWebSecurity
      @EnableMethodSecurity
      @RequiredArgsConstructor
      public class SecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
      
          //.....
          private final RSAKeyRecord rsaKeyRecord;
          private final JwtTokenUtils jwtTokenUtils;
      
          // .....
          @Order(2)
          @Bean
          public SecurityFilterChain apiSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
              return httpSecurity
                      .securityMatcher(new AntPathRequestMatcher("/api/**"))
                      .csrf(csrf -> csrf.disable())
                      .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                      .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
                      .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                      .addFilterBefore(new JwtAccessTokenFilter(rsaKeyRecord, jwtTokenUtils), UsernamePasswordAuthenticationFilter.class)
                      .exceptionHandling(ex -> {
                          log.error("[SecurityConfig:apiSecurityFilterChain] Exception due to :{}",ex);
                          ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint());
                          ex.accessDeniedHandler(new BearerTokenAccessDeniedHandler());
                      })
                      .build();
             // ..
          }
      }
   
   ```

2. Create a `OncePerRequestFilter` which will scrutinize the jwt token. 
   
   - Access Filter
   ```java
   @RequiredArgsConstructor
   @Slf4j
   public class JwtAccessTokenFilter extends OncePerRequestFilter {
   
       private final RSAKeyRecord rsaKeyRecord;
       private final JwtTokenUtils jwtTokenUtils;
       @Override
       protected void doFilterInternal(HttpServletRequest request,
                                       HttpServletResponse response,
                                       FilterChain filterChain) throws ServletException, IOException {
   
           try{
               log.info("[JwtAccessTokenFilter:doFilterInternal] :: Started ");
   
               log.info("[JwtAccessTokenFilter:doFilterInternal]Filtering the Http Request:{}",request.getRequestURI());
               final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
               JwtDecoder jwtDecoder =  NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();
   
               if(!authHeader.startsWith(TokenType.Bearer.name())){
                   filterChain.doFilter(request,response);
                   return;
               }
   
               final String token = authHeader.substring(7);
               final Jwt jwtToken = jwtDecoder.decode(token);
   
   
               final String userName = jwtTokenUtils.getUserName(jwtToken);
   
               if(!userName.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null){
                   UserDetails userDetails = jwtTokenUtils.userDetails(userName);
                   if(jwtTokenUtils.isTokenValid(jwtToken,userDetails)){
                       SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
   
                       UsernamePasswordAuthenticationToken createdToken = new UsernamePasswordAuthenticationToken(
                               userDetails,
                               null,
                               userDetails.getAuthorities()
                       );
                       createdToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                       securityContext.setAuthentication(createdToken);
                       SecurityContextHolder.setContext(securityContext);
                   }
               }
               log.info("[JwtAccessTokenFilter:doFilterInternal] Completed");
               filterChain.doFilter(request,response);
           }catch (JwtValidationException jwtValidationException){
               log.error("[JwtAccessTokenFilter:doFilterInternal] Exception due to :{}",jwtValidationException.getMessage());
               throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE,jwtValidationException.getMessage());
           }
       }
   }

   ```

3. Common jwt-token filter helper methods
   ```java
   @Component
   @RequiredArgsConstructor
   public class JwtTokenUtils {
   
       public String getUserName(Jwt jwtToken){
           return jwtToken.getSubject();
       }
   
       public boolean isTokenValid(Jwt jwtToken, UserDetails userDetails){
           final String userName = getUserName(jwtToken);
           boolean isTokenExpired = getIfTokenIsExpired(jwtToken);
           boolean isTokenUserSameAsDatabase = userName.equals(userDetails.getUsername());
           return !isTokenExpired  && isTokenUserSameAsDatabase;
   
       }
   
       private boolean getIfTokenIsExpired(Jwt jwtToken) {
           return Objects.requireNonNull(jwtToken.getExpiresAt()).isBefore(Instant.now());
       }
   
       private final UserInfoRepo useruserInfoRepo;
       public UserDetails userDetails(String emailId){
           return useruserInfoRepo
                   .findByEmailId(emailId)
                   .map(UserInfoConfig::new)
                   .orElseThrow(()-> new UsernameNotFoundException("UserEmail: "+emailId+" does not exist"));
       }
   }
   
   ```
   
4. Testing:
   - [Success] Test with the same API  
   - [Failure] After creating the token , delete the user or Wait for expiry. 

## Part 5 : `Refresh token ` using `HttpOnly` Cookie and store it in database

1. Let's modify the `entity` to accommodate `RefreshToken`:
   - Add `RefreshTokenEntity`
   ```java
      @Entity
      @Data
      @Builder
      @NoArgsConstructor
      @AllArgsConstructor
      @Table(name="REFRESH_TOKENS")
      public class RefreshTokenEntity {
      
          @Id
          @GeneratedValue
          private Long id;
          // Increase the length to a value that can accommodate your actual token lengths
          @Column(name = "REFRESH_TOKEN", nullable = false, length = 10000)
          private String refreshToken;
      
          @Column(name = "REVOKED")
          private boolean revoked;
      
          @ManyToOne
          @JoinColumn(name = "user_id",referencedColumnName = "id")
          private UserInfoEntity user;
      
      }
   ```
   - Let's add `RefreshTokenEntity` to  `UserInfoEntity`
   ```java
   @Data
   @NoArgsConstructor
   @AllArgsConstructor
   @Entity
   @Table(name="USER_INFO")
   public class UserInfoEntity {
      //....
   
       // Many-to-One relationship with RefreshTokenEntity
       @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
       private List<RefreshTokenEntity> refreshTokens;
   }
   
   ```
   - Let's add a `RefreshTokenRepo` for hibernate mapping
   ```java
   @Repository
   public interface RefreshTokenRepo extends JpaRepository<RefreshTokenEntity, Long> {
   }

   ```
   

2. Create a `refreshTokenGenerator` method in `JwtTokenGenerator`, which will give us `refreshToken` used to pull `access_token`

   ```java
   @Service
   @RequiredArgsConstructor
   @Slf4j
   public class JwtTokenGenerator {
   
   
      //....
       public String generateRefreshToken(Authentication authentication) {
           log.info("[JwtTokenGenerator:generateRefreshToken] Refresh token generation process started for:{}", authentication.getName());
   
           JwtClaimsSet claims = getJwtClaimsSet(
                   60,
                   ChronoUnit.DAYS,
                   authentication,
                   "REFRESH_TOKEN");
           return getTokenValue(claims);
       }
       
       // ....
   }
   ```
2. Let's modify `getJwtTokensAfterAuthentication` method which will return accessToken as well as refreshToken. 

   ```java
   @Service
   @RequiredArgsConstructor
   @Slf4j
   public class AuthService {
   
       //...
       private final RefreshTokenRepo refreshTokenRepo;
       public AuthResponseDto getJwtTokensAfterAuthentication(Authentication authentication) {
           try
           {
              //....
               String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);
   
               //Let's save the refreshToken as well
               saveUserRefreshToken(userInfoEntity,refreshToken);
               log.info("[AuthService:userSignInAuth] Access token for user:{}, has been generated",userInfoEntity.getUserName());
               return  AuthResponseDto.builder()
                       .accessToken(accessToken)
                       .accessTokenExpiry("60")
                       .userName(userInfoEntity.getUserName())
                       .tokenType(TokenType.Bearer)
                       .build();
   
   
           }catch (Exception e){
               log.error("[AuthService:userSignInAuth]Exception while authenticating the user due to :"+e.getMessage());
               throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,"Please Try Again");
           }
       }
   
       private void saveUserRefreshToken(UserInfoEntity userInfoEntity, String refreshToken) {
           var refreshTokenEntity = RefreshTokenEntity.builder()
                   .user(userInfoEntity)
                   .refreshToken(refreshToken)
                   .revoked(false)
                   .build();
           refreshTokenRepo.save(refreshTokenEntity);
       }
   }
   
   ```

3. Now let's return the `refresh-token` using **`HttpOnlyCookie`**

   - Add `HttpServletReponse` in the `/sign-in` api. 
   ```java
   @RestController
   @RequiredArgsConstructor
   @Slf4j
   public class AuthController {
   
      private final AuthService authService;
      @PostMapping("/sign-in")
      public ResponseEntity<?> authenticateUser(Authentication authentication, HttpServletResponse response){
         return ResponseEntity.ok(authService.getJwtTokensAfterAuthentication(authentication,response));
      }
   }
   ```
   
   - Modify the method to `create a cookie`. 
   ```java
   @Service
   @RequiredArgsConstructor
   @Slf4j
   public class AuthService {
   
    
       public AuthResponseDto getJwtTokensAfterAuthentication(Authentication authentication, HttpServletResponse response) {
               //..
               String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
               String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);
               //..
               creatRefreshTokenCookie(response,refreshToken);
   
               //....
       }
   
       private Cookie creatRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
           Cookie refreshTokenCookie = new Cookie("refresh_token",refreshToken);
           refreshTokenCookie.setHttpOnly(true);
           refreshTokenCookie.setSecure(true);
           refreshTokenCookie.setMaxAge(15 * 24 * 60 * 60 ); // in seconds
           response.addCookie(refreshTokenCookie);
           return refreshTokenCookie;
       }
   
   }
   
   ```
4. Now let's create the API which will use the `refresh-token` to get new `access-token`

   - Create the Api
   ```java
   @RestController
   @RequiredArgsConstructor
   @Slf4j
   public class AuthController {
   
      private final UserInfoService userInfoService;
   
       //...
      @PreAuthorize("hasAuthority('SCOPE_REFRESH_TOKEN')")
      @PostMapping ("/refresh-token")
      public ResponseEntity<?> getAccessToken(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader){
         return ResponseEntity.ok(authService.getAccessTokenUsingRefreshToken(authorizationHeader));
      }
      
   
   }
   ```
   - Now Add the method
   ```java
   @Service
   @RequiredArgsConstructor
   @Slf4j
   public class AuthService {
   
    //..
   
       public Object getAccessTokenUsingRefreshToken(String authorizationHeader) {
   
           if(!authorizationHeader.startsWith(TokenType.Bearer.name())){
               return new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,"Please verify your token");
           }
   
           final String refreshToken = authorizationHeader.substring(7);
   
           var refreshTokenEntity = refreshTokenRepo.findByRefreshToken(refreshToken)
                   .filter(tokens-> !tokens.isRevoked())
                   .orElseThrow(()-> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,"Refresh token revoked"));
   
           UserInfoEntity userInfoEntity = refreshTokenEntity.getUser();
           Authentication authentication =  createAuthentication(userInfoEntity);
           
           String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
   
           return  AuthResponseDto.builder()
                   .accessToken(accessToken)
                   .accessTokenExpiry(5 * 60)
                   .userName(userInfoEntity.getUserName())
                   .tokenType(TokenType.Bearer)
                   .build();
       }
   
       private static Authentication createAuthentication(UserInfoEntity userInfoEntity) {
           // Extract user details from UserDetailsEntity
           String username = userInfoEntity.getEmailId();
           String password = userInfoEntity.getPassword();
           String roles = userInfoEntity.getRoles();
   
           // Extract authorities from roles (comma-separated)
           String[] roleArray = roles.split(",");
           GrantedAuthority[] authorities = Arrays.stream(roleArray)
                   .map(role -> (GrantedAuthority) role::trim)
                   .toArray(GrantedAuthority[]::new);
           
           return new UsernamePasswordAuthenticationToken(username, password, Arrays.asList(authorities));
       }
   }
   
   ```
5. Now let's create a `Filter` for `refresh-token api`
   - Now add that filter to `SecurityConfig`:
     ```java
     @Configuration
     @EnableWebSecurity
     @EnableMethodSecurity
     @RequiredArgsConstructor
     @Slf4j
     public class SecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
  
         private final UserInfoManagerConfig userInfoManagerConfig;
         private final RSAKeyRecord rsaKeyRecord;
         private final JwtTokenUtils jwtTokenUtils;
         private final RefreshTokenRepo refreshTokenRepo;
  
        // ..
         @Order(2)
         @Bean
         public SecurityFilterChain refreshTokenFilterChain(HttpSecurity httpSecurity) throws Exception{
             return httpSecurity
                     .securityMatcher(new AntPathRequestMatcher("/refresh-token/**"))
                     .csrf(csrf->csrf.disable())
                     .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                     .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
                     .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                     .addFilterBefore(new JwtRefreshTokenAuthenticationFilter(rsaKeyRecord, jwtTokenUtils,refreshTokenRepo), UsernamePasswordAuthenticationFilter.class)
                     .exceptionHandling(ex -> {
                         ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint());
                         ex.accessDeniedHandler(new BearerTokenAccessDeniedHandler());
                     })
                     .build();
         }
         // ..
     }

     ```
      - Filter 
      ```java
      @RequiredArgsConstructor
      @Slf4j
      public class JwtRefreshTokenAuthenticationFilter extends OncePerRequestFilter {
   
   
         private  final RSAKeyRecord rsaKeyRecord;
         private final JwtTokenUtils jwtTokenUtils;
         private final RefreshTokenRepo refreshTokenRepo;
         @Override
         protected void doFilterInternal(HttpServletRequest request,
                                         HttpServletResponse response,
                                         FilterChain filterChain) throws ServletException, IOException {
   
            final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
            JwtDecoder jwtDecoder =  NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();
   
            if(!authHeader.startsWith("Bearer ")){
               filterChain.doFilter(request,response);
               return;
            }
   
            final String token = authHeader.substring(7);
            final Jwt jwtRefreshToken = jwtDecoder.decode(token);
   
   
            final String userName = jwtTokenUtils.getUserName(jwtRefreshToken);
   
   
            if(!userName.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null){
               //Check if refreshToken isPresent in database and is valid
               var isRefreshTokenValidInDatabase = refreshTokenRepo.findByRefreshToken(jwtRefreshToken.getTokenValue())
                       .map(refreshTokenEntity -> !refreshTokenEntity.isRevoked())
                       .orElse(false);
   
               UserDetails userDetails = jwtTokenUtils.userDetails(userName);
               if(jwtTokenUtils.isTokenValid(jwtRefreshToken,userDetails) && isRefreshTokenValidInDatabase){
                  SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
   
                  UsernamePasswordAuthenticationToken createdToken = new UsernamePasswordAuthenticationToken(
                          userDetails,
                          null,
                          userDetails.getAuthorities()
                  );
   
                  createdToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                  securityContext.setAuthentication(createdToken);
                  SecurityContextHolder.setContext(securityContext);
               }
            }
   
            filterChain.doFilter(request,response);
         }
      }
   
      ```
  
6. Test the api : 
   - Sign-in using admin : http://localhost:8080/sign-in
   - Copy the `refresh-token` from `cookie`
   - Use the `refresh-token` to get new `access-token`: http://localhost:8080/refresh-token
   - Access any of the `admin-api` using it : http://localhost:8080/api/admin-message

## Part 6: `Sign-out` and `Revoke` the token

1. Modify the `SecurityConfig` to add `logout` url

   ```java
   @Configuration
   @EnableWebSecurity
   @EnableMethodSecurity
   @RequiredArgsConstructor
   @Slf4j
   public class SecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
   
       //..
       private final LogoutHandlerService logoutHandlerService;
       @Order(4)
       @Bean
       public SecurityFilterChain logoutSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
           return httpSecurity
                   .securityMatcher(new AntPathRequestMatcher("/logout/**"))
                   .csrf(csrf->csrf.disable())
                   .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                   .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
                   .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                   .addFilterBefore(new JwtAccessTokenFilter(rsaKeyRecord,jwtTokenUtils), UsernamePasswordAuthenticationFilter.class)
                   .logout(logout -> logout
                           .logoutUrl("/logout")
                           .addLogoutHandler(logoutHandlerService)
                           .logoutSuccessHandler(((request, response, authentication) -> SecurityContextHolder.clearContext()))
                   )
                   .exceptionHandling(ex -> {
                       log.error("[SecurityConfig:logoutSecurityFilterChain] Exception due to :{}",ex);
                       ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint());
                       ex.accessDeniedHandler(new BearerTokenAccessDeniedHandler());
                   })
                   .build();
            }
    //..
    }
   ```
2. Add Logic for revoking access
   ```java
   @Service
   @Slf4j
   @RequiredArgsConstructor
   public class LogoutHandlerService implements LogoutHandler {
   
       private final RefreshTokenRepo refreshTokenRepo;
   
       @Override
       public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
           final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
           if(!authHeader.startsWith("Bearer ")){
               return;
           }
   
           final String refreshToken = authHeader.substring(7);
           var storedRefreshToken = refreshTokenRepo.findByRefreshToken(refreshToken)
                   .map(token->{
                       token.setRevoked(true);
                       refreshTokenRepo.save(token);
                       return token;
                   })
                   .orElse(null);
       }
   }
   ```

3. Now test the api using `refreshToken` : http://localhost:8080/logout
4. **Note: If you want to revoke from all the places, you can get the userName**
   ```java
      @Repository
      public interface RefreshTokenRepo extends JpaRepository<RefreshTokenEntity, Long> {
      
         Optional<RefreshTokenEntity> findByRefreshToken(String refreshToken);
      
         @Query(value = "SELECT rt.* FROM REFRESH_TOKENS rt " +
                 "INNER JOIN USER_DETAILS ud ON rt.user_id = ud.id " +
                 "WHERE ud.EMAIL = :userEmail and rt.revoked = false ", nativeQuery = true)
         List<RefreshTokenEntity> findAllRefreshTokenByUserEmailId(String userEmail);
      }
   
   ```
## Part 7:  `Sign-Up` to getAccess and RefreshToken

1. Let's create a `UserRegistrationDto` 

   ```java
   public record UserRegistrationDto (
           @NotEmpty(message = "User role must not be empty")
           String userName,
           String userMobileNo,
           @NotEmpty(message = "User email must not be empty") //Neither null nor 0 size
           @Email(message = "Invalid email format")
           String userEmail,
   
           @NotEmpty(message = "User password must not be empty")
           String userPassword,
           @NotEmpty(message = "User role must not be empty")
           String userRole){
   
   
   }
   ```
2. Create a endpoint in `AuthController` to accept it and create a respective services 
   ```java
   @RestController
   @RequiredArgsConstructor
   @Slf4j
   public class AuthController {
   
      private final AuthService authService;
      //..
   
      @PostMapping("/sign-up")
      public ResponseEntity<?> registerUser(@Valid @RequestBody UserRegistrationDto userRegistrationDto,
                                            BindingResult bindingResult,HttpServletResponse httpServletResponse){
   
         log.info("[AuthController:registerUser]Signup Process Started for user:{}",userRegistrationDto.userName());
         if (bindingResult.hasErrors()) {
            List<String> errorMessage = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .toList();
            log.error("[AuthController:registerUser]Errors in user:{}",errorMessage);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorMessage);
         }
         return ResponseEntity.ok(authService.registerUser(userRegistrationDto,httpServletResponse));
      }
   
   }
   
   ```
3. Add respective service : 

   ```java
   @Service
   @RequiredArgsConstructor
   @Slf4j
   public class AuthService {
   
      //..
       private final UserInfoMapper userInfoMapper;
      //..
       public AuthResponseDto registerUser(UserRegistrationDto userRegistrationDto,HttpServletResponse httpServletResponse){
   
           try{
               log.info("[AuthService:registerUser]User Registration Started with :::{}",userRegistrationDto);
   
               Optional<UserInfoEntity> user = userInfoRepo.findByEmailId(userRegistrationDto.userEmail());
               if(user.isPresent()){
                   throw new Exception("User Already Exist");
               }
   
               UserInfoEntity userDetailsEntity = userInfoMapper.convertToEntity(userRegistrationDto);
               Authentication authentication = createAuthentication(userDetailsEntity);
   
   
               // Generate a JWT token
               String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
               String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);
   
               UserInfoEntity savedUserDetails = userInfoRepo.save(userDetailsEntity);
               saveUserRefreshToken(userDetailsEntity,refreshToken);
               
               creatRefreshTokenCookie(httpServletResponse,refreshToken);
               
               log.info("[AuthService:registerUser] User:{} Successfully registered",savedUserDetails.getUserName());
               return   AuthResponseDto.builder()
                       .accessToken(accessToken)
                       .accessTokenExpiry(5 * 60)
                       .userName(savedUserDetails.getUserName())
                       .tokenType(TokenType.Bearer)
                       .build();
   
   
           }catch (Exception e){
               log.error("[AuthService:registerUser]Exception while registering the user due to :"+e.getMessage());
               throw new ResponseStatusException(HttpStatus.BAD_REQUEST,e.getMessage());
           }
   
       }
   }
   
   ```
4. Respective Mapper
   ```java
   @Component
   @RequiredArgsConstructor
   public class UserInfoMapper {
   
       private final PasswordEncoder passwordEncoder;
       public UserInfoEntity convertToEntity(UserRegistrationDto userRegistrationDto) {
           UserInfoEntity userInfoEntity = new UserInfoEntity();
           userInfoEntity.setUserName(userRegistrationDto.userName());
           userInfoEntity.setEmailId(userRegistrationDto.userEmail());
           userInfoEntity.setMobileNumber(userRegistrationDto.userMobileNo());
           userInfoEntity.setRoles(userRegistrationDto.userRole());
           userInfoEntity.setPassword(passwordEncoder.encode(userRegistrationDto.userPassword()));
           return userInfoEntity;
       }
   }
   
   ```
5. Finally, add the endpoint for `SecurityConfig`
   ```java
       @Order(5)
       @Bean
       public SecurityFilterChain registerSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
           return httpSecurity
                   .securityMatcher(new AntPathRequestMatcher("/sign-up/**"))
                   .csrf(csrf->csrf.disable())
                   .authorizeHttpRequests(auth ->
                           auth.anyRequest().permitAll())
                   .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                   .build();
       }
   ```
6. Testing with api : http://localhost:8080/sign-up
```json
{
    "userName": "Manager",
    "userEmail": "manager1@manager.com",
    "userMobileNo": "8888888888",
    "userPassword": "password",
    "userRole": "ROLE_MANAGER"
}
```