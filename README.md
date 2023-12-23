# spring-security
Welcome to my Spring Security GitHub repository! This repository contains a collection of
examples and tutorials on how to use Spring Security to secure your Spring Boot applications.
Spring Security is a powerful and highly customizable security framework that provides 
authentication, authorization, and other security features for your applications.

### Part 1: Application config

1. Spring Initializer : https://start.spring.io/
2. Add dependency : `lombok`, `spring-boot-starter-web`, `spring-boot-starter-security`, `h2-database`
    ```
   dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'
    compileOnly 'org.projectlombok:lombok'
    annotationProcessor 'org.projectlombok:lombok'
    testImplementation 'org.springframework.boot:spring-boot-starter-test'

    //Security:
    implementation 'org.springframework.boot:spring-boot-starter-security'
    
    //Database: 
    runtimeOnly 'com.h2database:h2'
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    }
   ```
3. Configure `application.yml` file, to add database setting (using yml is better as it stores data in **hierarchical** format, whereas properties will store in **key-value**)

    ```yaml
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
        database-platform: org.hibernate.dialect.H2Dialect
        show-sql: true
        hibernate:
          ddl-auto: create-drop #Create new db everytime we start the application
    
   ```

### Part 2: Adding User 

1. Create a `UserEntity`, which holds User Data in `entity` package
    ```java
    @Entity
    @Table(name = "USERS")
    @Data
    @NoArgsConstructor
    public class UserEntity {
    
        @Id
        @GeneratedValue
        private Long id;
        private String username;
        private String password;
        private String roles;
    }

   ```

2. Create a `ORM-Mapping` in `UserRepo` file. 

    ```java

    @Repository
    public interface UserRepo  extends JpaRepository<UserEntity,Long> {
    }

   ```

3. Add `SecurityConfig`, which allows `h2-console` to be accessed without password, and also restrict other `api` calls without password

   ```java
   @Configuration
   @EnableWebSecurity
   public class SecurityConfig {
   
       @Bean
       @Order(1)
       public SecurityFilterChain h2ConsoleSecurityFilterChainConfig(HttpSecurity httpSecurity) throws Exception{
           return httpSecurity
                   .securityMatcher(new AntPathRequestMatcher(("/h2-console/**")))
                   .authorizeHttpRequests(auth->auth.anyRequest().permitAll())
                   .csrf(csrf -> csrf.ignoringRequestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")))
                   .headers(headers -> headers.frameOptions(withDefaults()).disable())
                   .build();
       }
   
       @Bean
       @Order(2)
       public SecurityFilterChain apiSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
           return httpSecurity
                   .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                   .formLogin(withDefaults())
                   .build();
       }
   
       @Bean
       PasswordEncoder passwordEncoder(){
           return new BCryptPasswordEncoder();
       }
   
   }

   ```
4. Let's add user in our table using `command-line-runner`
    ```java
    @SpringBootApplication
    public class SpringSecurityApplication {
    
        public static void main(String[] args) {
            SpringApplication.run(SpringSecurityApplication.class, args);
        }
    
        //Command line runner: After the application context, but before the application starts
        @Bean
        CommandLineRunner commandLineRunner(UserRepo userRepo, PasswordEncoder passwordEncoder){
            return args -> {
                UserEntity manager = new UserEntity();
                manager.setUsername("manager");
                manager.setPassword(passwordEncoder.encode("password"));
                manager.setRoles("ROLE_MANAGER");

                UserEntity admin = new UserEntity();
                admin.setUsername("admin");
                admin.setPassword(passwordEncoder.encode("password"));
                admin.setRoles("ROLE_MANAGER,ROLE_ADMIN");
                
                userRepo.saveAll(List.of(manager,admin));
            };
        }
    }

   ```
5. Let's start the application and check these url `http://localhost:8080/h2-console`, and you can see that the user `atquil` is present in the database

![h2-console.png](src%2Fmain%2Fresources%2Fimages%2Fh2-console.png)

### Part 3: Configuring `SecurityConfig`, to use this user to access the `api`

1. Create a file `UserSecurityConfig` which will implement `UserDetails`, for `Authentication`, using the `UserEntity` object. 

   **UserDetails simply store user info which is later encapsulated into Authentication object.**
   ```java
   @RequiredArgsConstructor
   public class UserSecurityConfig implements UserDetails {
   
   
       private final UserEntity userEntity;
       @Override
       public String getUsername() {
           return userEntity.getUsername();
       }
   
       @Override
       public String getPassword() {
           return userEntity.getPassword();
       }
       @Override
       public Collection<? extends GrantedAuthority> getAuthorities() {
           return Arrays
                   .stream(userEntity
                           .getRoles()
                           .split(","))
                   .map(SimpleGrantedAuthority::new)
                   .toList();
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
   
2. Now Create a `JPAUserDetailsManagerConfig` file, which will use `UserSecurityConfig`, and `UserEntity` to find the user and map it for `Authentication`

   ```java
   @Service
   @RequiredArgsConstructor
   public class JPAUserDetailsManagerConfig implements UserDetailsService {
   
       private final UserRepo userRepo;
       @Override
       public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
           return userRepo
                   .findByUsername(username) // Create the method like this Optional<UserEntity> findByUsername(String username);
                   .map(UserSecurityConfig::new)
                   .orElseThrow(()-> new UsernameNotFoundException("User: "+username+" does not exist"));
       }
   }
   ```
   
   - You also need to create a method called `findByUserName` in `UserRepo`
   ```java
   @Repository
   public interface UserRepo  extends JpaRepository<UserEntity,Long> {
   Optional<UserEntity> findByUsername(String username);
   }

   ```
   
3. Finally, point the `Authentication` to use `JPAUserDetailsManagerConfig`, instead of default one

   ```java
   @Configuration
   @EnableWebSecurity
   @RequiredArgsConstructor
   public class SecurityConfig {
   
       private final JPAUserDetailsManagerConfig jpaUserDetailsManagerConfig;
      //...
   
       @Bean
       @Order(2)
       public SecurityFilterChain apiSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
           return httpSecurity
                   .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                   .userDetailsService(jpaUserDetailsManagerConfig)
                   .formLogin(withDefaults())
                   .build();
       }
   
      //...
   
   }

   ```
### Part 4: RoleBasedAuth with Endpoint

1. Create a `UserController` and add 2 endpoints. 
   ```java
   @RestController
   @RequestMapping("/api")
   @RequiredArgsConstructor
   public class UserController {
   
       private final UserRepo userRepo;
       //Everyone can access
       @GetMapping("/anyone")
       public ResponseEntity<?> getTestAPI1(){
           return ResponseEntity.ok("Response");
       }
   
       //Accessed only with the role MANAGER AND ADMIN
       @PreAuthorize("hasAnyRole('ROLE_MANAGER','ROLE_ADMIN')")
       @GetMapping("/MANAGER")
       public ResponseEntity<?> getTestAPI2(Principal principal){
   
           return ResponseEntity.ok(principal.getName()+" : All data from backend"+ userRepo.findAll());
       }
   
       //Accessed only with the role ADMIN
       @PreAuthorize("hasRole('ROLE_ADMIN')")
       @GetMapping("/admin")
       public ResponseEntity<?> getTestAPI3(Principal principal){
           return ResponseEntity.ok("User:"+principal.getName()+" is an owner");
       }
   }
   ```
2. Also add `@EnableMethodSecurity` in securityConfig file

   ```java
      @Configuration
      @EnableWebSecurity
      @RequiredArgsConstructor
      @EnableMethodSecurity
      public class SecurityConfig {
      //...
      }
   ```
   
3. Test with the url : Let's create user Manager and Admin

| API                                 | Access |
|-------------------------------------|--------|
| `http://localhost:8080/api/anyone`  | Yes    |
| `http://localhost:8080/api/manager` | Yes    |
| `http://localhost:8080/api/admin`   | No     |

