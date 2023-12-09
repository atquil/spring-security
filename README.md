# spring-security
Welcome to my Spring Security GitHub repository! This repository contains a collection of
examples and tutorials on how to use Spring Security to secure your Spring Boot applications.
Spring Security is a powerful and highly customizable security framework that provides 
authentication, authorization, and other security features for your applications.

UserDetailsManager has two implementation: **InMemoryUserDetailsManager** and **JdbcUserDetailsManager**

###  Part 1: Config

1. Create the project : https://start.spring.io/
2. Add dependency : `lombok`, `spring-boot-starter-web`, `spring-boot-starter-security`

   ```
    dependencies {
        implementation 'org.springframework.boot:spring-boot-starter-web'
        compileOnly 'org.projectlombok:lombok'
        annotationProcessor 'org.projectlombok:lombok'
        testImplementation 'org.springframework.boot:spring-boot-starter-test'
        
        // Security
        implementation 'org.springframework.boot:spring-boot-starter-security'
    }

   ```
3. Create a package `UserController` and add one `testAPI`
    ```java
    @RestController
    @RequestMapping("/api/user")
    public class UserController {
    
        @GetMapping("/test1")
        public ResponseEntity<?> getTestAPI(){
            return ResponseEntity.ok("Response");
        }
    }

    ```
4. You can access the API : `http://localhost:8080/api/user/test` using `username`: `user` and `password`: console
5. You can also set `username` and `password` in `application.yml` file. 
    ```yaml
    spring:
     security:
         user:
             name: atquil
             password: atquil
    ```

### Part 2: UserDetailsManager - InMemoryUserDetailsManager

1. Create a `UserInfoDetails` class in `config` package
2. Add `InMemoryUserDetailsManager` in the config. Also comment out the userDetails in `application.yml`
   ```java
   @Configuration
   public class UserDetailsConfig {
    @Bean
    public InMemoryUserDetailsManager user(){
        return new InMemoryUserDetailsManager(
                User.withUsername("atquil")
                    .password(passwordEncoder().encode("password")) 
                    .authorities("ROLE_USER")
                    .build()
        );
    }
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
   }
   ```
3. Test the API:  `http://localhost:8080/api/user/test1`
4. Enable method level security for API. 
   ```java
   @EnableWebSecurity
   @Configuration
   @EnableMethodSecurity
   public class SecurityConfig {
   
   
       @Bean
       SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
           return httpSecurity
                   .authorizeHttpRequests( auth -> {
                       auth.anyRequest().authenticated();
                   })
                   .formLogin(withDefaults())
                   .build();
       }
   
   }


   ```
   -- Now edit the API to use it
   ```java
   @RequestMapping("/api/user")
   @RestController
   public class UserController {
   
       @GetMapping("/test1")
       public ResponseEntity<?> getTestAPI(){
           return ResponseEntity.ok("Response");
       }
   
       //Accessed only with the role USER
       @PreAuthorize("hasRole('ROLE_USER')")
       @GetMapping("/test2")
       public ResponseEntity<?> getTestAPI2(Principal principal){
   
           return ResponseEntity.ok(principal.getName()+": has logged in.");
       }
       //Accessed only with the role OWNER
       @PreAuthorize("hasRole('ROLE_OWNER')")
       @GetMapping("/test3")
       public ResponseEntity<?> getTestAPI3(Principal principal){
           return ResponseEntity.ok("User:"+principal.getName()+" is an owner");
       }
   }

   ```
5. Test the API:

| API                                    | Access |
|----------------------------------------|--------|
| `http://localhost:8080/api/user/test1` | YES    |
| `http://localhost:8080/api/user/test2` | YES    |
| `http://localhost:8080/api/user/test3` | NO     |


### Part 3: UserDetailsManager - JdbcUserDetailsManager

1. Add database `dependency`: 

   ```
   dependencies {
   implementation 'org.springframework.boot:spring-boot-starter-web'
   compileOnly 'org.projectlombok:lombok'
   annotationProcessor 'org.projectlombok:lombok'
   testImplementation 'org.springframework.boot:spring-boot-starter-test'
   
       // Security
       implementation 'org.springframework.boot:spring-boot-starter-security'
   
       // Database
       runtimeOnly 'com.h2database:h2'
       implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
   }
   ```
2. Add the `h2-console` config in `application.yml`
   ```yaml
   spring:
      h2:
        console:
          enabled: true
   ```
3. Modify the UserDetailsConfig, to include EmbeddedDataSource for JdbcUserDetailsManager

   ```java
   @Configuration
   public class UserDetailsConfig {
   //    @Bean
   //    public InMemoryUserDetailsManager user(){
   //        return new InMemoryUserDetailsManager(
   //                User.withUsername("atquil")
   //                        .password(passwordEncoder().encode("password"))
   //                        .authorities("ROLE_USER")
   //                        .build()
   //        );
   //    }
   
       @Bean
       EmbeddedDatabase datasource(){
           return new EmbeddedDatabaseBuilder()
                   .setType(EmbeddedDatabaseType.H2)
                   .setName("atquilDb")
                   .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION) //Present default script to create user Roles
                   .build();
       }
       @Bean
       JdbcUserDetailsManager userDetailsManager(DataSource dataSource){
           UserDetails userDetails = User.builder()
                   .username("atquil")
                   .password(passwordEncoder().encode("password"))
                   .roles("OWNER")
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
4. Also Modify `SecurityConfig`, so that you can access h2-console

   ```java
   @EnableWebSecurity
   @Configuration
   @EnableMethodSecurity
   public class SecurityConfig {
   
   
       @Bean
       SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
           return httpSecurity
                   .authorizeHttpRequests( auth -> {
                       auth.requestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")).permitAll();
                       auth.anyRequest().authenticated();
                   })
                   .csrf(csrf -> csrf.ignoringRequestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")))
                   .headers(headers -> headers.frameOptions(withDefaults()).disable())
                   .formLogin(withDefaults())
                   .build();
       }
   
   }

   ```
   
5. Test the API: 
   
   | API                                    | Access |
   |----------------------------------------|--------|
   | `http://localhost:8080/api/user/test1` | YES    |
   | `http://localhost:8080/api/user/test2` | NO     |
   | `http://localhost:8080/api/user/test3` | YES    |

6. You can also see data in `h2-console` : `http://localhost:8080/h2-console`
![h2-console.png](src%2Fmain%2Fresources%2Fh2-console.png)