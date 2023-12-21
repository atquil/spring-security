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
3. Create a package `UserController` and add one `anyone`
    ```java
    @RestController
    @RequestMapping("/api")
    public class UserController {
    
         @GetMapping("/anyone")
         public ResponseEntity<?> getTestAPI(){
            return ResponseEntity.ok("Anyone can access me");
         }
    }

    ```
4. You can access the API : `http://localhost:8080/api/anyone` using `username`: `user` and `password`: console
5. You can also set `username` and `password` in `application.yml` file. 
    ```yaml
    spring:
     security:
         user:
             name: atquil
             password: password
    ```

### Part 2: UserDetailsManager - InMemoryUserDetailsManager

1. Create a `UserDetailsConfig` class in `config` package
2. Add `InMemoryUserDetailsManager` in the config. Also comment out the userDetails in `application.yml`
   ```java
   @Configuration
   public class UserDetailsConfig {
    @Bean
    public InMemoryUserDetailsManager user(){
        return new InMemoryUserDetailsManager(
                User.withUsername("atquil")
                    .password(passwordEncoder().encode("password")) 
                    .authorities("ROLE_MANAGER")
                    .build()
        );
    }
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
   }
   ```
3. Test the API:  `http://localhost:8080/api/manager`
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
   
        @GetMapping("/anyone")
        public ResponseEntity<?> getTestAPI(){
            return ResponseEntity.ok("Anyone can access me");
        }

        @PreAuthorize("hasAnyRole('ROLE_MANAGER','ROLE_ADMIN')")
        @GetMapping("/manager")
        public ResponseEntity<?> getTestAPI2(Principal principal){
            return ResponseEntity.ok(principal.getName()+": has logged in.");
        }
       
        @PreAuthorize("hasRole('ROLE_ADMIN')")
        @GetMapping("/admin")
        public ResponseEntity<?> getTestAPI3(Principal principal){
            return ResponseEntity.ok("User:"+principal.getName()+" is an owner");
        }
   }

   ```
5. Test the API:

| API                                 | Access |
|-------------------------------------|--------|
| `http://localhost:8080/api/anyone`  | YES    |
| `http://localhost:8080/api/manager` | YES    |
| `http://localhost:8080/api/admin`   | NO     |


### Part 3: UserDetailsManager - JdbcUserDetailsManager

1. Add database `dependency`: `h2database`, `jpa`

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
2. Add the `h2-console` config in `application.yml` to show h2-console
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
        // ....
   
       // *********** JDBC - User Details Manager

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
            UserDetails manager = User.builder()
                .username("manager")
                .password(passwordEncoder().encode("password"))
                .roles("MANAGER")
                .build();
            UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("password"))
                .roles("ADMIN")
                .build();

            JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
            jdbcUserDetailsManager.createUser(manager);
            jdbcUserDetailsManager.createUser(admin);
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
   
   
       // SecurityFilterChain bean will be managed by application context, which helps in filtering out the api's for web-based protection
        @Bean
        SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
            return httpSecurity
                .authorizeHttpRequests( auth -> {
                    auth.requestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")).permitAll();
                    auth.anyRequest().authenticated();
                })
                // ignore cross-site-request-forgery(CSRF) , though you should never disable it, but for to access some tools we need to disable it
                .csrf(csrf -> csrf.ignoringRequestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")))
                // important to display h2-console in frame in browser.
                .headers(headers -> headers.frameOptions(withDefaults()).disable())
                .formLogin(withDefaults())
                .httpBasic(withDefaults()) // if formLogin is not available, then we can use it.
                .build();
        }
   
   }

   ```
   
5. Test the API: using `admin`
   
   | API                                 | Access |
   |-------------------------------------|--------|
   | `http://localhost:8080/api/anyone`  | YES    |
   | `http://localhost:8080/api/manager` | YES    |
   | `http://localhost:8080/api/admin`   | YES    |

6. You can also see data in `h2-console` : `http://localhost:8080/h2-console`
![h2-console.png](src%2Fmain%2Fresources%2Fimages%2Fh2-console.png)