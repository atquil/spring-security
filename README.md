# spring-security

UserDetailsManager: It is an interface which provides ability to create new users and update existing ones

UserDetailsManager has two implementation
1. InMemoryUserDetailsManager : For small poc
2. JdbcUserDetailsManager: Can be used in prod, where we want to keep the user details strictly to our servers. 


## Setup 
1. Spring Initializer : https://start.spring.io/
2. Dependency : `spring-boot-starter-security`, `implementation 'com.h2database:h2'`, `implementation 'org.springframework.boot:spring-boot-starter-data-jpa'`

## Coding : 

1. Add, the configuration in `SecurityConfig` class

```java
@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry ->
                        authorizationManagerRequestMatcherRegistry.anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .build();
    }

}
```

2. Design a API just to check if above config is working fine or not. 

```java
@RestController
@RequestMapping("/api")
public class APIController {

    @GetMapping("/dummy")
    public ResponseEntity<String> getDummyData(){
        return ResponseEntity.ok("Returning dummy data");
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/dummy/admin")
    public ResponseEntity<String> getDummyDataForAdmin(){
        return ResponseEntity.ok("Admin: Dummy data");
    }
}
}

```

3. Testing the API : http://localhost:8080/api/dummy
![defaultPassword.png](src%2Fmain%2Fresources%2Fimages%2FdefaultPassword.png)

Login 
![defaultFormLogin.png](src%2Fmain%2Fresources%2Fimages%2FdefaultFormLogin.png)

Output: 
![defaultOutput.png](src%2Fmain%2Fresources%2Fimages%2FdefaultOutput.png)

4. Create a InMemoryUser with some role
```java
  @Bean
    InMemoryUserDetailsManager userDetailsManager(){
        return new InMemoryUserDetailsManager(
                User.withUsername("atquil")
                        .password("password")
                        .roles("ADMIN") //Helps in method security
                        .build()
        );
    }
```

5. Test the API with the role. : http://localhost:8080/api/dummy/admin

![dummyWithAdmin.png](src%2Fmain%2Fresources%2Fimages%2FdummyWithAdmin.png)

6. If we change the role from the user, then this api will not be assessed. 
```java
  @Bean
    InMemoryUserDetailsManager userDetailsManager(){
        return new InMemoryUserDetailsManager(
                User.withUsername("atquil")
                        .password("password")
                        .roles("OTHER") //Helps in method security
                        .build()
        );
    }
```

7. H2 Database configuration in `application.yml`

```properties
spring:
    h2:
        console:
            enabled: true



```

8. Add configuration so that, we can access h2Console without login in 

```java

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
```

9. Now, we need to EmbedScript for UserInfo, this sql script can be from userDefined or predefined. Here we are using predefined DDL script

```java

   @Bean
    EmbeddedDatabase datasource(){
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .setName("atquil")
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION) //Present default script to create user Roles
                .build();
    }
    
    // This datasource value will be passed to JdbcUserDetailsManager now. 
```

10. Login to H2 console : http://localhost:8080/h2-console/

![h2ConsoleImage.png](src%2Fmain%2Fresources%2Fimages%2Fh2ConsoleImage.png)

You will see that, default table has been created. 
![defaultH2ConsolePage.png](src%2Fmain%2Fresources%2Fimages%2FdefaultH2ConsolePage.png)

11. Now let's create a user and store it's details

```java
   @Bean
    JdbcUserDetailsManager userDetailsManager(DataSource dataSource){
        UserDetails userDetails = User.builder()
                .username("alpha")
                .password("password")
                .roles("ADMIN")
                .build();
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(userDetails);
        return jdbcUserDetailsManager;
    }
```

12. Let's restart the server and see if user exist in the h2-db. 
![userAlphaInDb.png](src%2Fmain%2Fresources%2Fimages%2FuserAlphaInDb.png)

13. Problem is the password is in plain text, which is not suitable so let's encrypt it 

- Let's introduce Bycrypt Password encoder 

```java

  @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
```

- Let's modify the `JdbcUserDetailsManager` so that it can take input for PasswordEncoder. 

```java
 @Bean
    JdbcUserDetailsManager userDetailsManager(DataSource dataSource){
        UserDetails userDetails = User.builder()
                .username("alpha")
                .password(passwordEncoder().encode("password"))
                .roles("ADMIN")
                .build();
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(userDetails);
        return jdbcUserDetailsManager;
    }

```

- Now the password saved as encrypted
![EncodedPasswordSaved.png](src%2Fmain%2Fresources%2Fimages%2FEncodedPasswordSaved.png)

14. Login using new userid and password to access the api : http://localhost:8080/api/dummy

![repoUser.png](src%2Fmain%2Fresources%2Fimages%2FrepoUser.png)
Done... 
