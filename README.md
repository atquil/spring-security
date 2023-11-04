# spring-security

https://www.danvega.dev/blog/2022/09/09/spring-security-jwt
## What and when to use JWT

When you want to delegate authority management to some type of Autorization server
## JWT Authentication : 

Architecture Diagram: 



### 

- Explaination : https://youtu.be/b9O9NI-RJ3o?t=1861


### Setup. 
1. Spring Initializer : https://start.spring.io/
2. Dependency : 

![dependency.png](src%2Fmain%2Fresources%2Fimages%2Fdependency.png)

Note: `oauth2-resource-server` has many of the `spring-security` resource, like `security-config`, `security-core`, 

### Coding: 

1. Design some simple API

```java
@RestController
@RequestMapping("/api")
public class APIController {

    @GetMapping("/dummy")
    public ResponseEntity<String> getResponse(){
        return ResponseEntity.ok("I am getting response");
    }
}
```

2. Ping the API , and you will be redirected to login page where you should use `user` and password as in terminal. 
![defaultLogin.png](src%2Fmain%2Fresources%2Fimages%2FdefaultLogin.png)
3. API output for : `http://localhost:8080/api/dummy`
![defaultOutput.png](src%2Fmain%2Fresources%2Fimages%2FdefaultOutput.png)

4. `WebSecurityConfigurationAdapter` has been depricated from `spring-security-5.7`
5. Now create a `SecurityConfig.java` file to put your configuration, also `@EnableWebSecurity` tells that it with override the bean for default web security
6. Inside `SecurityConfig.java` create a bean which will handle the authentication for the user

```java
@Configuration
@EnableWebSecurity // This will enable us to override the default security behaviour of spring security.
public class SecurityConfig {
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
}
```

7. Add a default User to it 

```java

@Configuration
@EnableWebSecurity // This will enable us to override the default security behaviour of spring security.
public class SecurityConfig {
    
    //Security Config. ...
    @Bean
    public InMemoryUserDetailsManager user() {
        return new InMemoryUserDetailsManager(
                User.withUsername("atquil")
                        .password("{noop}password") //encrypt the password.usng bean
                        .authorities("read")
                        .build()
        );
    }
}
```

8. Now if you want to see the user Details when API is called , use `Principal` 
```java
//Note: Principal is not @RequestBody
 @GetMapping("/dummy/user-detail")
    public ResponseEntity<String> getUserDetails(Principal principal){
        return ResponseEntity.ok(principal.getName() +" Is the user");
    }
```
![getUserDetailsAfterLogin.png](src%2Fmain%2Fresources%2Fimages%2FgetUserDetailsAfterLogin.png)