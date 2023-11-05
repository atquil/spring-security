# spring-security
Note: (If you are using JIO images will not be shown, please use other internet provider)
https://www.danvega.dev/blog/2022/09/09/spring-security-jwt
## What and when to use JWT
Spring Security supports protecting endpoints using two forms of OAuth 2.0 Bearer Tokens:
1. JWT
2. Opaque Tokens

This is handy in circumstances where an application has delegated its authority management to an authorization server (for example, Okta or Spring Authorization Server). This authorization server can be consulted by resource servers to authorize requests.


**Self-signed JWTs**, which will eliminate the need to introduce an authorization server may work in small project but may also use it like

Scenerios when Self-signed JWT is not acceptable: 
1. When you want to introduce a **refresh tokens**
2. Distribuaton Architecture : When you have more than one services or you want to be able to harden security

Spring Authorization server. .. 
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


9. Create a **resource server**

Signing JWT

JWT has 3 parts `header`, `payload`, and `signature`. 

The header is created using encrypting the header + payload and a secreat(or private key)

A JWT can be encrypted using either a symmetric key (shared secret) or asymmetric keys (the private key of a private-public pair).
- Symmetric key: The same key is used for both encryption (when the JWT is created) and decryption (MobileTogether Server uses the key to verify the JWT). The symmetric key—also known as the shared secret—is stored as a setting in MobileTogether Server. See Symmetric Key: Shared Secret for details of working with symmetric keys.
- Asymmetric keys: Different keys are used for encryption (private key) and decryption (public key). The public key is stored as a setting in MobileTogether Server so that the JWT can be verified. For information about using asymmetric encryption for JWTs, see Asymmetric Keys: Public Key.
  There are pros/cons to each but it is generally recommended that you use Asymmetric keys so that is the approach you will take here.

 ### Creating a self-signed token using command line

1. Create a folder to hold your secrets
2. Change the location in terminal to that folder
```
 cd src/main/resources/certs

```

3. Generate a rsa token (for windows follow this link)

- Private Key for encryption 
```java
openssl genrsa -out keypair.pem 2048   
```
- Generate a public key from the private key that you just created
```java
 openssl rsa -in keypair.pem -pubout -out publicKey.pem 

```
Now we need to format the private key (keypair.pem) in supported format (PKCS8 format)

```java

openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out private.pem

```

We can now remove the keypair.pem key as we just need public and private key. 

4. Externalise the private and public key , as we don't want it to go in production with code. So we must take value from external source like environment variable etc. 


```properties
rsa:
  rsa-private-key: classpath:certs/private.pem
  rsa-public-key: classpath:certs/publicKey.pem
```
 Using `config-processor` get the values. 
 
- Create a class through which you will access the key, and add to the spring boot 

```java

@EnableConfigurationProperties(RSAKeyRecord.class)
@SpringBootApplication
public class SpringSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityApplication.class, args);
    }

}
```
Inside `RSAKeyRecord.class` 

```java
@ConfigurationProperties(prefix = "rsa") // it's the prefix taking values from properties file. 
public record RSAKeyRecord (RSAPublicKey rsaPublicKey, RSAPrivateKey rsaPrivateKey){

}
```

Now we also need to update our `Security filter chain file` to add jwt, as resource server `httpSecurityOAuth2ResourceServerConfigurer.jwt(Customizer.withDefaults())`

NOTE: JWT() has been depricated after 6.1

```java
@Configuration
@EnableWebSecurity // This will enable us to override the default security behaviour of spring security.
@RequiredArgsConstructor
public class SecurityConfig {
    // Quick tip : Never disable CSRF withouth leaving session managment enable

    private final RSAKeyRecord rsaKeyRecord;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
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
}
```

Now, let's decode the request, as we are using asymtric then public key otherswise with symitric we will use secretekey

```java
  @Bean
    JwtDecoder jwtDecoder(){
        return NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();
    }
    

```

Ok, now let's encode 

```java

 @Bean
    JwtEncoder jwtEncoder(){
        //Nimbus need a source
        JWK jwk = new RSAKey.Builder(rsaKeyRecord.rsaPublicKey()).privateKey(rsaKeyRecord.rsaPrivateKey()).build();
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwkSource);
    }
```

5. Let's create a Post request to get the token to access all of them : `AuthController.class`

```java

@RestController
@Slf4j
@RequiredArgsConstructor
public class AuthController {


    private final JWTTokenService jwtTokenService;

    @PostMapping("/token")
    public String token(Authentication authentication) {
        log.debug("Token requested for user: '{}'", authentication.getName());
        String token = jwtTokenService.generateToken(authentication);
        log.debug("Token granted: {}", token);
        return token;
    }
}

```

## Manual Testing

1. First we need a jwt token so that we can make a request
   - Call the API : http://localhost:8080/token
   - We are using basic auth so , add your user name and password that we have created
2. You will receive the jwt token

![token.png](src%2Fmain%2Fresources%2Fimages%2Ftoken.png)

3. Now use this token to call the api. It will be valid for 1 hr as the time limit we have set. 

![bearToken.png](src%2Fmain%2Fresources%2Fimages%2FbearToken.png)

4. Call the getAPI: http://localhost:8080/api/dummy/user-detail

![output.png](src%2Fmain%2Fresources%2Fimages%2Foutput.png)

## Automated test

1. Add spring security test dependency 'testImplementation 'org.springframework.security:spring-security-test'
2. Write different test (inside the repo)