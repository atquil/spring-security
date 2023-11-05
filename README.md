# spring-security



Any applicaiton that provides the OAUTH2 authentication can be used, so here we are usign GITHUB, we can also use Google, Twitter etc. 


### Setup Project :

1. Spring Initializer : https://start.spring.io/
2. Dependency: `spring-boot-starter-oauth2-client`, `spring-boot-starter-web`



## Creation of Oauth2.0 client in Github

1. Login to your github account -> go to `settings`
![githubSettings.png](src%2Fmain%2Fresources%2Fimages%2FgithubSettings.png)
2. Go to developer Setting in Github
![developerSettings.png](src%2Fmain%2Fresources%2Fimages%2FdeveloperSettings.png)
3. Go to OAuthApps --> Register a new application
![oauth2apps.png](src%2Fmain%2Fresources%2Fimages%2Foauth2apps.png)
4. Fill the application : `http://localhost:8080/login/oauth2/code/github`
![registerApplication.png](src%2Fmain%2Fresources%2Fimages%2FregisterApplication.png)
5. Get client-id
![clientId.png](src%2Fmain%2Fresources%2Fimages%2FclientId.png)
6. Generate client-secrete
![clientScerete.png](src%2Fmain%2Fresources%2Fimages%2FclientScerete.png)


```properties

application.properties

spring.security.oauth2.client.registration.github.client-id=599c29a5b22730b83088
spring.security.oauth2.client.registration.github.client-secret=3696bf549bfacc9b1d6072c446b63b5e0cf05706

application.yml

spring:
    security:
        oauth2:
            client:
                registration:
                    github:
                        client-id: 599c29a5b22730b83088
                        client-secret: 3696bf549bfacc9b1d6072c446b63b5e0cf05706

```

7. Create the APIs

```java
@RestController
public class APIController {

    @GetMapping
    public ResponseEntity<String> getOpenData(){
        return ResponseEntity.ok("Open Access");
    }

    @GetMapping("/oauth")
    public ResponseEntity<String> getOauthData(){
        return ResponseEntity.ok("Secured Data");
    }
}
```
9. Secure these api's using the above configuration 
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {


    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .authorizeHttpRequests(auth->{
                    auth.requestMatchers("/").permitAll();
                    auth.anyRequest().authenticated();
                    })
                .oauth2Login(withDefaults()) // setup in application properties to say which provider we want
                .formLogin(withDefaults()) //default login
                .build();
    }
}


```
8. Now let's first check with Open Access: `http://localhost:8080/`
![openAccess.png](src%2Fmain%2Fresources%2Fimages%2FopenAccess.png)
9. Now let's connect with oauth , where we have configured to 
![loginWindow.png](src%2Fmain%2Fresources%2Fimages%2FloginWindow.png)
10. Try to login using Github


## Setup for google 

1. Go to `https://console.cloud.google.com/`
2. Create a consentForm first (if first time creating)
![createConsent.png](src%2Fmain%2Fresources%2Fimages%2FcreateConsent.png)
3. Click on oauthClientId
![createOauth.png](src%2Fmain%2Fresources%2Fimages%2FcreateOauth.png)
4. Create URL: `http://localhost:8080/login/oauth2/code/google`
![formFill.png](src%2Fmain%2Fresources%2Fimages%2FformFill.png)
5. Now copy the client id and client secrete and put it in form
![clientCreated.png](src%2Fmain%2Fresources%2Fimages%2FclientCreated.png)
```properties
spring:
  security:
    oauth2:
      client:
        registration:
          github:
            client-id: 599c29a5b22730b83088
            client-secret: 3696bf549bfacc9b1d6072c446b63b5e0cf05706
          google:
            client-id: 796876257612-inmd2pr3gmni4e92fik8r0bdjvf46i1d.apps.googleusercontent.com
            client-secret: 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
```
6. Restart again to see the login screen for `http://localhost:8080/oauth`
![googleLogin.png](src%2Fmain%2Fresources%2Fimages%2FgoogleLogin.png)
7. After Login output
![output.png](src%2Fmain%2Fresources%2Fimages%2Foutput.png)