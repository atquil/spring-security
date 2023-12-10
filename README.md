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
    @Table(name = "users")
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
                UserEntity userEntity = new UserEntity();
                userEntity.setUsername("atquil");
                userEntity.setPassword(passwordEncoder.encode("password")); 
                userEntity.setRoles("ROLE_USER,ROLE_ADMIN");
                userRepo.save(userEntity);
            };
        }
    }

   ```
5. Let's start the application and check these url `http://localhost:8080/h2-console`, and you can see that the user `atquil` is present in the database

![h2-console.png](src%2Fmain%2Fresources%2Fimages%2Fh2-console.png)

### Part 3: Configuring `SecurityConfig`, to use this user to access the `api`

1. Create a file `UserSecurityConfig` which will implement `UserDetails`, for `Authentication`, using the `UserEntity` object. 

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
   //UserDetails simply store user info which is later encapsulated into Authentication object.
   
       private final UserRepo userRepo;
       @Override
       public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
           Optional<UserEntity> user = userRepo.findByUsername(username);
           return userRepo
                   .findByUsername(username)
                   .map(UserSecurityConfig::new)
                   .orElseThrow(()-> new UsernameNotFoundException("User :"+username+" does not exist"));
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
   @RequestMapping("/api/user")
   @RequiredArgsConstructor
   public class UserController {
   
       private final UserRepo userRepo;
       //Everyone can access
       @GetMapping("/test1")
       public ResponseEntity<?> getTestAPI(){
           return ResponseEntity.ok("Response");
       }
   
       //Accessed only with the role USER
       @PreAuthorize("hasRole('ROLE_USER')")
       @GetMapping("/test2")
       public ResponseEntity<?> getTestAPI2(Principal principal){
               
           return ResponseEntity.ok(principal.getName()+" : All data from backend"+ userRepo.findAll());
       }
   
       //Accessed only with the role OWNER
       @PreAuthorize("hasRole('ROLE_OWNER')")
       @GetMapping("/test3")
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
   
3. Test with the url : 

| API                                    | Access |
|----------------------------------------|--------|
| `http://localhost:8080/api/user/test1` | Yes    |
| `http://localhost:8080/api/user/test2` | Yes    |
| `http://localhost:8080/api/user/test3` | No     |

### Part 5: Adding UI using react: `cd frontend` and do these steps. Or please open frontend from `vs-code`

1. Setup : 
   - Install : 
     - node: `https://nodejs.org/en/download` and check version using `npm -v`
     - yarn: `npm install --global yarn` and check using `yarn -v`
     - Add **axios**: `yarn add axios` for API's 
     - Add **Routing** : `yarn add react-router-dom`
     - Add **Material UI ** `yarn add @mui/material @emotion/react @emotion/styled`
   - Create project using `npx create-react-app frontend`
   - Update the project based on new version of react using : `npm install react-scripts@latest`
   - Add front-end `.gitIgnore` to main file as it will be used
      ```.gitignore
         # See https://help.github.com/articles/ignoring-files/ for more about ignoring files.
         
         # dependencies
         /node_modules
         /.pnp
         .pnp.js
         
         # testing
         /coverage
         
         # production
         /build
         
         # misc
         .DS_Store
         .env.local
         .env.development.local
         .env.test.local
         .env.production.local
         
         npm-debug.log*
         yarn-debug.log*
         yarn-error.log*
   
      ```
2. Create an api, which needs to be called, once we have Sign-In. 

   - Let's create a `.env` file, to hold env variable like `host` we are going to use: `REACT_APP_BACKEND_URL = http://localhost:8080/`
   - Create a folder `config` inside `src` and add `basic-auth-api-config.js`
   ```javascript
   import axios from "axios";
   
   
   const basicAuthAPI =  axios.create({
      baseURL: process.env.REACT_APP_BACKEND_URL,
      headers: {
            'Content-Type': 'application/json',
        }
   });
   
   
   export default basicAuthAPI;
   ```
   - Inside `api` folder add `user-api.js` where you will have all the backend-calling api
   ```javascript
   import basicAuthAPI from "../config/basic-auth-api-config";
   
   export const test2 = (userInfo) => {
   
       const authHeader =  window.btoa(userInfo.userEmail+":"+userInfo.userPassword);
       
       return basicAuthAPI.get('/api/user/test2',{
           headers: { 
               'Authorization': 'Basic '+ authHeader,
           }
   
       }).then((response) => {
           console.log("Response:::",response.data);
           return response.data ?? {};
       }).catch(error => {
           throw new Error("UserNotFound");
       });
   }
   ```

3. Let's create a `SignIn.js` page, using inside `pages` folder

   ```javascript
   import React, { useState } from 'react';
   import Avatar from '@mui/material/Avatar';
   import Button from '@mui/material/Button';
   import CssBaseline from '@mui/material/CssBaseline';
   import TextField from '@mui/material/TextField';
   import FormControlLabel from '@mui/material/FormControlLabel';
   import Checkbox from '@mui/material/Checkbox';
   import Link from '@mui/material/Link';
   import Grid from '@mui/material/Grid';
   import Box from '@mui/material/Box';
   
   import Typography from '@mui/material/Typography';
   import Container from '@mui/material/Container';
   import { useNavigate } from 'react-router-dom';
   
   import { test2 } from '../api/user-api';
   
   
   export default function SignIn() {
       const navigate = useNavigate();
       const [errorMessage, setErrorMessage] = useState('');
     const handleSubmit = (event) => {
       event.preventDefault();
       
       const data = new FormData(event.currentTarget);
       const userInfo = {
           userEmail: data.get('email'),
           userPassword:data.get('password')
       }
       test2(userInfo)
           .then((response)=>
               {    
                   navigate('/dashboard', { state: { response: response } });
               })
           .catch((error) => {
               setErrorMessage('Login failed: Please create your account');
           });
     };
   
     return (
       <div >
         <Container component="main" maxWidth="xs">
           <CssBaseline />
           <Box
             sx={{
               marginTop: 18,
               display: 'flex',
               flexDirection: 'column',
               alignItems: 'center',
             }}
           >
           {errorMessage && <div>{errorMessage}</div>}
             <Avatar sx={{ m: 1, bgcolor: 'secondary.main' }}>
              
             </Avatar>
             <Typography component="h1" variant="h5">
               Sign in
             </Typography>
             <Box component="form" onSubmit={handleSubmit}  sx={{ mt: 1 }}>
               <TextField
                 margin="normal"
                 required
                 fullWidth
                 id="email"
                 label="Email Address"
                 name="email"
                 autoComplete="email"
                 autoFocus
                 
               />
               <TextField
                 margin="normal"
                 required
                 fullWidth
                 name="password"
                 label="Password"
                 type="password"
                 id="password"
                 autoComplete="current-password"
               />
               <FormControlLabel
                 control={<Checkbox value="remember" color="primary" />}
                 label="Remember me"
               />
               <Button
                 type="submit"
                 fullWidth
                 variant="contained"
                 sx={{ mt: 3, mb: 2 }}
               >
                 Sign In
               </Button>
               <Grid container>
                 <Grid item xs>
                   <Link href="#" variant="body2">
                     Forgot password?
                   </Link>
                 </Grid>
                 <Grid item>
                   <Link href="/signUp" variant="body2">
                     {"Don't have an account? Sign Up"}
                   </Link>
                 </Grid>
               </Grid>
             </Box>
           </Box>
           
        
           <Copyright sx={{ mt: 8, mb: 4 }} />
         </Container>
         
       </div>
     );
   }
   
   function Copyright(props) {
       return (
         <Typography variant="body2" color="text.secondary" align="center" {...props}>
           {'Copyright © '}
           <Link color="inherit" href="https://www.youtube.com/@atquil1032">
             Atquil
           </Link>{' '}
           {new Date().getFullYear()}
           {'.'}
         </Typography>
       );
     }
   ```
4. Also create a `Dashboard.js` page to show the response data

   ```javascript
   import React from 'react';
   
   export default function Dashboard() {
    
         
     return (
       <div>
           You have have Sign-In
       </div>
     );
   }
   ```

5. Let's create a `routing`  in `App.js`

   ```javascript
   import React from 'react';
   import { Route, RouterProvider, createBrowserRouter,Navigate } from 'react-router-dom';
   import './App.css';
   import SignIn from '../component/SignIn';
   import Dashboard from './pages/Dashboard';
   
   const router = createBrowserRouter([
      { path: '/', element: <SignIn /> },
      { path: '/dashboard', element: <Dashboard /> },
      { path: '/*', element:<Navigate to="/" /> },
   ]);
   function App() {
      return (
              <div className="App">
                 <RouterProvider router ={router}>
                    <Route path="/" element={<SignIn />} />
                    <Route path="/dashboard" element={<Dashboard />} />
                 </RouterProvider>
              </div>
      );
   }
   
   export default App;
   ```
3. Add an `url` to connect with in `.env` file : 
3. 