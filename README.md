# spring-security-



## 1. Create a connection between react frontend and spring-boot backend :

### Backend

Setup: 
1. Spring Initializer : https://start.spring.io/
2. Dependency: `spring-boot-starter-web`, `lombok`

Coding: 
1. Create a `controller` package and add a `WelcomePageController` in it 
```java
package com.atquil.springSecurity.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author atquil
 */
@RestController
public class WelcomePageController {

    @GetMapping("/welcome-message")
    public ResponseEntity<String> getFirstWelcomeMessage(){

        return ResponseEntity.ok("Welcome to the tutorial");
    }
}

```

2. Create `config` package and add `SecurityConfig`. We will enable react to request API's call to spring-boot. By default spring boot restrict these to save from CROS attack. 
```java

package com.atquil.springSecurity.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.util.Arrays;
import java.util.List;

/**
 * @author atquil
 */
@Configuration
@EnableWebMvc
public class SecurityConfig {

    private static final Long MAX_AGE = 3600L;
    private static final int CORS_FILTER_ORDER = -102;

    @Bean
    public FilterRegistrationBean corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("http://localhost:3000");
        config.setAllowedHeaders(Arrays.asList(
                HttpHeaders.AUTHORIZATION,
                HttpHeaders.CONTENT_TYPE,
                HttpHeaders.ACCEPT));
        config.setAllowedMethods(Arrays.asList(
                HttpMethod.GET.name(),
                HttpMethod.POST.name(),
                HttpMethod.PUT.name(),
                HttpMethod.DELETE.name()));
        config.setMaxAge(MAX_AGE);
        source.registerCorsConfiguration("/**", config);
        FilterRegistrationBean bean = new FilterRegistrationBean(new CorsFilter(source));
        
        bean.setOrder(CORS_FILTER_ORDER);
        return bean;
    }
}

```
3. Run the api using : `htpp://localhost:8080/welcome-message`
4. Let's start with front-end now

### Frontend: 


Folder Structure (Please add a PR, if you are following a better folder structure)
1. `api` : All the API that you are going to develop, will be here.
2. `assets`: It will hold all the `images`
3. `component`: What we want to display inside the pages
4. `config` : All the configuration for the application, along with environment variables
5. `pages`: The actual page you will be seeing e.g. `localhost:3000/home` etc
6. `styles`: It will hold all the styling file like `.css`



Setup: 

1. Install `node` :(https://nodejs.org/en/download). Check using `node -v` in terminal
2. Node will also install `npm` . Check using `npm -v` in terminal
3. Now install yarn `npm install --global yarn` .
    -  [Interview Question] Why to install yarn when you have node ? As yarn install packages parallel, which is faster than npm which has sequential installation process. Also yarn has more reliable version management system then npm.

4. To add environment configuration,
    - create a `.env` file in the root directory
    - Add the environment variable starting with `REACT_APP_<...>` e.g. `REACT_APP_BACKEND_URL = http://localhost:8080/`

5.  Add `axios` to the project : `yarn add axios`
- [Interview Question] What and why axios? It handles `promise-based HTTP request and response`
    - Axios is easy to use and has many features, including:
        - Interceptors for request and response
        - Automatic transforms for JSON data
        - Automatic data object serialization to multipart/form-data and x-www-form-urlencoded body encodings
        - Client-side support for protecting against XSRF
        - Automatic transforms for JSON data

- Create a `api-config.js` file inside `config` folder, here we will add the configuration for our api's
 ```
     import axios from "axios";


     const api = axios.create({
         baseURL: process.env.REACT_APP_BACKEND_URL,
         headers: {
             'Content-Type': 'application/json'
         }
     });

     export default api;
 ```
6. Create a `WelcomePage.js` in `component`, to call the backendApi `/welcome-page` to display the message
   ```
    import React, { useEffect, useState } from 'react'
    import { getWelcomeMessage } from '../api/user-api'

    export default function WelcomePage() {
        const [welcomeMessage,setWelcomeMessage] = useState("");
        useEffect(()=>{
            const welcomePageApi = getWelcomeMessage().then((response)=>setWelcomeMessage(response));
        },[])
        //Let's call the API to test if it works or not 

        
    return (
        <div>
        {welcomeMessage}
        </div>
    )
    }
   ```
7. Move `App.js` to `pages` folder that you have created and add `WelcomePage` inside it 

```js

import WelcomePage from '../component/WelcomePage';
import './App.css';

function App() {
  return (
    <div className="App">
     <WelcomePage></WelcomePage>
    </div>
  );
}

export default App;
```
8. Start the application using: `yarn start`
9. Output : 

![welcome-page-output.png](src%2Fmain%2Fresources%2Fimages%2Fwelcome-page-output.png)


## 2. SignUp page with Creating user

### Backend

Setup: 
1. Dependency : `com.h2database:h2` , `spring-boot-starter-data-jpa`
2. Add configuration to `application.yml` file 
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
      ddl-auto: create-drop #Create new db everytime i start the project
```
3. Create a `record` , called `UserRegistrationDto` which will be used to get the info from frontend to backend
```java
public record UserRegistrationDto (String userName, String userEmail, String userMobileNo, String userPassword){}

```
4. Create the `UserController` to hold the API, `UserService` and `UserRepo` to hold the info and save the info in db. 


- UserInfoEntity in `entity` package
```java
@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name="USER_INFO")
public class UserInfoEntity {

    @Id
    @GeneratedValue(strategy= GenerationType.UUID) //It will find the best suitable match based on what kind of db we are using
    private String id;

    @Column(name = "USER_NAME")
    private String userName;


    @Column(nullable = false, name = "EMAIL")
    private String emailId;

    @Column(name = "MOBILE_NUMBER")
    private String mobileNumber;

    @Column(nullable = false, name = "PASSWORD")
    private String password;
}

```

- UserInfoRepo in `repo` package
```java
@Repository
public interface UserInfoRepo extends JpaRepository<UserInfoEntity,String> {
    Optional<UserInfoEntity> findByEmailId(String userEmailId);
}
```

- Create a UserRegistrationDto 
```java
public record UserRegistrationDto (String userName, String userEmail, String userMobileNo, String userPassword){}

```

- Create a mapper to transform dto to entity
```java
@Component
public class UserInfoMapper {



    public UserInfoEntity convertToEntity(UserRegistrationDto userRegistrationDto) {

        UserInfoEntity userInfoEntity = new UserInfoEntity();
        userInfoEntity.setUserName(userRegistrationDto.userName());
        userInfoEntity.setEmailId(userRegistrationDto.userEmail());
        userInfoEntity.setMobileNumber(userRegistrationDto.userMobileNo());
        return userInfoEntity;
    }
}
```
- Create a service to add the user to db
```java
@Service
@RequiredArgsConstructor
public class UserRegistrationService {
    private final UserInfoRepo userInfoRepo;
    private final UserInfoMapper userInfoMapper;

    public String registerUser(UserRegistrationDto userRegistrationDto){

        log.info("UserRegistrationDto:::"+userRegistrationDto);
        Optional<UserInfoEntity> user = userInfoRepo.findByEmailId(userRegistrationDto.userEmail());
        if(user.isPresent()){
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User with emailId:"+userRegistrationDto.userEmail()+" already exist");
        }
        // Now Map the DTO to Entities
        UserInfoEntity userInfoEntity = userInfoMapper.convertToEntity(userRegistrationDto);
        //About password, we will have to encode it then save it.

        userInfoEntity.setPassword(userRegistrationDto.userPassword()); // Need to encrypt
        //Save the user

        UserInfoEntity savedUserDetails = userInfoRepo.save(userInfoEntity);
        return  savedUserDetails.getUserName()+" account has been created";
    }

}

```
- Finally Create a API to 
```java
@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserInfoService userInfoService;
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody UserRegistrationDto userRegistrationDto){
        return ResponseEntity.ok(userInfoService.registerUser(userRegistrationDto));
    }
}

```
- Now hit the endpoint 
```
POST http://localhost:8080/register
Content-Type: application/json

{
  "userEmail": "abc",
  "userMobileNo": "123",
  "userName": "alpha",
  "userPassword": "abcd"
}

Output: alpha account has been created
```

### FrontEnd

1. Let's create the `POST` api in `user-api.js`

```javascript
export const registerNewUser = (userRegistrationDto) => {
    return api.post('/register',userRegistrationDto ).then((response) => {
        return response.data ?? {};
    }).catch(error => {
        console.error(error);
        throw new Error("User Already Exist");
    });
}
```

2. Let's create a page called `SignUpPage.js` inside `component` folder. It's a simple page which will call the Api once subit button is pressed. 
```javascript
import React, { useState } from 'react';
import { registerNewUser } from '../api/user-api';


const Signup = () => {
    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [mobileNo, setMobileNo] = useState('');
    const [userRegistered,setUserRegistered] = useState(null);
    const [errorMessage,setErrorMessage] = useState('');
    const handleSubmit = (event) => {
        event.preventDefault();
        const userRegistrationDto = {
            userName: name,
            userEmail: email,
            userMobileNo: mobileNo,
            userPassword: password
        }

        registerNewUser(userRegistrationDto)
            .then((response)=>setUserRegistered(response))
            .catch((error)=>setErrorMessage('Login failed: ' + error.message));
    };
    return (
        <div>
            {userRegistered && userRegistered ?
                (
                    <div>
                        User {userRegistered} has been registered
                    </div>
                )
                :
                (
                    <form onSubmit={handleSubmit}>
                        <label>
                            Name:
                            <input type="text" value={name} onChange={(e) => setName(e.target.value)} />
                        </label>
                        <br />
                        <label>
                            Email:
                            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
                        </label>
                        <br />
                        <label>
                            Mobile No:
                            <input type="password" value={mobileNo} onChange={(e) => setMobileNo(e.target.value)} />
                        </label>
                        <br />
                        <label>
                            Password:
                            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
                        </label>
                        <br />
                        <button type="submit">Signup</button>
                    </form>

                )
            }
            {errorMessage && <div>{errorMessage}</div>}
        </div>
    )
}

export default Signup;

```
2. Let's add that to our   `App.js` page
```javascript
import React from 'react';
import Signup from '../component/SignUpPage';
import WelcomePage from '../component/WelcomePage';
import './App.css';

function App() {
  return (
    <div className="App">
      <Signup></Signup>
     <WelcomePage></WelcomePage>
    </div>
  );
}

export default App;

```
4. Output : 

- Page loads
![signup1.png](src%2Fmain%2Fresources%2Fimages%2Fsignup1.png)
- After submit
![Signup2Success.png](src%2Fmain%2Fresources%2Fimages%2FSignup2Success.png)




## 3. Login Page

### Backend

1. Create a `record` which will take value `eamil` and `password` to search for the database for the user

```java
public record UserLoginUsingEmailDto(String userEmail, String userPassword){
}
```
2. Create a `endpoint` which will take the record and a `service` which will search the repo for the record. 

```java
    @PostMapping ("/login")
    public ResponseEntity<?> checkUserForLogin(@RequestBody UserLoginUsingEmailDto userLoginUsingEmailDto){
        return ResponseEntity.ok(userInfoService.getUserDetailsUsingEmail(userLoginUsingEmailDto));
    }
```

```java
public String getUserDetailsUsingEmail(UserLoginUsingEmailDto userLoginUsingEmailDto) {
        Optional<UserInfoEntity> user = userInfoRepo.findByEmailId(userLoginUsingEmailDto.userEmail());
        if(user.isEmpty()){
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, userLoginUsingEmailDto.userEmail()+ " not found. Please consider registering");
        }
        UserInfoEntity userInfoEntity = user.get();
        return userInfoEntity.getUserName();
        
    }
```

### Frontend

1. Create an `api` , to get the value in `user-api.js`
```javascript
export const loginUser = (userInfo) => {
    return api.post('/login',userInfo).then((response) => {
        return response.data ?? {};
    }).catch(error => {
        throw new Error("UserNotFound");
    });
}

```

2. Create a `LoginPage.js` inside component

```javascript
import React, { useState } from 'react';
import { loginUser } from '../api/user-api';


export default function LoginPage() {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [loginSuccess,setLoginSuccess] = useState(false);
    const [userName,setUserName] = useState('');
    const [errorMessage, setErrorMessage] = useState('');

    const handleSubmit = (event) => {
        event.preventDefault();

        // Validate email
        if (!validateEmail(email)) {
            setErrorMessage('Invalid email address');
            return;
        }

        const userInfo = {
            userEmail: email,
            userPassword:password
        }
        loginUser(userInfo)
            .then((response)=>
                {
                    setLoginSuccess(true);
                    setUserName(response);
                })
            .catch((error) => {
                setLoginSuccess(false);
                setErrorMessage('Login failed: ' + error.message);
            });
    }
    return (
        <div>
            {loginSuccess ? 
                (
                    <div>
                        Login Successful : {userName}
                    </div>
                ):
                (
                <form onSubmit={handleSubmit}>
                    <label>
                        Email:
                        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
                    </label>
                    <br />
                    <label>
                        Password:
                        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
                    </label>
                    <br />
                    <button type="submit">Login</button>
                </form>
                )
            }
            {errorMessage && <div>{errorMessage}</div>}
        </div>
    )
}


function validateEmail(email) {
    var re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(String(email).toLowerCase());
}
```

3. Add the page in `App.js`
```javascript
import LoginPage from '../component/LoginPage';
import React from 'react';
import Signup from '../component/SignUpPage';
import WelcomePage from '../component/WelcomePage';
import './App.css';

function App() {
  return (
    <div className="App">
     <LoginPage></LoginPage>

     <br></br>
      <Signup></Signup>

      <br></br>
     <WelcomePage></WelcomePage>
    </div>
  );
}

export default App;

```
Output:
- Register `ab@gmail.com`
![RegistringAtquil.png](src%2Fmain%2Fresources%2Fimages%2FRegistringAtquil.png)
 
![AtquilAccountCreated.png](src%2Fmain%2Fresources%2Fimages%2FAtquilAccountCreated.png)

- Login Failed Attempt
![LoginFailedWrongEmail.png](src%2Fmain%2Fresources%2Fimages%2FLoginFailedWrongEmail.png)
- Login Success Attempt
![LoginSuccess.png](src%2Fmain%2Fresources%2Fimages%2FLoginSuccess.png)

## 4. Routing to Dashboard and Logout

1. Add `yarn add react-router-dom` for routing
2. Modify the `App.js` page for routing
```javascript
import { BrowserRouter as Router, Route, Switch } from 'react-router-dom';
import React from 'react';
import Signup from '../component/SignUpPage';
import LoginPage from '../component/LoginPage';
import WelcomePage from '../component/WelcomePage';
import Dashboard from './Dashboard';

import './App.css';

function App() {
    return (
        <Router>
            <div className="App">
                <Switch>
                    <Route path="/dashboard">
                        <Dashboard />
                    </Route>
                    <Route path="/">
                        <LoginPage />
                        <br />
                        <Signup />
                        <br />
                        <WelcomePage />
                    </Route>
                </Switch>
            </div>
        </Router>
    );
}

export default App;

```
3. Create a Dashboard.js page. 
```javascript
import React from 'react';
import { useLocation } from 'react-router-dom';

export default function Dashboard() {
    const location = useLocation();
    const userName = location.state.userName;

    return (
        <div>
            Login Successful : {userName}
        </div>
    )
}

```

4. Now, modify `LoginPage.js` to redirect to Dashboard if successfully

- App.js
```javascript
import LoginPage from '../component/LoginPage';
import React from 'react';
import Signup from '../component/SignUpPage';
import WelcomePage from '../component/WelcomePage';
import { Route, RouterProvider, Routes, createBrowserRouter,Navigate } from 'react-router-dom';
import './App.css';
import Dashboard from '../component/Dashboard';
const router = createBrowserRouter([
  { path: '/', element: <WelcomePage /> },
  { path: '/login', element: <LoginPage /> },
  { path: '/signup', element: <Signup /> },
  { path: '/dashboard', element: <Dashboard /> },
  { path: '/*', element:<Navigate to="/" /> },
]);
function App() {
  return (
    <div className="App">
      <RouterProvider router ={router}>
        <Route path="/" element={<WelcomePage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="*" element={<Navigate to="/" />} />
      </RouterProvider>  
    </div>
  );
}

export default App;

```
- LoginPage.js
```javascript
import React, { useState } from 'react';
import { loginUser } from '../api/user-api';
import { useNavigate } from 'react-router-dom';

export default function LoginPage() {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [loginSuccess,setLoginSuccess] = useState(false);
    const [userName,setUserName] = useState('');
    const [errorMessage, setErrorMessage] = useState('');
    const navigate = useNavigate();
    const handleSubmit = (event) => {
        event.preventDefault();

        // Validate email
        if (!validateEmail(email)) {
            setErrorMessage('Invalid email address');
            return;
        }

        const userInfo = {
            userEmail: email,
            userPassword:password
        }
        loginUser(userInfo)
            .then((response)=>
                {
                    navigate('/dashboard', { state: { userName: response } });
                })
            .catch((error) => {
                navigate('/dashboard', { state: { userName: "d" } });
                setLoginSuccess(false);
                setErrorMessage('Login failed: ' + error.message);
            });
    }
    return (
        <div>
            {loginSuccess ? 
                (
                    <div>
                        Login Successful : {userName}
                    </div>
                ):
                (
                <form onSubmit={handleSubmit}>
                    <label>
                        Email:
                        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
                    </label>
                    <br />
                    <label>
                        Password:
                        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
                    </label>
                    <br />
                    <button type="submit">Login</button>
                </form>
                )
            }
            {errorMessage && <div>{errorMessage}</div>}
        </div>
    )
}


function validateEmail(email) {
    var re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(String(email).toLowerCase());
}


```

- SignUp.js
```javascript
import React, { useState } from 'react';
import { registerNewUser } from '../api/user-api';
import { useNavigate } from 'react-router-dom';


const Signup = () => {
    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [mobileNo, setMobileNo] = useState('');
    const [userRegistered,setUserRegistered] = useState(null);
    const [errorMessage,setErrorMessage] = useState('');
    const navigate = useNavigate();
    const handleSubmit = (event) => {
        event.preventDefault();
        const userRegistrationDto = {
            userName: name,
            userEmail: email,
            userMobileNo: mobileNo,
            userPassword: password
        }
       
        registerNewUser(userRegistrationDto)
            .then((response)=>{
                setUserRegistered(response);
                navigate('/login', { state: { userName: response } });}
            )
            .catch((error)=>setErrorMessage('Login failed: ' + error.message));
    };
  return (
    <div>
        {userRegistered && userRegistered ?
            (
                <div>
                    User {userRegistered} has been registered
                </div>
            )
            :
            (
                <form onSubmit={handleSubmit}>
                    <label>
                        Name:
                        <input type="text" value={name} onChange={(e) => setName(e.target.value)} />
                    </label>
                    <br />
                    <label>
                        Email:
                        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
                    </label>
                    <br />
                    <label>
                        Mobile No:
                        <input type="password" value={mobileNo} onChange={(e) => setMobileNo(e.target.value)} />
                    </label>
                    <br />
                    <label>
                        Password:
                        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
                    </label>
                    <br />
                    <button type="submit">Signup</button>
                </form>
  
            )
        }
         {errorMessage && <div>{errorMessage}</div>}
    </div>
  )
}

export default Signup;
```

- Import that you have `yarn add react-router-dom ` for navigation

### Modify The UI design to look everything beautiful 

- Add Material Ui in your project : `yarn add @mui/material @emotion/react @emotion/styled`
- Get the signInPage form here: https://github.com/mui/material-ui/tree/v5.14.17/docs/data/material/getting-started/templates/sign-in
- Create a Component `SignIn.js`