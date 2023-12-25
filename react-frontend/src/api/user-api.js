import { setAuthHeader } from "../auth/login";
import api from "../config/api-config";
import basicAuthAPI from "../config/basic-auth-api-config";

export const getWelcomeMessage = () => {
   
   
    return api.get('/api/welcome-message' ).then((response) => {
        return response.data ?? {};
    }).catch(error => {
        console.error(error);
    });
}

export const registerNewUser = (userRegistrationDto) => {
    return api.post('/register',userRegistrationDto ).then((response) => {
        return response.data ?? {};
    }).catch(error => {
        console.error(error);
        throw new Error("User Already Exist");
    });
}

export const loginUser = (userInfo) => {

    const authHeader =  window.btoa(userInfo.userEmail+":"+userInfo.userPassword);
    console.log("----",authHeader);
    return basicAuthAPI.get('/token',{
        headers: { 
            'Authorization': 'Basic '+ authHeader,
        }

    }).then((response) => {
        console.log("Sucessfully logedin");
        window.localStorage.setItem('auth_token', response.data);
        //setAuthHeader(response.data);
        console.log(response.data);
        return response.data ?? {};
    }).catch(error => {
        throw new Error("UserNotFound");
    });
}

export const getAllUser = () => {
    console.log("In here");
    return api.post('/api/all-user').then((response) => {
        return response.data ?? {};
    }).catch(error => {
        throw new Error(" No user found");
    });
}

