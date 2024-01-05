import axios from "axios";
import api from "../config/api-config";
import basicAuthAPI from "../config/basic-auth-api-config";
import registerApi from "../config/register-config";

export const getWelcomeMessage = () => {
   
   
    return api.get('/api/welcome-message' ).then((response) => {
        return response.data ?? {};
    }).catch(error => {
        console.error(error);
    });
}

export const registerNewUser = (userRegistrationDto) => {
    return registerApi.post('/register',userRegistrationDto ).then((response) => {
        return response.data ?? {};
    }).catch(error => {
        console.error(error);
        throw new Error("User Already Exist");
    });
}

export const loginUser = (userInfo) => {

    const authHeader =  window.btoa(userInfo.userEmail+":"+userInfo.userPassword);
    return basicAuthAPI.get('/token',{
        headers: { 
            'Authorization': 'Basic '+ authHeader,
        }

    }).then((response) => {
        window.localStorage.setItem('atquil_auth_token', response.data);
        return response.data ?? {};
    }).catch(error => {
        throw new Error("UserNotFound");
    });
}

export const getAllUsers = () => {

    return api.post('/api/all-user').then((response) => {
        return response.data ?? {};
    }).catch(error => {
        throw new Error(" No user found");
    });
}

export const deleteUser = (userEmail) => {
    const params ={
        userEmail:userEmail
    };
    return api.delete('/api/delete-user',{params},{
    }).then((response) => {
        console.log(response.data);
        return response.data ?? {};
    }).catch(error => {
        throw new Error("UserNotFound");
    });
}