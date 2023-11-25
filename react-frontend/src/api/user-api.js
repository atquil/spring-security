import api from "../config/api-config";
import basicAuthAPI from "../config/basic-auth-api-config";

export const getWelcomeMessage = () => {
   
   
    return api.get('/welcome-message' ).then((response) => {
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

    const authHeader = btoa(userInfo.userEmail+':'+userInfo.userPassword);
 
    return basicAuthAPI.post('/token',{
        headers: {
            'Authorization': authHeader
        }

    }).then((response) => {
        console.log(response.data);
        return response.data ?? {};
    }).catch(error => {
        throw new Error("UserNotFound");
    });
}

export const getAllUser = () => {
    return api.get('/api/all-user').then((response) => {
        return response.data ?? {};
    }).catch(error => {
        throw new Error(" No user found");
    });
}