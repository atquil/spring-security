import api from "../config/api-config";

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
    return api.post('/login',userInfo).then((response) => {
        return response.data ?? {};
    }).catch(error => {
        throw new Error("UserNotFound");
    });
}