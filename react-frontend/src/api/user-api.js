import api from "../config/api-config";

export const getWelcomeMessage = () => {
   
   
    return api.get('/welcome-message' ).then((response) => {
        console.log("Response from the backend",response?.data);
        return response.data ?? {};
    }).catch(error => {
        console.error(error);
    });
}

export const registerNewUser = (userRegistrationDto) => {
    console.log("Sending data",userRegistrationDto);
    return api.post('/register',userRegistrationDto ).then((response) => {
        console.log("Response from the backend",response?.data);
        return response.data ?? {};
    }).catch(error => {
        console.error(error);
    });
}