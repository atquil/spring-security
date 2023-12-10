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