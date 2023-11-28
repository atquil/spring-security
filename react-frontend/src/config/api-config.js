import axios from "axios";


const api = axios.create({
    baseURL: process.env.REACT_APP_BACKEND_URL,
    headers: {
        'Content-Type': 'application/json'
    }
});

 api.interceptors.request.use(
     config => {
//         // JWT Config in future
        const token = window.localStorage.getItem('auth_token');
        if(token){
            config.headers['Authorization'] = `Bearer ${token}`
        }
         return config;
     },
     error => Promise.reject(error)
 )


export default api;