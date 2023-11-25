import axios from "axios";


const basicAuthAPI =  axios.create({
    baseURL: process.env.REACT_APP_BACKEND_URL,
    headers: {
        'Authorization': 'Basic YUBiLmNvbTphQGIuY29t'
    }
});

// api.interceptors.request.use(
//     config => {
//         // JWT Config in future
//         return config;
//     },
//     error => Promise.reject(error)
// )


export default basicAuthAPI;