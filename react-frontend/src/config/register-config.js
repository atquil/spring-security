import axios from "axios";

const registerApi = axios.create({
    baseURL: process.env.REACT_APP_BACKEND_URL,
    headers: {
        'Content-Type': 'application/json'
    }
});

export default registerApi ;