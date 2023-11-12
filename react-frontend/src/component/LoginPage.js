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