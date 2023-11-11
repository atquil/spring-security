import React, { useState } from 'react';
import { registerNewUser } from '../api/user-api';


const Signup = () => {
    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [mobileNo, setMobileNo] = useState('');
    const [userRegistered,setUserRegistered] = useState(null);
    const [errorMessage,setErrorMessage] = useState('');
    const handleSubmit = (event) => {
        event.preventDefault();
        const userRegistrationDto = {
            userName: name,
            userEmail: email,
            userMobileNo: mobileNo,
            userPassword: password
        }
       
        registerNewUser(userRegistrationDto)
            .then((response)=>setUserRegistered(response))
            .catch((error)=>setErrorMessage('Login failed: ' + error.message));
    };
  return (
    <div>
        {userRegistered && userRegistered ?
            (
                <div>
                    User {userRegistered} has been registered
                </div>
            )
            :
            (
                <form onSubmit={handleSubmit}>
                    <label>
                        Name:
                        <input type="text" value={name} onChange={(e) => setName(e.target.value)} />
                    </label>
                    <br />
                    <label>
                        Email:
                        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
                    </label>
                    <br />
                    <label>
                        Mobile No:
                        <input type="password" value={mobileNo} onChange={(e) => setMobileNo(e.target.value)} />
                    </label>
                    <br />
                    <label>
                        Password:
                        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
                    </label>
                    <br />
                    <button type="submit">Signup</button>
                </form>
  
            )
        }
         {errorMessage && <div>{errorMessage}</div>}
    </div>
  )
}

export default Signup;