import React, { useEffect, useState } from 'react'
import { getWelcomeMessage } from '../api/user-api'
import { Link } from 'react-router-dom';

export default function WelcomePage() {
    const [welcomeMessage,setWelcomeMessage] = useState("");
    useEffect(()=>{
        getWelcomeMessage().then((response)=>setWelcomeMessage(response));
    },[])
    //Let's call the API to test if it works or not 

    
  return (
    <div>
      {welcomeMessage}
      <div>
        <h1>Welcome</h1>
        <Link to="/login">Login</Link>
        <br />
        <Link to="/signup">Signup</Link>
        <br/>
      </div>
    </div>
  )
}
