import React, { useEffect, useState } from 'react'
import { getWelcomeMessage } from '../api/user-api'

export default function WelcomePage() {
    const [welcomeMessage,setWelcomeMessage] = useState("");
    useEffect(()=>{
        const welcomePageApi = getWelcomeMessage().then((response)=>setWelcomeMessage(response));
    },[])
    //Let's call the API to test if it works or not 

    
  return (
    <div>
      {welcomeMessage}
    </div>
  )
}
