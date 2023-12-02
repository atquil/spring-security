import React, { useState, useEffect } from 'react';
import { getAllUser, getWelcomeMessage } from '../api/user-api';

import { Grid, Card, CardContent, Typography, CardHeader, Box, AppBar, Toolbar, IconButton, Button, colors } from '@mui/material';
import LogOut from '../common/function/logOut';
import { useNavigate } from 'react-router-dom';





export default function Dashboard() {
    const navigate = useNavigate();
  const [users, setUsers] = useState([]);
  const [uP, setUP] = useState(true);
  const [welcomeMessage,setWelcomeMessage] = useState('');
  useEffect(() => {
    if(!localStorage.getItem("auth_token")){
       navigate("/signIn");
    }
    else{ getAllUser().then((response) => {
        if(response){
            setUsers(response);
            
        }
        else{
            setUP(false);
        }
      
    }).catch((error) => {
        setUP(false);
    });

    getWelcomeMessage().then((response)=>{
        const responseMessage = response;
       setWelcomeMessage(responseMessage);
        console.log("welcome message:",welcomeMessage);
    }
    ).catch((error)=>{
        console.log("error");
    });
}
   
  }, []);

  return (
    <div>
        <div>
            <Box sx={{ flexGrow: 1 }}>
                <AppBar position="static">
                    <Toolbar>
                        <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
                            Dashboard
                        </Typography>
                        <LogOut/>
                    </Toolbar>
                </AppBar>
            </Box>
        </div>
       {welcomeMessage && 
        <div>
            {welcomeMessage}
        </div>
       }
       { !uP && <div>
            <Grid container spacing={5} direction="row" justify="center" alignItems="center" padding={5} >
            {users.map((user) => (
            <Grid item xs={12} sm={6} md={4} key={user.id}>
                <Card>
                <CardHeader title={user.userName} />
                <CardContent>
                    <Typography variant="body2" color="textSecondary" component="p">
                    Email: {user.emailId}
                    </Typography>
                    <Typography variant="body2" color="textSecondary" component="p">
                    Mobile Number: {user.mobileNumber}
                    </Typography>
                    <Typography variant="body2" color="textSecondary" component="p">
                    Role: {user.role}
                    </Typography>
                </CardContent>
                </Card>
            </Grid>
            ))}
        </Grid>
        
        </div>
      }
    </div>
  );
}
