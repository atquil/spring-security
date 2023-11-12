import React, { useState, useEffect } from 'react';
import { getAllUser } from '../api/user-api';

import { Grid, Card, CardContent, Typography, CardHeader, Box, AppBar, Toolbar, IconButton, Button, colors } from '@mui/material';
import LogOut from '../common/function/logOut';




export default function Dashboard() {
 
  const [users, setUsers] = useState([]);
 

  useEffect(() => {
    getAllUser().then((response) => {
      setUsers(response);
    });
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
                        <LogOut />
                    </Toolbar>
                </AppBar>
            </Box>
        </div>
       
        <div>
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
      
    </div>
  );
}
