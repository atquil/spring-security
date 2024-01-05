import React, { useState, useEffect } from 'react';
import { deleteUser, getAllUsers, getWelcomeMessage } from '../api/user-api';

import { Grid, Card, CardContent, Typography, CardHeader, Box, AppBar, Toolbar, IconButton, Button, colors } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import ClearIcon from '@mui/icons-material/Clear';
import LogOutButton from '../common/function/logOut';


export default function Dashboard() {
    const navigate = useNavigate();
    const [users, setUsers] = useState([]);
    const [isUserListLoading, setIsUserListLoading] = useState(true);
    const [welcomeMessage, setWelcomeMessage] = useState('');
  
    const fetchUsers = () => {
      getAllUsers()
        .then((response) => {
          if (response) {
            setUsers(response);
            setIsUserListLoading(true);
          } else {
            setIsUserListLoading(false);
          }
        })
        .catch((error) => {
          console.log("Error fetching user data", error);
          setIsUserListLoading(false);
        });
    };
  
    useEffect(() => {
      if (!localStorage.getItem("atquil_auth_token")) {
        navigate("/signIn");
      } else {
        fetchUsers();
  
        getWelcomeMessage()
          .then((response) => {
            const responseMessage = response;
            setWelcomeMessage(responseMessage);
          })
          .catch((error) => {
            console.log("Error fetching welcome message", error);
          });
      }
    }, []);
  
    const handleDeleteUser = (userEmail) => {
      deleteUser(userEmail)
        .then(() => {
          // Reload user data after successful deletion
          fetchUsers();
        })
        .catch((error) => {
          console.log("Error deleting user", error);
          // Handle error if needed
        });
    };
  
    return (
      <div>
        <div>
          <Box sx={{ flexGrow: 1 }}>
            <AppBar position="static">
              <Toolbar>
                <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
                  Dashboard
                </Typography>
                <LogOutButton />
              </Toolbar>
            </AppBar>
          </Box>
        </div>
        {welcomeMessage && <div>{welcomeMessage}</div>}
        {isUserListLoading && (
          <div>
            <Grid container spacing={5} direction="row" justify="center" alignItems="center" padding={5}>
              {users.map((user) => (
                <Grid item xs={12} sm={6} md={4} key={user.id}>
                  <Card>
                    <CardHeader
                      title={user.userName}
                      action={
                        <IconButton aria-label="close" onClick={() => handleDeleteUser(user.emailId)}>
                          <ClearIcon />
                        </IconButton>
                      }
                    />
                    <CardContent>
                      <Typography variant="body2" color="textSecondary" component="p">
                        Email: {user.emailId}
                      </Typography>
                      <Typography variant="body2" color="textSecondary" component="p">
                        Mobile Number: {user.mobileNumber}
                      </Typography>
                      <Typography variant="body2" color="textSecondary" component="p">
                        Roles: {user.roles}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </div>
        )}
      </div>
    );
  }