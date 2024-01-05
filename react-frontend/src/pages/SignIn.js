import React, { useState } from 'react';
import Avatar from '@mui/material/Avatar';
import Button from '@mui/material/Button';
import CssBaseline from '@mui/material/CssBaseline';
import TextField from '@mui/material/TextField';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import Link from '@mui/material/Link';
import Grid from '@mui/material/Grid';
import Box from '@mui/material/Box';

import Typography from '@mui/material/Typography';
import Container from '@mui/material/Container';
import { loginUser } from '../api/user-api';
import { useNavigate } from 'react-router-dom';
import validateEmail from '../common/function/validateEmail';




export default function SignIn() {
    const navigate = useNavigate();
    const [errorMessage, setErrorMessage] = useState('');
  const handleSubmit = (event) => {
    event.preventDefault();
    
    const data = new FormData(event.currentTarget);
    if (!validateEmail(data.get('email'))) {
        setErrorMessage('Invalid email address');
        return;
    }
    const userInfo = {
        userEmail: data.get('email'),
        userPassword:data.get('password')
    }
    loginUser(userInfo)
    .then((response)=>
        {
            
            navigate('/dashboard', { state: { userName: response } });
        })
    .catch((error) => {
        setErrorMessage('Login failed: Please create your account');
    });
  };

  return (
    <div >
      <Container component="main" maxWidth="xs">
        <CssBaseline />
        <Box
          sx={{
            marginTop: 18,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
          }}
        >
        {errorMessage && <div>{errorMessage}</div>}
          <Avatar sx={{ m: 1, bgcolor: 'secondary.main' }}>
           
          </Avatar>
          <Typography component="h1" variant="h5">
            Sign in
          </Typography>
          <Box component="form" onSubmit={handleSubmit}  sx={{ mt: 1 }}>
            <TextField
              margin="normal"
              required
              fullWidth
              id="email"
              label="Email Address"
              name="email"
              autoComplete="email"
              autoFocus
              
            />
            <TextField
              margin="normal"
              required
              fullWidth
              name="password"
              label="Password"
              type="password"
              id="password"
              autoComplete="current-password"
            />
            
            <Button
              type="submit"
              fullWidth
              variant="contained"
              sx={{ mt: 3, mb: 2 }}
            >
              Sign In
            </Button>
            <Grid container>
              <Grid item xs>
                <Link href="#" variant="body2">
                  Forgot password?
                </Link>
              </Grid>
              <Grid item>
                <Link href="/signUp" variant="body2">
                  {"Don't have an account? Sign Up"}
                </Link>
              </Grid>
            </Grid>
          </Box>
        </Box>
        
     
        <Copyright sx={{ mt: 8, mb: 4 }} />
      </Container>
      
    </div>
  );
}

function Copyright(props) {
    return (
      <Typography variant="body2" color="text.secondary" align="center" {...props}>
        {'Copyright © '}
        <Link color="inherit" href="https://www.youtube.com/@atquil1032">
          Atquil
        </Link>{' '}
        {new Date().getFullYear()}
        {'.'}
      </Typography>
    );
  }