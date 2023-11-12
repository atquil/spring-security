import React from 'react'
import { Link } from 'react-router-dom';
import { Paper,colors } from '@mui/material';
import Stack from '@mui/material/Stack';
import { styled } from '@mui/material/styles';


const DemoPaper = styled(Paper)(({ theme, color }) => ({
  width: 120,
  height: 120,
  padding: theme.spacing(2),
  ...theme.typography.body2,
  textAlign: 'center',
  color:'white',
  backgroundColor: color,
  //Make text in center
  display: 'flex',
  justifyContent: 'center',
  alignItems: 'center',
  textDecoration: 'none',
  borderRadius:20,
}));

const CenteredStack = styled(Stack)({
  display: 'flex',
  justifyContent: 'center',
  alignItems: 'center',
  height: '100vh',
  backgroundColor: colors.grey[300]
});

export default function WelcomePage() {
  return (
    <div>
    <CenteredStack direction="row" spacing={2} >
      <Link  style={{textDecoration:'none'}} to="/signIn">
        <DemoPaper elevation={15} square={false} color={colors.teal[500]}>SignIn</DemoPaper>
      </Link>
      <Link style={{textDecoration:'none'}} to="/signUp">
        <DemoPaper elevation={15} square color={colors.pink[400]}>SignUp</DemoPaper>
      </Link>
    </CenteredStack>
  </div>
  )
}
