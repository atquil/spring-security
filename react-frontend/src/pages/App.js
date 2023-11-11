import LoginPage from '../component/LoginPage';
import React from 'react';
import Signup from '../component/SignUpPage';
import WelcomePage from '../component/WelcomePage';
import './App.css';

function App() {
  return (
    <div className="App">
     <LoginPage></LoginPage>

     <br></br>
      <Signup></Signup>

      <br></br>
     <WelcomePage></WelcomePage>
    </div>
  );
}

export default App;
