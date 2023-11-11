// import LoginPage from '../component/LoginPage';
import React from 'react';
import Signup from '../component/SignUpPage';
import WelcomePage from '../component/WelcomePage';
import './App.css';

function App() {
  return (
    <div className="App">
     {/* <LoginPage></LoginPage>
     <Signup/> */}
      <Signup></Signup>
     <WelcomePage></WelcomePage>
    </div>
  );
}

export default App;
