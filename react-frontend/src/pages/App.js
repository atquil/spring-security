import React from 'react';
import WelcomePage from '../component/WelcomePage';
import { Route, RouterProvider, createBrowserRouter,Navigate } from 'react-router-dom';
import './App.css';
import Dashboard from '../component/Dashboard';
import SignIn from '../component/SignIn';
import SignUp from '../component/SignUp';
const router = createBrowserRouter([
  { path: '/', element: <WelcomePage /> },
  { path: '/signup', element: <SignUp /> },
  { path: '/dashboard', element: <Dashboard /> },
  { path: '/signIn', element: <SignIn /> },
  { path: '/*', element:<Navigate to="/" /> },
]);
function App() {
  return (
    <div className="App">
      <RouterProvider router ={router}>
        <Route path="/" element={<WelcomePage />} />
        <Route path="/signIn" element={<SignIn />} />
        <Route path="/signup" element={<SignUp />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="*" element={<Navigate to="/" />} />
      </RouterProvider>  
    </div>
  );
}

export default App;
