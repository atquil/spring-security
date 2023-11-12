import LoginPage from '../component/LoginPage';
import React from 'react';
import Signup from '../component/SignUpPage';
import WelcomePage from '../component/WelcomePage';
import { Route, RouterProvider, Routes, createBrowserRouter,Navigate } from 'react-router-dom';
import './App.css';
import Dashboard from '../component/Dashboard';
const router = createBrowserRouter([
  { path: '/', element: <WelcomePage /> },
  { path: '/login', element: <LoginPage /> },
  { path: '/signup', element: <Signup /> },
  { path: '/dashboard', element: <Dashboard /> },
  { path: '/*', element:<Navigate to="/" /> },
]);
function App() {
  return (
    <div className="App">
      <RouterProvider router ={router}>
        <Route path="/" element={<WelcomePage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="*" element={<Navigate to="/" />} />
      </RouterProvider>  
    </div>
  );
}

export default App;
