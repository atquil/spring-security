import React from 'react';
import { Route, RouterProvider, createBrowserRouter,Navigate } from 'react-router-dom';
import './App.css';
import Dashboard from './Dashboard';
import SignIn from './SignIn';
import SignUp from './SignUp';
const router = createBrowserRouter([
  { path: '/', element: <SignIn /> },
  { path: '/signup', element: <SignUp /> },
  { path: '/dashboard', element: <Dashboard /> },
  { path: '/signIn', element: <SignIn /> },
  { path: '/*', element:<Navigate to="/" /> },
]);
function App() {
  return (
    <div className="App">
      <RouterProvider router ={router}>
        <Route path="/" element={<SignIn />} />
        <Route path="/signIn" element={<SignIn />} />
        <Route path="/signup" element={<SignUp />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="*" element={<Navigate to="/" />} />
      </RouterProvider>  
    </div>
  );
}

export default App;
