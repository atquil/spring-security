import React from 'react';
import { Route, RouterProvider, createBrowserRouter,Navigate } from 'react-router-dom';
import './App.css';
import SignIn from './pages/SignIn';
import Dashboard from './pages/Dashboard';


const router = createBrowserRouter([
  { path: '/', element: <SignIn /> },
  { path: '/dashboard', element: <Dashboard /> },
  { path: '/*', element:<Navigate to="/" /> },
]);
function App() {
  return (
    <div className="App">
      <RouterProvider router ={router}>
        <Route path="/" element={<SignIn />} />
        <Route path="/dashboard" element={<Dashboard />} />
      </RouterProvider>  
    </div>
  );
}

export default App;