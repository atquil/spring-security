import React from 'react';
import { useLocation } from 'react-router-dom';

export default function Dashboard() {
    const location = useLocation();
    const userName = location.state.userName;

    return (
        <div>
            Login Successful : {userName}
        </div>
    )
}
