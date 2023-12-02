import { useNavigate } from "react-router-dom";

export default function LogOut() {
    const navigate = useNavigate();

    function handleLogout() {
      localStorage.clear();
      navigate('/');
    }
  return (
    <div>
       <button onClick={handleLogout} style={{
          
       }}>Logout</button>
    </div>
  )
}