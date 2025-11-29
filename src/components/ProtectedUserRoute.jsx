import React, { useEffect, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { getCurrentUser } from '../services/authService';

const ProtectedUserRoute = ({ children }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const [authState, setAuthState] = useState('checking'); // 'checking', 'authenticated', 'redirect'

  useEffect(() => {
    const currentUser = getCurrentUser();
    
    if (currentUser) {
      // User is logged in, check if they are a regular user
      if (currentUser.role === 'user') {
        // Allow access to the protected content
        setAuthState('authenticated');
      } else {
        // User has a different role, redirect to their dashboard
        setAuthState('redirect');
        setTimeout(() => navigate(currentUser.dashboard), 500);
      }
    } else {
      // No user logged in, store full current URL (path + search + hash) and redirect to user login
      const fullPath = `${location.pathname || ''}${location.search || ''}${location.hash || ''}`;
      sessionStorage.setItem('previousPage', fullPath);
      setAuthState('redirect');
      setTimeout(() => navigate('/admin/user-login?redirect=protected-content'), 500);
    }
  }, [navigate, location.pathname]);

  // Show the appropriate content based on auth state
  if (authState === 'checking') {
    return (
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        minHeight: '50vh',
        flexDirection: 'column',
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        color: '#fff',
        borderRadius: '1rem',
        margin: '2rem',
        padding: '2rem'
      }}>
        <div style={{
          fontSize: '2rem',
          marginBottom: '1rem',
          animation: 'spin 1s linear infinite'
        }}>
          🔄
        </div>
        <h2 style={{ marginBottom: '1rem' }}>Loading...</h2>
        <p style={{ textAlign: 'center', maxWidth: '400px' }}>
          Preparing your cultural journey...
        </p>
        <style>{`
          @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
          }
        `}</style>
      </div>
    );
  }

  if (authState === 'redirect') {
    return (
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        minHeight: '50vh',
        flexDirection: 'column',
        background: 'linear-gradient(135deg, #ff6b6b 0%, #ffa726 100%)',
        color: '#fff',
        borderRadius: '1rem',
        margin: '2rem',
        padding: '2rem'
      }}>
        <div style={{
          fontSize: '2rem',
          marginBottom: '1rem'
        }}>
          🔐
        </div>
        <h2 style={{ marginBottom: '1rem' }}>Redirecting...</h2>
        <p style={{ textAlign: 'center', maxWidth: '400px' }}>
          Taking you to the login page to access this content...
        </p>
      </div>
    );
  }

  // If authenticated, render the protected content
  if (authState === 'authenticated') {
    return children;
  }

  return null;
};

export default ProtectedUserRoute;