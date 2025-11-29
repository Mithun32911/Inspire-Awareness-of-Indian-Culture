import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { initiateForgotPassword } from '../services/authService';
import './Admin.css';

const AdminLogin = ({ onLogin }) => {
  const navigate = useNavigate();
  const [credentials, setCredentials] = useState({ identifier: '', password: '' }); // identifier = email or username
  const [isRegistering, setIsRegistering] = useState(false);
  const [registerData, setRegisterData] = useState({ email: '', username: '', password: '', confirmPassword: '' });
  const [rememberMe, setRememberMe] = useState(false);
  const [showForgot, setShowForgot] = useState(false);
  const [forgotEmail, setForgotEmail] = useState('');
  const [forgotMessage, setForgotMessage] = useState('');
  const [error, setError] = useState('');
  const [showSuccess, setShowSuccess] = useState(false);
  const [successMessage, setSuccessMessage] = useState('');

  const getSavedCredentials = () => {
    const saved = localStorage.getItem('adminCredentials');
    return saved ? JSON.parse(saved) : null;
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setCredentials(prev => ({ ...prev, [name]: value }));
  };

  const handleRegisterInputChange = (e) => {
    const { name, value } = e.target;
    setRegisterData(prev => ({ ...prev, [name]: value }));
  };

  const handleRegister = (e) => {
    e.preventDefault();
    const { email, username, password, confirmPassword } = registerData;
    if (!email || !username || !password || !confirmPassword) {
      setError('Please fill all registration fields.');
      return;
    }
    // Simple email validation
    const emailValid = /^\S+@\S+\.\S+$/.test(email);
    if (!emailValid) {
      setError('Please enter a valid email address.');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }
    // Save only necessary fields
    const toSave = { email, username, password };
  localStorage.setItem('adminCredentials', JSON.stringify(toSave));
  setError('Registration successful! You can now log in using your email or username.');
    setIsRegistering(false);
    setCredentials({ identifier: '', password: '' });
    setRegisterData({ email: '', username: '', password: '', confirmPassword: '' });
  };

  const handleLogin = (e) => {
    e.preventDefault();
    const saved = getSavedCredentials();
    const { identifier, password } = credentials;
    // clear previous error
    setError('');
    if (!identifier || !password) {
      setError('Please enter your email/username and password.');
      return;
    }
    if (!saved) {
      setError('No admin account found. Please register first.');
      return;
    }
    const matchesUsername = identifier === saved.username && password === saved.password;
    const matchesEmail = identifier === saved.email && password === saved.password;
    if (matchesUsername || matchesEmail) {
      setError('');
      // show success message above the login block
      setSuccessMessage('Login successful Redirecting');
      // proceed after a short delay so the user sees the message
      setTimeout(() => {
        setSuccessMessage('');
        if (typeof onLogin === 'function') onLogin();
      }, 800);
    } else {
      setError('Invalid credentials. Please try again or register.');
    }
  };

  return (
    <div className="admin-container">
      {/* success banner (renders inside the form) will show via .top-success-banner */}
      <button
        className="admin-back-btn"
        onClick={() => navigate('/')}
        style={{ position: 'absolute', left: 20, top: 20, padding: '8px 12px', borderRadius: 6, border: 'none', background: '#0d0d0dff', color: 'white',   cursor: 'pointer' }}
      >
        Back
      </button>
      <div className="admin-login-form">
        {successMessage && (
          <div className="top-success-banner" role="status" aria-live="polite">
            <div className="auth-success">{successMessage}</div>
          </div>
        )}
        <h1>{isRegistering ? 'Admin Register' : 'Admin Login'}</h1>
        {isRegistering ? (
          <form onSubmit={handleRegister}>
            <div className="form-group">
              <label htmlFor="reg-email">Email:</label>
              <input
                type="email"
                id="reg-email"
                name="email"
                value={registerData.email}
                onChange={handleRegisterInputChange}
                required
                placeholder="enter your email"
              />
            </div>
            <div className="form-group">
              <label htmlFor="reg-username">Username:</label>
              <input
                type="text"
                id="reg-username"
                name="username"
                value={registerData.username}
                onChange={handleRegisterInputChange}
                required
                placeholder="enter your username"
              />
            </div>
            <div className="form-group">
              <label htmlFor="reg-password">Password:</label>
              <input
                type="password"
                id="reg-password"
                name="password"
                value={registerData.password}
                onChange={handleRegisterInputChange}
                required
                placeholder=" enter your password"
              />
            </div>
            <div className="form-group">
              <label htmlFor="reg-confirm">Confirm Password:</label>
              <input
                type="password"
                id="reg-confirm"
                name="confirmPassword"
                value={registerData.confirmPassword}
                onChange={handleRegisterInputChange}
                required
                placeholder="re-enter password"
              />
            </div>
            <div className="admin-btn-row">
              <button type="submit" className="admin-btn primary">Register</button>
              <button type="button" className="admin-btn" onClick={() => setIsRegistering(false)}>Back to Login</button>
            </div>
          </form>
        ) : (
          <form onSubmit={handleLogin}>
            <div className="form-group">
              <label htmlFor="identifier">Email or Username:</label>
              <input
                type="text"
                id="identifier"
                name="identifier"
                value={credentials.identifier}
                onChange={handleInputChange}
                required
                placeholder="Email or Username"
              />
            </div>
            <div className="form-group">
              <label htmlFor="password">Password:</label>
              <input
                type="password"
                id="password"
                name="password"
                value={credentials.password}
                onChange={handleInputChange}
                required
                placeholder="Enter your password"
              />
            </div>
            <div className="admin-btn-row">
              <button type="submit" className="admin-btn primary">Login</button>
              <button type="button" className="admin-btn" onClick={() => setIsRegistering(true)}>Register</button>
            </div>
            {error && <div className="auth-error">{error}</div>}
            <div style={{ marginTop: 12 }}>
              <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                <input type="checkbox" checked={rememberMe} onChange={e => setRememberMe(e.target.checked)} /> Remember me
              </label>
              {' | '}
              <a href="#" onClick={(e) => { e.preventDefault(); setShowForgot(s => !s); }}>Forgot password?</a>
              {showForgot && (
                <div style={{ marginTop: 8, padding: 8, border: '1px solid #eee', borderRadius: 6 }}>
                  <input value={forgotEmail} onChange={e => setForgotEmail(e.target.value)} placeholder="Enter admin email" style={{ width: '100%', marginBottom: 8 }} />
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button className="admin-btn" onClick={() => { setForgotMessage(''); const res = initiateForgotPassword(forgotEmail.trim()); setForgotMessage(res.message); }}>Send OTP</button>
                    <button className="admin-btn secondary" onClick={() => { setShowForgot(false); setForgotEmail(''); setForgotMessage(''); }}>Cancel</button>
                  </div>
                  {forgotMessage && <div style={{ marginTop: 8 }}>{forgotMessage}</div>}
                </div>
              )}
            </div>
          </form>
        )}
        
      </div>
    </div>
  );
};

export default AdminLogin;
