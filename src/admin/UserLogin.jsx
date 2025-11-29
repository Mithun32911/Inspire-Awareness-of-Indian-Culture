import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { authenticateUser, rememberCredentials, getRememberedCredentials, initiateForgotPassword, verifyOtpAndReset } from '../services/authService';
import './Admin.css';
import './ContentCreatorDashboard.css';

const UserLogin = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const [successMessage, setSuccessMessage] = useState('');
  const [showForgot, setShowForgot] = useState(false);
  const [forgotEmail, setForgotEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [forgotMessage, setForgotMessage] = useState('');
  const [redirectMessage, setRedirectMessage] = useState('');
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    // Check if user was redirected from protected content
    const urlParams = new URLSearchParams(location.search);
    if (urlParams.get('redirect') === 'protected-content') {
      setRedirectMessage('Please login to access Culture, Heritage, and Monuments content.');
    }
  }, [location]);

  useEffect(() => {
    const remembered = getRememberedCredentials();
    if (remembered) {
      setUsername(remembered.email || '');
      setPassword(remembered.password || '');
      setRememberMe(true);
    }
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setError('Please enter both email and password.');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const result = authenticateUser(username.trim(), password.trim());
      
      if (result.success) {
        // Check if user role matches the login type
        if (result.user.role === 'user') {
          // Show success message briefly then navigate so user sees the confirmation
          setSuccessMessage('Login successful! Redirecting...');
          const previousPage = sessionStorage.getItem('previousPage');
          setTimeout(() => {
            setSuccessMessage('');
            if (rememberMe) rememberCredentials(username.trim(), password.trim());
            if (previousPage) {
              navigate(`${result.user.dashboard}?from=${encodeURIComponent(previousPage)}`);
            } else {
              navigate(result.user.dashboard);
            }
          }, 800);
        } else {
          setError('Invalid credentials for User login. Please check your role.');
        }
      } else {
        setError(result.message);
      }
        // rememberCredentials will be handled when we actually navigate (so it persists before leaving)
    } catch (err) {
      console.error('UserLogin error:', err);
      setError('Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const startForgot = () => {
    setForgotMessage('');
    if (!forgotEmail) return setForgotMessage('Please enter your email');
    const res = initiateForgotPassword(forgotEmail.trim());
    setForgotMessage(res.message || 'OTP sent');
  };

  const submitReset = async () => {
    if (!otp || !newPassword) return setForgotMessage('Enter OTP and new password');
    const res = verifyOtpAndReset(forgotEmail.trim(), otp.trim(), newPassword);
    setForgotMessage(res.message);
    if (res.success) {
      setShowForgot(false);
      setForgotEmail(''); setOtp(''); setNewPassword('');
    }
  };

  return (
    <div className="admin-container">
      <button
        className="admin-back-btn"
        onClick={() => navigate('/')}
        style={{ position: 'absolute', left: 20, top: 20, padding: '8px 12px', borderRadius: 6, border: 'none', background: '#0d0d0dff', color: 'white', cursor: 'pointer' }}
      >
        Back
      </button>
      <div className="admin-login-form">
        <h1>User Login</h1>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="email">Email</label>
            <input
              type="email"
              id="email"
              value={username}
              onChange={e => setUsername(e.target.value)}
              placeholder="enter your email"
              autoComplete="username"
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="enter your password"
              autoComplete="current-password"
            />
          </div>

          <div className="form-actions" style={{ marginTop: '1rem', display: 'flex', justifyContent: 'center' }}>
            <button type="submit" className="admin-btn secondary" disabled={loading} style={{ width: 220, maxWidth: '90%', background: loading ? '#888' : '#1976d2', color: '#fff', border: 'none', padding: '0.6rem 1rem', borderRadius: 6 }}>{loading ? 'Logging in...' : 'Login'}</button>
          </div>

          {redirectMessage && (
            <div className="info-box" style={{ marginTop: '1rem' }}>{redirectMessage}</div>
          )}
          {error && (
            <div className="auth-error">{error}</div>
          )}
          {successMessage && (
            <div className="auth-success" style={{ color: '#1b5e20' }}>{successMessage}</div>
          )}

          <div style={{ marginTop: '1rem' }}>
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
              <input type="checkbox" checked={rememberMe} onChange={e => setRememberMe(e.target.checked)} /> Remember me
            </label>
            <div style={{ marginTop: 8 }}>
              <a href="#" onClick={() => navigate('/admin/user-signup')}>Don't have an account? Sign Up</a>
              {' | '}
              <a href="#" onClick={(e) => { e.preventDefault(); setShowForgot(s => !s); }}>Forgot password?</a>
            </div>
            {showForgot && (
              <div style={{ marginTop: 12, padding: 12, border: '1px solid #eee', borderRadius: 8 }}>
                <h4>Forgot Password</h4>
                <input type="email" placeholder="Enter your email" value={forgotEmail} onChange={e => setForgotEmail(e.target.value)} style={{ width: '100%', marginBottom: 8 }} />
                <div style={{ display: 'flex', gap: 8 }}>
                  <button onClick={startForgot} className="admin-btn">Send OTP</button>
                  <button onClick={() => { setForgotEmail(''); setOtp(''); setNewPassword(''); setShowForgot(false); }} className="admin-btn secondary">Cancel</button>
                </div>
                {forgotMessage && <div style={{ marginTop: 8 }}>{forgotMessage}</div>}
                <div style={{ marginTop: 12 }}>
                  <input type="text" placeholder="Enter OTP" value={otp} onChange={e => setOtp(e.target.value)} style={{ width: '100%', marginBottom: 8 }} />
                  <input type="password" placeholder="New password" value={newPassword} onChange={e => setNewPassword(e.target.value)} style={{ width: '100%', marginBottom: 8 }} />
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button onClick={submitReset} className="admin-btn">Reset Password</button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </form>
      </div>
    </div>
  );
};

export default UserLogin;