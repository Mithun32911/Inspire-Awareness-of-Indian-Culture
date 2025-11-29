import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authenticateUser, rememberCredentials, getRememberedCredentials, initiateForgotPassword, verifyOtpAndReset } from '../services/authService';
import { useEffect } from 'react';

const CulturalEnthusiastLogin = () => {
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
  const [captcha, setCaptcha] = useState('');
  const [captchaInput, setCaptchaInput] = useState('');
  const [captchaError, setCaptchaError] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    const remembered = getRememberedCredentials();
    if (remembered) {
      setUsername(remembered.email || '');
      setPassword(remembered.password || '');
      setRememberMe(true);
    }
    const gen = () => Math.random().toString(36).slice(2, 8).toUpperCase();
    setCaptcha(gen());
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
      setCaptchaError('');
      if (!captchaInput || captchaInput.trim().toUpperCase() !== captcha) {
        setCaptchaError('Invalid captcha');
        setLoading(false);
        return;
      }
      const result = await authenticateUser(username.trim(), password.trim());
      
      if (result && result.success) {
        // Check if user role matches the login type (admin for cultural enthusiast)
        if (result.user.role === 'admin') {
          setSuccessMessage('Login successful! Redirecting...');
          setTimeout(() => {
            setSuccessMessage('');
            const previousPage = sessionStorage.getItem('previousPage');
            if (previousPage) {
              sessionStorage.removeItem('previousPage');
              navigate(previousPage);
            } else {
              navigate(result.user.dashboard);
            }
          }, 800);
        } else {
          setError('Invalid credentials for Admin login. Please check your role.');
        }
      } else {
        setError(result ? result.message : 'Login failed.');
      }
      if (result && result.success && rememberMe) rememberCredentials(username.trim(), password.trim());
    } catch {
      setError('Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const refreshCaptcha = () => {
    const gen = () => Math.random().toString(36).slice(2, 8).toUpperCase();
    setCaptcha(gen());
    setCaptchaInput('');
    setCaptchaError('');
  };

  return (
    <section className="vh-100 gradient-custom" style={{ minHeight: '100vh', background: 'linear-gradient(to right, #6a11cb, #2575fc)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <fieldset style={{
        maxWidth: '400px',
        width: '100%',
        margin: '0 auto',
        borderRadius: '1rem',
        border: '2px solid #fff',
        background: 'rgba(20, 20, 40, 0.95)',
        color: '#fff',
        boxShadow: '0 0 32px 0 #0008',
        padding: '2.5rem 2rem',
        textAlign: 'center',
      }}>
        <legend style={{ fontSize: '2rem', fontWeight: 'bold', color: '#fff', letterSpacing: '2px', marginBottom: '1.5rem' }}>Admin Login</legend>
        <form onSubmit={handleSubmit}>
          <p style={{ color: '#fff', fontWeight: 'bold', fontSize: '1.1rem', marginBottom: '2rem' }}>Welcome Admin! Manage the heritage platform.</p>
          <div style={{ background: 'rgba(255,255,255,0.1)', padding: '1rem', borderRadius: '0.5rem', marginBottom: '1.5rem', fontSize: '0.9rem' }}>
            <p style={{ color: '#2575fc', fontWeight: 'bold', marginBottom: '0.5rem' }}>Test Credentials:</p>
            <p style={{ color: '#fff', margin: '0.2rem 0' }}> admin@heritage.com</p>
            <p style={{ color: '#fff', margin: '0.2rem 0' }}> admin123</p>
          </div>
          <input
            type="email"
            id="typeEmailX"
            value={username}
            onChange={e => setUsername(e.target.value)}
            placeholder="Email"
            autoComplete="username"
            style={{
              width: '100%',
              padding: '0.8rem',
              marginBottom: '1.2rem',
              borderRadius: '0.5rem',
              border: '1px solid #fff',
              background: '#222',
              color: '#fff',
              fontSize: '1rem',
              fontWeight: 'bold',
              outline: 'none',
            }}
          />
          <input
            type="password"
            id="typePasswordX"
            value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder="Password"
            autoComplete="current-password"
            style={{
              width: '100%',
              padding: '0.8rem',
              marginBottom: '1.2rem',
              borderRadius: '0.5rem',
              border: '1px solid #fff',
              background: '#222',
              color: '#fff',
              fontSize: '1rem',
              fontWeight: 'bold',
              outline: 'none',
            }}
          />
          <p style={{ marginBottom: '2rem', fontSize: '0.95rem' }}>
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, color: '#fff' }}>
              <input type="checkbox" checked={rememberMe} onChange={e => setRememberMe(e.target.checked)} /> Remember me
            </label>
            {' '}
            <a href="#" style={{ color: '#ffd700', textDecoration: 'underline', fontWeight: 'bold' }} onClick={(e) => { e.preventDefault(); setShowForgot(s => !s); }}>Forgot password?</a>
            {showForgot && (
              <div style={{ marginTop: 12, padding: 12, border: '1px solid #eee', borderRadius: 8, background: '#111', color: '#fff' }}>
                <h4>Forgot Password</h4>
                <input type="email" placeholder="Enter your email" value={forgotEmail} onChange={e => setForgotEmail(e.target.value)} style={{ width: '100%', marginBottom: 8 }} />
                <div style={{ display: 'flex', gap: 8 }}>
                  <button onClick={() => { setForgotMessage(''); const res = initiateForgotPassword(forgotEmail.trim()); setForgotMessage(res.message || 'OTP sent'); }} className="admin-btn">Send OTP</button>
                  <button onClick={() => { setForgotEmail(''); setOtp(''); setNewPassword(''); setShowForgot(false); }} className="admin-btn secondary">Cancel</button>
                </div>
                {forgotMessage && <div style={{ marginTop: 8 }}>{forgotMessage}</div>}
                <div style={{ marginTop: 12 }}>
                  <input type="text" placeholder="Enter OTP" value={otp} onChange={e => setOtp(e.target.value)} style={{ width: '100%', marginBottom: 8 }} />
                  <input type="password" placeholder="New password" value={newPassword} onChange={e => setNewPassword(e.target.value)} style={{ width: '100%', marginBottom: 8 }} />
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button onClick={() => { const res = verifyOtpAndReset(forgotEmail.trim(), otp.trim(), newPassword); setForgotMessage(res.message); if (res.success) { setShowForgot(false); setForgotEmail(''); setOtp(''); setNewPassword(''); } }} className="admin-btn">Reset Password</button>
                  </div>
                </div>
              </div>
            )}
          </p>
          <button type="submit" disabled={loading} style={{
            width: '100%',
            padding: '0.9rem',
            borderRadius: '2rem',
            border: 'none',
            background: loading ? '#666' : 'linear-gradient(90deg, #6a11cb 0%, #2575fc 100%)',
            color: '#fff',
            fontWeight: 'bold',
            fontSize: '1.1rem',
            boxShadow: '0 2px 8px #0006',
            cursor: loading ? 'not-allowed' : 'pointer',
            marginBottom: '1.5rem',
            letterSpacing: '1px',
          }}>{loading ? 'Logging in...' : 'Login'}</button>
          <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 12, justifyContent: 'center' }}>
            <div style={{ padding: 12, background: '#f3f3f3', borderRadius: 6, fontWeight: '700', letterSpacing: 3, fontSize: 20, userSelect: 'none' }}>{captcha}</div>
            <div style={{ display: 'flex', flexDirection: 'column', width: 220, maxWidth: '60%' }}>
              <input type="text" value={captchaInput} onChange={e => setCaptchaInput(e.target.value)} placeholder="Enter captcha" style={{ padding: '0.5rem', borderRadius: 6, border: '1px solid #ccc' }} />
              <button type="button" onClick={refreshCaptcha} className="admin-btn secondary" style={{ marginTop: 8 }}>Refresh</button>
              {captchaError && <div style={{ color: '#ff6b6b', marginTop: 6 }}>{captchaError}</div>}
            </div>
          </div>
          {error && (
            <div style={{ color: '#ff6b6b', marginTop: '1rem', fontWeight: 'bold', fontSize: '1rem' }}>{error}</div>
          )}
          {successMessage && (
            <div style={{ color: '#1b5e20', marginTop: '1rem', fontWeight: '800', fontSize: '1rem', textAlign: 'center' }}>{successMessage}</div>
          )}
          <div style={{ display: 'flex', justifyContent: 'center', gap: '1.5rem', margin: '2rem 0 1rem 0' }}>
            <a href="#" style={{ color: '#fff', fontSize: '1.5rem', textShadow: '0 0 8px #1976d2' }}><i className="fab fa-facebook-f"></i></a>
            <a href="#" style={{ color: '#fff', fontSize: '1.5rem', textShadow: '0 0 8px #1976d2' }}><i className="fab fa-twitter"></i></a>
            <a href="#" style={{ color: '#fff', fontSize: '1.5rem', textShadow: '0 0 8px #1976d2' }}><i className="fab fa-google"></i></a>
          </div>
          <p style={{ marginTop: '1.5rem', fontSize: '1rem' }}>
            Don't have an account?{' '}
            <a href="#" style={{ color: '#2575fc', fontWeight: 'bold', textDecoration: 'underline' }} onClick={() => navigate('/admin/admin-signup')}>Sign Up</a>
          </p>
        </form>
      </fieldset>
    </section>
  );
};

export default CulturalEnthusiastLogin;
