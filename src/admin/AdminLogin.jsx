import React, { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { initiateForgotPassword } from '../services/authService';
import './Admin.css';

const AdminLogin = ({ onLogin }) => {
  const navigate = useNavigate();
  const { t } = useTranslation();
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
  const [captcha, setCaptcha] = useState('');
  const [captchaInput, setCaptchaInput] = useState('');
  const [captchaError, setCaptchaError] = useState('');

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
      setError(t('adminLogin.fill_registration_fields') || 'Please fill all registration fields.');
      return;
    }
    // Simple email validation
    const emailValid = /^\S+@\S+\.\S+$/.test(email);
    if (!emailValid) {
      setError(t('adminLogin.invalid_email') || 'Please enter a valid email address.');
      return;
    }
    if (password !== confirmPassword) {
      setError(t('adminLogin.passwords_no_match') || 'Passwords do not match.');
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

  useEffect(() => {
    const gen = () => Math.random().toString(36).slice(2, 8).toUpperCase();
    setCaptcha(gen());
  }, []);

  const handleLogin = (e) => {
    e.preventDefault();
    const saved = getSavedCredentials();
    const { identifier, password } = credentials;
    // clear previous error
    setError('');
    setCaptchaError('');
    // validate captcha
    if (!captchaInput || captchaInput.trim().toUpperCase() !== captcha) {
      setCaptchaError(t('adminLogin.invalid_captcha') || 'Invalid captcha');
      return;
    }
    if (!identifier || !password) {
      setError(t('adminLogin.missing_fields') || 'Please enter your email/username and password.');
      return;
    }
    if (!saved) {
      setError(t('adminLogin.no_admin') || 'No admin account found. Please register first.');
      return;
    }
    const matchesUsername = identifier === saved.username && password === saved.password;
    const matchesEmail = identifier === saved.email && password === saved.password;
    if (matchesUsername || matchesEmail) {
      setError('');
      // show success message above the login block
      setSuccessMessage(t('auth.login_success'));
      // proceed after a short delay so the user sees the message
      setTimeout(() => {
        setSuccessMessage('');
        if (typeof onLogin === 'function') onLogin();
      }, 800);
    } else {
      setError(t('adminLogin.invalid_credentials') || 'Invalid credentials. Please try again or register.');
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
        {t('nav.back')}
      </button>
      <div className="admin-login-form">
        {successMessage && (
          <div className="top-success-banner" role="status" aria-live="polite">
            <div className="auth-success">{successMessage}</div>
          </div>
        )}
        <h1>{isRegistering ? t('adminLogin.register') : t('adminLogin.login')}</h1>
        {isRegistering ? (
          <form onSubmit={handleRegister}>
            <div className="form-group">
              <label htmlFor="reg-email">{t('userLogin.email')}:</label>
              <input
                type="email"
                id="reg-email"
                name="email"
                value={registerData.email}
                onChange={handleRegisterInputChange}
                required
                placeholder={t('userLogin.email_placeholder')}
              />
            </div>
            <div className="form-group">
              <label htmlFor="reg-username">{t('adminLogin.email_or_username')}:</label>
              <input
                type="text"
                id="reg-username"
                name="username"
                value={registerData.username}
                onChange={handleRegisterInputChange}
                required
                placeholder={t('adminLogin.email_or_username_placeholder')}
              />
            </div>
            <div className="form-group">
              <label htmlFor="reg-password">{t('userLogin.password')}:</label>
              <input
                type="password"
                id="reg-password"
                name="password"
                value={registerData.password}
                onChange={handleRegisterInputChange}
                required
                placeholder={t('userLogin.password_placeholder')}
              />
            </div>
            <div className="form-group">
              <label htmlFor="reg-confirm">{t('adminLogin.confirm_password') || 'Confirm Password'}:</label>
              <input
                type="password"
                id="reg-confirm"
                name="confirmPassword"
                value={registerData.confirmPassword}
                onChange={handleRegisterInputChange}
                required
                placeholder={t('adminLogin.confirm_password_placeholder') || 're-enter password'}
              />
            </div>
            <div className="admin-btn-row">
              <button type="submit" className="admin-btn primary">{t('adminLogin.register') || 'Register'}</button>
              <button type="button" className="admin-btn" onClick={() => setIsRegistering(false)}>{t('adminLogin.back_to_login') || 'Back to Login'}</button>
            </div>
          </form>
        ) : (
          <form onSubmit={handleLogin}>
            <div className="form-group">
              <label htmlFor="identifier">{t('adminLogin.email_or_username')}:</label>
              <input
                type="text"
                id="identifier"
                name="identifier"
                value={credentials.identifier}
                onChange={handleInputChange}
                required
                placeholder={t('adminLogin.email_or_username_placeholder')}
              />
            </div>
            <div className="form-group">
              <label htmlFor="password">{t('userLogin.password')}:</label>
              <input
                type="password"
                id="password"
                name="password"
                value={credentials.password}
                onChange={handleInputChange}
                required
                placeholder={t('adminLogin.password_placeholder')}
              />
            </div>

            <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 12, justifyContent: 'center' }}>
              <div style={{ padding: 12, background: '#f3f3f3', borderRadius: 6, fontWeight: '700', letterSpacing: 3, fontSize: 20, userSelect: 'none' }}>{captcha}</div>
              <div style={{ display: 'flex', flexDirection: 'column', width: 220, maxWidth: '60%' }}>
                <input type="text" value={captchaInput} onChange={e => setCaptchaInput(e.target.value)} placeholder={t('Enter Captcha') || 'Enter captcha'} style={{ padding: '0.5rem', borderRadius: 6, border: '1px solid #ccc' }} />
                <button type="button" onClick={() => { const gen = () => Math.random().toString(36).slice(2, 8).toUpperCase(); setCaptcha(gen()); }} className="admin-btn secondary" style={{ marginTop: 8 }}>{t('Refresh') || 'Refresh'}</button>
                {captchaError && <div style={{ color: '#ff6b6b', marginTop: 6 }}>{captchaError}</div>}
              </div>
            </div>
            <div className="admin-btn-row">
              <button type="submit" className="admin-btn primary">{t('adminLogin.login')}</button>
              <button type="button" className="admin-btn" onClick={() => setIsRegistering(true)}>{t('adminLogin.register')}</button>
            </div>
            {error && <div className="auth-error">{error}</div>}
            <div style={{ marginTop: 12 }}>
              <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                <input type="checkbox" checked={rememberMe} onChange={e => setRememberMe(e.target.checked)} /> {t('userLogin.remember_me')}
              </label>
              {' | '}
              <a href="#" onClick={(e) => { e.preventDefault(); setShowForgot(s => !s); }}>{t('userLogin.forgot_password')}</a>
              {showForgot && (
                <div style={{ marginTop: 8, padding: 8, border: '1px solid #eee', borderRadius: 6 }}>
                  <input value={forgotEmail} onChange={e => setForgotEmail(e.target.value)} placeholder={t('userLogin.email_placeholder')} style={{ width: '100%', marginBottom: 8 }} />
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button className="admin-btn" onClick={() => { setForgotMessage(''); const res = initiateForgotPassword(forgotEmail.trim()); setForgotMessage(res.message); }}>{t('userLogin.send_otp')}</button>
                    <button className="admin-btn secondary" onClick={() => { setShowForgot(false); setForgotEmail(''); setForgotMessage(''); }}>{t('userLogin.cancel')}</button>
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
