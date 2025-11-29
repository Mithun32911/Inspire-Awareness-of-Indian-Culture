import React, { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
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
  const [captcha, setCaptcha] = useState('');
  const [captchaInput, setCaptchaInput] = useState('');
  const [captchaError, setCaptchaError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [showForgot, setShowForgot] = useState(false);
  const [forgotEmail, setForgotEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [forgotMessage, setForgotMessage] = useState('');
  const [redirectMessage, setRedirectMessage] = useState('');
  const navigate = useNavigate();
  const location = useLocation();
  const { t } = useTranslation();

  useEffect(() => {
    // Check if user was redirected from protected content
    const urlParams = new URLSearchParams(location.search);
    if (urlParams.get('redirect') === 'protected-content') {
      setRedirectMessage(t('userLogin.redirect_prompt'));
    }
  }, [location]);

  useEffect(() => {
    const remembered = getRememberedCredentials();
    if (remembered) {
      setUsername(remembered.email || '');
      setPassword(remembered.password || '');
      setRememberMe(true);
    }
    // generate initial captcha
    const gen = () => Math.random().toString(36).slice(2, 8).toUpperCase();
    setCaptcha(gen());
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setError(t('auth.please_enter_credentials'));
      return;
    }

    setLoading(true);
    setError('');

    try {
      // verify captcha before attempting login
      setCaptchaError('');
      if (!captchaInput || captchaInput.trim().toUpperCase() !== captcha) {
        setCaptchaError(t('auth.captcha_invalid', 'Invalid captcha'));
        setLoading(false);
        return;
      }

      const result = await authenticateUser(username.trim(), password.trim());

      if (result && result.success) {
        // Check if user role matches the login type
        if (result.user.role === 'user') {
          // Show success message briefly then navigate so user sees the confirmation
          setSuccessMessage(t('auth.login_success'));
          const previousPage = sessionStorage.getItem('previousPage');
          setTimeout(() => {
            setSuccessMessage('');
            if (rememberMe) rememberCredentials(username.trim(), password.trim());
            if (previousPage) {
              sessionStorage.removeItem('previousPage');
              navigate(previousPage);
            } else {
              navigate(result.user.dashboard);
            }
          }, 800);
        } else {
          setError(t('userLogin.invalid_role'));
        }
      } else {
        setError(result ? result.message : t('auth.login_failed'));
      }
      // rememberCredentials will be handled when we actually navigate (so it persists before leaving)
    } catch (err) {
      console.error('UserLogin error:', err);
      setError(t('auth.login_failed'));
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
        {t('nav.back')}
      </button>
      <div className="admin-login-form">
        {successMessage && (
          <div className="top-success-banner" aria-live="polite">
            <div className="auth-success">{successMessage}</div>
          </div>
        )}
        <h1>{t('userLogin.title')}</h1>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="email">{t('userLogin.email')}</label>
            <input
              type="email"
              id="email"
              value={username}
              onChange={e => setUsername(e.target.value)}
              placeholder={t('userLogin.email_placeholder')}
              autoComplete="username"
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">{t('userLogin.password')}</label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder={t('userLogin.password_placeholder')}
              autoComplete="current-password"
            />
          </div>

          <div className="form-actions" style={{ marginTop: '1rem', display: 'flex', justifyContent: 'center' }}>
            <button type="submit" className="admin-btn secondary" disabled={loading} style={{ width: 220, maxWidth: '90%', background: loading ? '#888' : '#1976d2', color: '#fff', border: 'none', padding: '0.6rem 1rem', borderRadius: 6 }}>{loading ? t('auth.logging_in') : t('auth.login')}</button>
          </div>

          <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 12, justifyContent: 'center' }}>
            <div style={{ padding: 12, background: '#f3f3f3', borderRadius: 6, fontWeight: '700', letterSpacing: 3, fontSize: 20, userSelect: 'none' }}>{captcha}</div>
            <div style={{ display: 'flex', flexDirection: 'column', width: 220, maxWidth: '60%' }}>
              <input type="text" value={captchaInput} onChange={e => setCaptchaInput(e.target.value)} placeholder={t('auth.captcha_placeholder', 'Enter captcha')} style={{ padding: '0.5rem', borderRadius: 6, border: '1px solid #ccc' }} />
              <button type="button" onClick={refreshCaptcha} className="admin-btn secondary" style={{ marginTop: 8 }}>Refresh</button>
              {captchaError && <div style={{ color: '#ff6b6b', marginTop: 6 }}>{captchaError}</div>}
            </div>
          </div>

          {redirectMessage && (
            <div className="info-box" style={{ marginTop: '1rem' }}>{redirectMessage}</div>
          )}
          {error && (
            <div className="auth-error">{error}</div>
          )}
          {/* success message shown at top of login card */}

          <div style={{ marginTop: '1rem' }}>
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
              <input type="checkbox" checked={rememberMe} onChange={e => setRememberMe(e.target.checked)} /> {t('userLogin.remember_me')}
            </label>
            <div style={{ marginTop: 8 }}>
              <a href="#" onClick={() => navigate('/admin/user-signup')}>{t('userLogin.no_account')}</a>
              {' | '}
              <a href="#" onClick={(e) => { e.preventDefault(); setShowForgot(s => !s); }}>{t('userLogin.forgot_password')}</a>
            </div>
            {showForgot && (
              <div style={{ marginTop: 12, padding: 12, border: '1px solid #eee', borderRadius: 8 }}>
                <h4>{t('userLogin.forgot_heading')}</h4>
                <input type="email" placeholder={t('userLogin.email_placeholder')} value={forgotEmail} onChange={e => setForgotEmail(e.target.value)} style={{ width: '100%', marginBottom: 8 }} />
                <div style={{ display: 'flex', gap: 8 }}>
                  <button onClick={startForgot} className="admin-btn">{t('userLogin.send_otp')}</button>
                  <button onClick={() => { setForgotEmail(''); setOtp(''); setNewPassword(''); setShowForgot(false); }} className="admin-btn secondary">{t('userLogin.cancel')}</button>
                </div>
                {forgotMessage && <div style={{ marginTop: 8 }}>{forgotMessage}</div>}
                <div style={{ marginTop: 12 }}>
                  <input type="text" placeholder={t('userLogin.enter_otp')} value={otp} onChange={e => setOtp(e.target.value)} style={{ width: '100%', marginBottom: 8 }} />
                  <input type="password" placeholder={t('userLogin.new_password')} value={newPassword} onChange={e => setNewPassword(e.target.value)} style={{ width: '100%', marginBottom: 8 }} />
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button onClick={submitReset} className="admin-btn">{t('userLogin.reset_password')}</button>
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