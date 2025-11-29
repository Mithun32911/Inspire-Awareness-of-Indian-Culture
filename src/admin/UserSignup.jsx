import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { registerUser } from '../services/authService';

const UserSignup = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
    confirmPassword: ''
  });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { t } = useTranslation();

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
    // Clear errors when user starts typing
    if (error) setError('');
    if (success) setSuccess('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!formData.name.trim() || !formData.email.trim() || !formData.password.trim() || !formData.confirmPassword.trim()) {
      setError(t('userSignup.missing_fields', 'All fields are required.'));
      return;
    }

    if (formData.password !== formData.confirmPassword) {
      setError(t('userSignup.passwords_no_match', 'Passwords do not match.'));
      return;
    }

    setLoading(true);
    setError('');

    try {
      const result = await registerUser(formData.email.trim(), formData.password.trim(), formData.name.trim(), 'user');
      
      if (result && result.success) {
        setSuccess(result.message || t('userSignup.success', 'Account created successfully.'));
        setTimeout(() => {
          navigate('/admin/user-login');
        }, 2000);
      } else {
        setError(result.message);
      }
    } catch {
      setError(t('userSignup.register_failed', 'Registration failed. Please try again.'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="admin-container">
      <div className="admin-login-form">
        <h1>{t('userSignup.title', 'User Registration')}</h1>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="name">{t('userSignup.name_label', 'Full Name')}</label>
            <input type="text" id="name" name="name" value={formData.name} onChange={handleChange} placeholder={t('userSignup.name_placeholder', 'Full Name')} />
          </div>
          <div className="form-group">
            <label htmlFor="email">{t('userSignup.email_label', 'Email Address')}</label>
            <input type="email" id="email" name="email" value={formData.email} onChange={handleChange} placeholder={t('userSignup.email_placeholder', 'Email Address')} autoComplete="username" />
          </div>
          <div className="form-group">
            <label htmlFor="password">{t('userSignup.password_label', 'Password')}</label>
            <input type="password" id="password" name="password" value={formData.password} onChange={handleChange} placeholder={t('userSignup.password_placeholder', 'Password (min 6 characters)')} autoComplete="new-password" />
          </div>
          <div className="form-group">
            <label htmlFor="confirmPassword">{t('userSignup.confirm_password_label', 'Confirm Password')}</label>
            <input type="password" id="confirmPassword" name="confirmPassword" value={formData.confirmPassword} onChange={handleChange} placeholder={t('userSignup.confirm_password_placeholder', 'Confirm Password')} autoComplete="new-password" />
          </div>

          <div className="form-actions" style={{ marginTop: '1rem', display: 'flex', justifyContent: 'center' }}>
            <button type="submit" className="admin-btn primary" disabled={loading} style={{ width: 240, maxWidth: '90%', margin: '0 auto', background: loading ? '#888' : '#1976d2', color: '#fff', border: 'none', padding: '0.6rem 1rem', borderRadius: 6 }}>{loading ? t('userSignup.creating_account', 'Creating Account...') : t('userSignup.create_account', 'Create Account')}</button>
          </div>

          {error && <div className="error-box" style={{ marginTop: '1rem' }}>{error}</div>}
          {success && <div className="info-box" style={{ marginTop: '1rem' }}>{success}</div>}

          <div style={{ marginTop: '1rem' }}>
            <button type="button" onClick={() => navigate('/admin/user-login')} style={{ background: 'none', border: 'none', color: '#48D1CC', textDecoration: 'underline', cursor: 'pointer' }}>{t('userSignup.already_have_account', 'Already have an account? Login Here')}</button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default UserSignup;