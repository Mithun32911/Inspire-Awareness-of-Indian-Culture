import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { registerUser } from '../services/authService';

const AdminSignup = () => {
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
      setError(t('adminSignup.missing_fields', 'All fields are required.'));
      return;
    }

    if (formData.password !== formData.confirmPassword) {
      setError(t('adminSignup.passwords_no_match', 'Passwords do not match.'));
      return;
    }

    setLoading(true);
    setError('');

    try {
      const result = await registerUser(formData.email.trim(), formData.password.trim(), formData.name.trim(), 'admin');

      if (result && result.success) {
        setSuccess(result.message);
        setTimeout(() => {
          navigate('/admin/enthusiast-login');
        }, 2000);
      } else {
        setError(result ? result.message : t('adminSignup.register_failed', 'Registration failed.'));
      }
    } catch (err) {
      console.error('AdminSignup error:', err);
      setError('Registration failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="vh-100 gradient-custom" style={{ 
      minHeight: '200vh', 
      background: 'linear-gradient(to right, #e5dbbc)', 
      display: 'flex', 
      alignItems: 'center', 
      justifyContent: 'center',
      padding: '2rem 1rem'
    }}>
      <fieldset style={{
        maxWidth: '450px',
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
          <legend style={{ 
          fontSize: '2rem', 
          fontWeight: 'bold', 
          color: '#fff', 
          letterSpacing: '2px', 
          marginBottom: '1.5rem' 
        }}>
          {t('adminSignup.title', 'Admin Registration')}
        </legend>
        
        <form onSubmit={handleSubmit}>
          <p style={{ 
            color: '#fff', 
            fontWeight: 'bold', 
            fontSize: '1.1rem', 
            marginBottom: '2rem' 
          }}>
            {t('adminSignup.join_text', 'Join as an Admin to manage the heritage platform!')}
          </p>

          <input
            type="text"
            name="name"
            value={formData.name}
            onChange={handleChange}
            placeholder={t('adminSignup.name_placeholder', 'Full Name')}
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
            type="email"
            name="email"
            value={formData.email}
            onChange={handleChange}
            placeholder={t('adminSignup.email_placeholder', 'Email Address')}
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
            name="password"
            value={formData.password}
            onChange={handleChange}
            placeholder={t('adminSignup.password_placeholder', 'Password (min 6 characters)')}
            autoComplete="new-password"
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
            name="confirmPassword"
            value={formData.confirmPassword}
            onChange={handleChange}
            placeholder={t('adminSignup.confirm_password_placeholder', 'Confirm Password')}
            autoComplete="new-password"
            style={{
              width: '100%',
              padding: '0.8rem',
              marginBottom: '1.5rem',
              borderRadius: '0.5rem',
              border: '1px solid #fff',
              background: '#222',
              color: '#fff',
              fontSize: '1rem',
              fontWeight: 'bold',
              outline: 'none',
            }}
          />

          <button 
            type="submit" 
            disabled={loading}
            style={{
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
            }}
          >
            {loading ? t('adminSignup.creating_account', 'Creating Account...') : t('adminSignup.create_account', 'Create Admin Account')}
          </button>

          {error && (
            <div style={{ 
              color: '#ff6b6b', 
              marginTop: '1rem', 
              fontWeight: 'bold', 
              fontSize: '1rem',
              background: 'rgba(255,107,107,0.1)',
              padding: '0.8rem',
              borderRadius: '0.5rem',
              border: '1px solid #ff6b6b'
            }}>
              {error}
            </div>
          )}

          {success && (
            <div style={{ 
              color: '#4CAF50', 
              marginTop: '1rem', 
              fontWeight: 'bold', 
              fontSize: '1rem',
              background: 'rgba(76,175,80,0.1)',
              padding: '0.8rem',
              borderRadius: '0.5rem',
              border: '1px solid #4CAF50'
            }}>
              {success}
            </div>
          )}

          <div style={{ 
            display: 'flex', 
            justifyContent: 'center', 
            gap: '1.5rem', 
            margin: '2rem 0 1rem 0' 
          }}>
            <a href="#" style={{ 
              color: '#fff', 
              fontSize: '1.5rem', 
              textShadow: '0 0 8px #2575fc' 
            }}>
              <i className="fab fa-facebook-f"></i>
            </a>
            <a href="#" style={{ 
              color: '#fff', 
              fontSize: '1.5rem', 
              textShadow: '0 0 8px #2575fc' 
            }}>
              <i className="fab fa-twitter"></i>
            </a>
            <a href="#" style={{ 
              color: '#fff', 
              fontSize: '1.5rem', 
              textShadow: '0 0 8px #2575fc' 
            }}>
              <i className="fab fa-google"></i>
            </a>
          </div>

          <p style={{ marginTop: '1.5rem', fontSize: '1rem' }}>
            {t('adminSignup.already_have_account', 'Already have an account?')}{' '}
            <button
              type="button"
              onClick={() => navigate('/admin/enthusiast-login')}
              style={{ 
                color: '#2575fc', 
                fontWeight: 'bold', 
                textDecoration: 'underline',
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                fontSize: '1rem'
              }}
            >
              {t('adminSignup.login_here', 'Login Here')}
            </button>
          </p>
        </form>
      </fieldset>
    </section>
  );
};

export default AdminSignup;