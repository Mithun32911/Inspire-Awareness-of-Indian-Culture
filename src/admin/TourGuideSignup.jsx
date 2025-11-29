import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { registerUser } from '../services/authService';

const TourGuideSignup = () => {
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
      setError('All fields are required.');
      return;
    }

    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const result = await registerUser(formData.email.trim(), formData.password.trim(), formData.name.trim(), 'tour-guide');

      if (result && result.success) {
        setSuccess(result.message);
        setTimeout(() => {
          navigate('/admin/tour-guide-login');
        }, 2000);
      } else {
        setError(result ? result.message : 'Registration failed.');
      }
    } catch (err) {
      console.error('TourGuideSignup error:', err);
      setError('Registration failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="admin-container">
      <div className="admin-login-form">
        <h1>Tour Guide Registration</h1>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="name">Full Name</label>
            <input type="text" id="name" name="name" value={formData.name} onChange={handleChange} placeholder="Full Name" />
          </div>
          <div className="form-group">
            <label htmlFor="email">Email Address</label>
            <input type="email" id="email" name="email" value={formData.email} onChange={handleChange} placeholder="Email Address" autoComplete="username" />
          </div>
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input type="password" id="password" name="password" value={formData.password} onChange={handleChange} placeholder="Password (min 6 characters)" autoComplete="new-password" />
          </div>
          <div className="form-group">
            <label htmlFor="confirmPassword">Confirm Password</label>
            <input type="password" id="confirmPassword" name="confirmPassword" value={formData.confirmPassword} onChange={handleChange} placeholder="Confirm Password" autoComplete="new-password" />
          </div>

          <div className="form-actions" style={{ marginTop: '1rem', display: 'flex', justifyContent: 'center' }}>
            <button type="submit" className="admin-btn primary" disabled={loading} style={{ width: 240, maxWidth: '90%', margin: '0 auto', background: loading ? '#888' : '#1976d2', color: '#fff', border: 'none', padding: '0.6rem 1rem', borderRadius: 6 }}>{loading ? 'Creating Account...' : 'Create Account'}</button>
          </div>

          {error && <div className="error-box" style={{ marginTop: '1rem' }}>{error}</div>}
          {success && <div className="info-box" style={{ marginTop: '1rem' }}>{success}</div>}

          <div style={{ marginTop: '1rem' }}>
            <button type="button" onClick={() => navigate('/admin/tour-guide-login')} style={{ background: 'none', border: 'none', color: '#48D1CC', textDecoration: 'underline', cursor: 'pointer' }}>Already have an account? Login Here</button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default TourGuideSignup;