import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import { Shield } from 'lucide-react';

function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);
    
    try {
      await login(username, password);
      navigate('/');
    } catch (err) {
      setError(err.message || 'Login failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: '100vh',
      width: '100vw',
      background: 'var(--bg-base)',
      margin: '-var(--space-xl)' // negate main content padding temporarily for full bleed
    }}>
      <div className="card" style={{ width: '400px', padding: 'var(--space-xl)', boxShadow: 'var(--shadow-md)' }}>
        
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: 'var(--space-xl)' }}>
          <div style={{ background: 'var(--accent-subtle)', padding: 'var(--space-md)', borderRadius: '50%', marginBottom: 'var(--space-md)' }}>
            <Shield color="var(--accent-primary)" size={48} />
          </div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: '600' }}>CyberTrace<span style={{ color: 'var(--accent-primary)' }}>-Graph</span></h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginTop: 'var(--space-sm)' }}>Sign in to access the SOC Dashboard</p>
        </div>

        {error && (
          <div style={{ background: 'rgba(239, 68, 68, 0.1)', color: 'var(--severity-critical)', padding: 'var(--space-sm) var(--space-md)', borderRadius: 'var(--radius-sm)', marginBottom: 'var(--space-md)', fontSize: '0.875rem' }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-md)' }}>
          <div>
            <label style={{ display: 'block', marginBottom: 'var(--space-xs)', fontSize: '0.875rem', color: 'var(--text-secondary)' }}>Username</label>
            <input 
              type="text" 
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              style={{ width: '100%', padding: '10px', background: 'var(--bg-elevated)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', outline: 'none' }}
              placeholder="admin or analyst"
              required
            />
          </div>
          <div>
            <label style={{ display: 'block', marginBottom: 'var(--space-xs)', fontSize: '0.875rem', color: 'var(--text-secondary)' }}>Password</label>
            <input 
              type="password" 
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={{ width: '100%', padding: '10px', background: 'var(--bg-elevated)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', outline: 'none' }}
              placeholder="••••••••"
              required
            />
          </div>
          <button 
            type="submit" 
            className="btn btn-primary" 
            style={{ justifyContent: 'center', padding: '12px', marginTop: 'var(--space-sm)' }}
            disabled={isSubmitting}
          >
            {isSubmitting ? 'Authenticating...' : 'Sign In'}
          </button>
        </form>
        
        <div style={{ marginTop: 'var(--space-lg)', textAlign: 'center', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          <p>Demo accounts:</p>
          <p><code>admin:admin</code> (Full Access)</p>
          <p><code>analyst:analyst</code> (Read Only)</p>
        </div>
      </div>
    </div>
  );
}

export default LoginPage;
