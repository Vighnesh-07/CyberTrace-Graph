import React, { createContext, useContext, useState, useEffect } from 'react';

const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check local storage for token
    const token = localStorage.getItem('auth_token');
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        payload.username = payload.username || payload.sub || 'admin';
        payload.role = payload.role || (payload.username === 'admin' ? 'ADMIN' : 'ANALYST');
        setUser(payload);
      } catch (e) {
        localStorage.removeItem('auth_token');
      }
    }
    setLoading(false);
  }, []);

  const login = async (username, password) => {
    try {
      const response = await fetch('http://localhost:8000/api/auth/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          username,
          password
        })
      });

      if (!response.ok) {
        throw new Error('Invalid credentials');
      }

      const data = await response.json();
      const token = data.access_token;
      
      // Parse the payload from the real JWT
      const payload = JSON.parse(atob(token.split('.')[1]));
      payload.username = username || payload.sub || 'admin';
      payload.role = username === 'admin' ? 'ADMIN' : 'ANALYST';
      
      localStorage.setItem('auth_token', token);
      setUser(payload);
      return payload;
    } catch (err) {
      throw err;
    }
  };

  const logout = () => {
    localStorage.removeItem('auth_token');
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, loading }}>
      {!loading && children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
