import React, { createContext, useContext, useState, useEffect } from 'react';

const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check local storage for mock token
    const token = localStorage.getItem('auth_token');
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        setUser(payload);
      } catch (e) {
        localStorage.removeItem('auth_token');
      }
    }
    setLoading(false);
  }, []);

  const login = async (username, password) => {
    // Mock authentication
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        if (username === 'admin' && password === 'admin') {
          const payload = {
            username: 'admin',
            role: 'ADMIN',
            exp: Math.floor(Date.now() / 1000) + (60 * 60)
          };
          const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
          const body = btoa(JSON.stringify(payload));
          const signature = 'mock_signature';
          const token = `${header}.${body}.${signature}`;
          
          localStorage.setItem('auth_token', token);
          setUser(payload);
          resolve(payload);
        } else if (username === 'analyst' && password === 'analyst') {
          const payload = {
            username: 'analyst',
            role: 'ANALYST',
            exp: Math.floor(Date.now() / 1000) + (60 * 60)
          };
          const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
          const body = btoa(JSON.stringify(payload));
          const signature = 'mock_signature';
          const token = `${header}.${body}.${signature}`;
          
          localStorage.setItem('auth_token', token);
          setUser(payload);
          resolve(payload);
        } else {
          reject(new Error('Invalid credentials'));
        }
      }, 500); // simulate network delay
    });
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
