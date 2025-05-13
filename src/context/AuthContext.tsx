import React, { createContext, useState, useEffect, ReactNode } from 'react';
import { mockAPI } from '../mockBackend';

// Define the shape of our context
interface AuthContextType {
  isAuthenticated: boolean;
  user: any | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (name: string, email: string, password: string) => Promise<void>;
  logout: () => void;
  updateProfile: (data: any) => Promise<void>;
  changePassword: (oldPassword: string, newPassword: string) => Promise<void>;
}

// Create context with a default value
export const AuthContext = createContext<AuthContextType>({
  isAuthenticated: false,
  user: null,
  loading: true,
  login: async () => {},
  register: async () => {},
  logout: () => {},
  updateProfile: async () => {},
  changePassword: async () => {},
});

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [user, setUser] = useState<any | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  // Get CSRF token helper function
  const getCsrfToken = (): string => {
    return document.cookie
      .split('; ')
      .find(row => row.startsWith('XSRF-TOKEN='))
      ?.split('=')[1] || '';
  };

  useEffect(() => {
    // Check for authentication status
    const checkAuthStatus = async () => {
      try {
        const userData = await mockAPI.auth.getUser();
        setUser(userData);
        setIsAuthenticated(true);
      } catch (err) {
        // If not authenticated or token invalid, reset state
        setUser(null);
        setIsAuthenticated(false);
      } finally {
        setLoading(false);
      }
    };

    checkAuthStatus();
  }, []);

  // Login user
  const login = async (email: string, password: string) => {
    try {
      console.log('Login attempt for:', email);
      const result = await mockAPI.auth.login(email, password);
      console.log('Login successful:', result);
      
      // Fetch user data
      const userData = await mockAPI.auth.getUser();
      console.log('User data retrieved:', userData);
      
      setUser(userData);
      setIsAuthenticated(true);
    } catch (err) {
      console.error('Login error:', err);
      throw err;
    }
  };

  // Register user
  const register = async (name: string, email: string, password: string) => {
    try {
      console.log('Registration attempt for:', email);
      const result = await mockAPI.auth.register(name, email, password);
      console.log('Registration successful:', result);
      
      // Fetch user data
      const userData = await mockAPI.auth.getUser();
      console.log('User data retrieved:', userData);
      
      setUser(userData);
      setIsAuthenticated(true);
    } catch (err) {
      console.error('Registration error:', err);
      throw err;
    }
  };

  // Logout user
  const logout = async () => {
    try {
      await mockAPI.auth.logout();
      
      // Reset state
      setUser(null);
      setIsAuthenticated(false);
    } catch (err) {
      console.error('Logout error:', err);
      // Even if there's an error, reset client-side state
      setUser(null);
      setIsAuthenticated(false);
    }
  };

  // Update profile
  const updateProfile = async (data: any) => {
    try {
      const csrfToken = getCsrfToken();
      const updatedUser = await mockAPI.users.updateProfile(data, csrfToken);
      setUser({ ...user, ...updatedUser });
    } catch (err) {
      throw err;
    }
  };

  // Change password
  const changePassword = async (oldPassword: string, newPassword: string) => {
    try {
      const csrfToken = getCsrfToken();
      await mockAPI.users.changePassword(oldPassword, newPassword, csrfToken);
    } catch (err) {
      throw err;
    }
  };

  return (
    <AuthContext.Provider value={{
      isAuthenticated,
      user,
      loading,
      login,
      register,
      logout,
      updateProfile,
      changePassword
    }}>
      {children}
    </AuthContext.Provider>
  );
}; 