// This file simulates a secure backend service with security mitigations

import axios from 'axios';

interface User {
  id: string;
  name: string;
  email: string;
  password: string;
  bio?: string;
  website?: string;
}

// Mock database
let users: User[] = [
  {
    id: '1',
    name: 'Test User',
    email: 'test@example.com',
    password: 'password123',
    bio: 'This is a test user account.',
    website: 'https://example.com'
  }
];

// Current user reference (simulates server-side session)
let currentUser: User | null = null;

// Mock CSRF tokens store
const csrfTokens = new Set<string>();

// Generate a random token
const generateRandomToken = (): string => {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
};

// Helper to simulate network delay
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

// Direct implementation of backend functions - no HTTP calls
const mockServiceImplementations = {
  // Auth services
  auth: {
    // Login implementation
    async loginImpl(email: string, password: string) {
      await delay(300); // Simulate network delay
      
      const user = users.find(u => u.email === email);
      if (!user || user.password !== password) {
        throw new Error('Invalid credentials');
      }
      
      // Set current user (simulates session)
      currentUser = user;
      
      return {
        success: true,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          bio: user.bio,
          website: user.website
        }
      };
    },
    
    // Register implementation
    async registerImpl(name: string, email: string, password: string) {
      await delay(300);
      
      if (users.some(u => u.email === email)) {
        throw new Error('Email already in use');
      }
      
      const newUser: User = {
        id: (users.length + 1).toString(),
        name,
        email,
        password
      };
      
      users.push(newUser);
      currentUser = newUser;
      
      return {
        success: true,
        user: {
          id: newUser.id,
          name: newUser.name,
          email: newUser.email
        }
      };
    },
    
    // Get current user
    async getUserImpl() {
      await delay(200);
      
      if (!currentUser) {
        throw new Error('Not authenticated');
      }
      
      return {
        id: currentUser.id,
        name: currentUser.name,
        email: currentUser.email,
        bio: currentUser.bio,
        website: currentUser.website
      };
    },
    
    // Logout
    async logoutImpl() {
      await delay(200);
      currentUser = null;
      return { success: true };
    },
    
    // Get CSRF token
    async getCSRFTokenImpl() {
      await delay(100);
      const token = generateRandomToken();
      csrfTokens.add(token);
      return { csrfToken: token };
    }
  },
  
  // User services
  users: {
    // Update profile
    async updateProfileImpl(data: any, csrfToken: string) {
      await delay(300);
      
      if (!currentUser) {
        throw new Error('Not authenticated');
      }
      
      if (!csrfTokens.has(csrfToken)) {
        throw new Error('Invalid CSRF token');
      }
      
      // Update user data
      if (data.name) currentUser.name = data.name;
      if (data.bio) currentUser.bio = data.bio;
      if (data.website) currentUser.website = data.website;
      
      return {
        success: true,
        user: {
          id: currentUser.id,
          name: currentUser.name,
          email: currentUser.email,
          bio: currentUser.bio,
          website: currentUser.website
        }
      };
    },
    
    // Change password
    async changePasswordImpl(oldPassword: string, newPassword: string, csrfToken: string) {
      await delay(300);
      
      if (!currentUser) {
        throw new Error('Not authenticated');
      }
      
      if (!csrfTokens.has(csrfToken)) {
        throw new Error('Invalid CSRF token');
      }
      
      if (currentUser.password !== oldPassword) {
        throw new Error('Current password is incorrect');
      }
      
      currentUser.password = newPassword;
      
      return { success: true };
    }
  }
};

// Mock API for client usage
export const mockAPI = {
  // CSRF protection
  csrf: {
    // Generate a new CSRF token
    generateToken(): string {
      const token = generateRandomToken();
      csrfTokens.add(token);
      return token;
    },
    
    // Validate a CSRF token
    validateToken(token: string): boolean {
      return csrfTokens.has(token);
    }
  },
  
  // Auth endpoints
  auth: {
    // Login endpoint
    async login(email: string, password: string) {
      try {
        // Directly call the implementation instead of making an HTTP request
        return await mockServiceImplementations.auth.loginImpl(email, password);
      } catch (error) {
        throw error;
      }
    },
    
    // Register endpoint
    async register(name: string, email: string, password: string) {
      try {
        return await mockServiceImplementations.auth.registerImpl(name, email, password);
      } catch (error) {
        throw error;
      }
    },
    
    // Get current user data
    async getUser() {
      try {
        return await mockServiceImplementations.auth.getUserImpl();
      } catch (error) {
        throw error;
      }
    },
    
    // Logout - Clears session
    async logout() {
      try {
        return await mockServiceImplementations.auth.logoutImpl();
      } catch (error) {
        throw error;
      }
    },

    // Get CSRF token
    async getCSRFToken() {
      try {
        return await mockServiceImplementations.auth.getCSRFTokenImpl();
      } catch (error) {
        throw error;
      }
    }
  },
  
  // User endpoints
  users: {
    // Update profile endpoint
    async updateProfile(data: any, csrfToken: string) {
      try {
        return await mockServiceImplementations.users.updateProfileImpl(data, csrfToken);
      } catch (error) {
        throw error;
      }
    },
    
    // Change password endpoint
    async changePassword(oldPassword: string, newPassword: string, csrfToken: string) {
      try {
        return await mockServiceImplementations.users.changePasswordImpl(oldPassword, newPassword, csrfToken);
      } catch (error) {
        throw error;
      }
    }
  }
};

// Export the direct service implementations for server-side usage
export const mockServices = {
  auth: {
    login: mockServiceImplementations.auth.loginImpl,
    register: mockServiceImplementations.auth.registerImpl,
    getUser: mockServiceImplementations.auth.getUserImpl,
    logout: mockServiceImplementations.auth.logoutImpl,
    getCSRFToken: mockServiceImplementations.auth.getCSRFTokenImpl
  },
  users: {
    updateProfile: mockServiceImplementations.users.updateProfileImpl,
    changePassword: mockServiceImplementations.users.changePasswordImpl
  }
};

// This function sets up our mock backend
export const setupMockBackend = () => {
  // Generate initial CSRF token
  const initialToken = mockAPI.csrf.generateToken();
  document.cookie = `XSRF-TOKEN=${initialToken}; secure; samesite=strict`;
  
  console.log('Secure mock backend initialized with CSRF protection');
}; 