// This file simulates a secure backend service with security mitigations

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

// Mock API implementation with security features
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
    // Login endpoint - Sets HttpOnly cookies
    async login(email: string, password: string) {
      await delay(500);
      
      const user = users.find(u => u.email === email && u.password === password);
      if (!user) {
        throw { response: { data: { message: 'Invalid credentials' } } };
      }
      
      currentUser = user;
      
      // In a real server, we would set HttpOnly cookies
      // For this mock, we're simulating the behavior
      const authToken = generateRandomToken();
      const csrfToken = mockAPI.csrf.generateToken();
      
      // Set CSRF token cookie (accessible to JavaScript)
      document.cookie = `XSRF-TOKEN=${csrfToken}; secure; samesite=strict`;
      
      // HttpOnly cookie would be set by the server and not accessible to JS
      // We're just simulating this behavior
      console.log('Auth token set as HttpOnly cookie:', authToken);
      
      return { success: true };
    },
    
    // Register endpoint
    async register(name: string, email: string, password: string) {
      await delay(500);
      
      if (users.some(u => u.email === email)) {
        throw { response: { data: { message: 'User already exists' } } };
      }
      
      const newUser: User = {
        id: String(users.length + 1),
        name,
        email,
        password
      };
      
      users.push(newUser);
      currentUser = newUser;
      
      // In a real server, we would set HttpOnly cookies
      // For this mock, we're simulating the behavior
      const authToken = generateRandomToken();
      const csrfToken = mockAPI.csrf.generateToken();
      
      // Set CSRF token cookie (accessible to JavaScript)
      document.cookie = `XSRF-TOKEN=${csrfToken}; secure; samesite=strict`;
      
      // HttpOnly cookie would be set by the server and not accessible to JS
      // We're just simulating this behavior
      console.log('Auth token set as HttpOnly cookie:', authToken);
      
      return { success: true };
    },
    
    // Get current user data
    async getUser() {
      await delay(300);
      
      // For demo purposes, just return the first user if no current user
      const user = currentUser || users[0];
      const { password, ...userWithoutPassword } = user;
      return userWithoutPassword;
    },
    
    // Logout - Clears cookies
    async logout() {
      await delay(300);
      
      currentUser = null;
      
      // Clear CSRF token
      document.cookie = 'XSRF-TOKEN=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
      
      // In a real server, we would also clear the HttpOnly auth cookie
      console.log('Auth token cookie cleared');
      
      return { success: true };
    }
  },
  
  // User endpoints
  users: {
    // Update profile endpoint
    async updateProfile(data: { bio?: string; website?: string }, csrfToken: string) {
      await delay(500);
      
      // Validate CSRF token
      if (!mockAPI.csrf.validateToken(csrfToken)) {
        throw { response: { status: 403, data: { message: 'Invalid CSRF token' } } };
      }
      
      // If no current user, use the first user (for demo purposes)
      const user = currentUser || users[0];
      const updatedUser = {
        ...user,
        ...data
      };
      
      // Update the user in the "database"
      if (currentUser) {
        currentUser = updatedUser;
      } else {
        users[0] = updatedUser;
      }
      
      const { password, ...userWithoutPassword } = updatedUser;
      return userWithoutPassword;
    },
    
    // Change password endpoint
    async changePassword(oldPassword: string, newPassword: string, csrfToken: string) {
      await delay(500);
      
      // Validate CSRF token
      if (!mockAPI.csrf.validateToken(csrfToken)) {
        throw { response: { status: 403, data: { message: 'Invalid CSRF token' } } };
      }
      
      // If no current user, use the first user (for demo purposes)
      const user = currentUser || users[0];
      
      if (oldPassword !== user.password) {
        throw { response: { data: { message: 'Current password is incorrect' } } };
      }
      
      // Update password
      if (currentUser) {
        currentUser.password = newPassword;
      } else {
        users[0].password = newPassword;
      }
      
      return { message: 'Password changed successfully' };
    }
  }
};

// This function sets up our mock backend
export const setupMockBackend = () => {
  // Generate initial CSRF token
  const initialToken = mockAPI.csrf.generateToken();
  document.cookie = `XSRF-TOKEN=${initialToken}; secure; samesite=strict`;
  
  console.log('Secure mock backend initialized with CSRF protection');
}; 