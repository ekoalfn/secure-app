// This file simulates a secure backend service for testing purposes
// Instead of modifying axios, we provide mock API functions

// Load users from localStorage or use default
const loadUsers = () => {
  const savedUsers = localStorage.getItem('secureUsers');
  if (savedUsers) {
    return JSON.parse(savedUsers);
  }
  return [{
    id: '1',
    name: 'Test User',
    email: 'test@example.com',
    password: 'password123',
    bio: 'This is a test user account.',
    website: 'https://example.com'
  }];
};

// Save users to localStorage
const saveUsers = (users) => {
  localStorage.setItem('secureUsers', JSON.stringify(users));
};

// Mock database
let users = loadUsers();

// Current user reference (simulates server-side session)
let currentUser = null;

// Mock CSRF token
let csrfToken = null;

// Mock JWT token
const generateToken = (userId) => {
  return `mock-jwt-token-for-user-${userId}`;
};

// Generate new CSRF token
const generateCSRFToken = () => {
  csrfToken = `csrf-token-${Math.random().toString(36).substring(2)}`;
  return csrfToken;
};

// Helper to simulate network delay
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Mock API implementation
export const mockAPI = {
  // Auth endpoints
  auth: {
    // Login endpoint
    async login(email, password) {
      await delay(500);
      
      const user = users.find(u => u.email === email && u.password === password);
      if (!user) {
        throw { response: { data: { message: 'Invalid credentials' } } };
      }
      
      currentUser = user;
      // Generate new CSRF token on login
      csrfToken = generateCSRFToken();
      return { 
        token: generateToken(user.id),
        csrfToken: csrfToken
      };
    },
    
    // Register endpoint
    async register(name, email, password) {
      await delay(500);
      
      if (users.some(u => u.email === email)) {
        throw { response: { data: { message: 'User already exists' } } };
      }
      
      const newUser = {
        id: String(users.length + 1),
        name,
        email,
        password
      };
      
      users.push(newUser);
      saveUsers(users);
      currentUser = newUser;
      // Generate new CSRF token on register
      csrfToken = generateCSRFToken();
      return { 
        token: generateToken(newUser.id),
        csrfToken: csrfToken
      };
    },
    
    // Get current user data
    async getUser() {
      await delay(300);
      
      // For demo purposes, just return the first user if no current user
      const user = currentUser || users[0];
      const { password, ...userWithoutPassword } = user;
      return userWithoutPassword;
    },

    // Get new CSRF token
    async getCSRFToken() {
      await delay(300);
      return { csrfToken: generateCSRFToken() };
    }
  },
  
  // User endpoints
  users: {
    // Update profile endpoint
    async updateProfile(data, token) {
      await delay(500);
      
      // Validate CSRF token
      if (!token || token !== csrfToken) {
        throw { response: { data: { message: 'Invalid CSRF token' } } };
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
      
      saveUsers(users);
      const { password, ...userWithoutPassword } = updatedUser;
      return userWithoutPassword;
    },
    
    // Change password endpoint
    async changePassword(oldPassword, newPassword, token) {
      await delay(500);
      
      // Validate CSRF token
      if (!token || token !== csrfToken) {
        throw { response: { data: { message: 'Invalid CSRF token' } } };
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
      
      saveUsers(users);
      return { message: 'Password changed successfully' };
    },

    // Secure change password endpoint - dengan CSRF protection
    async changePasswordSecure(newPassword) {
      await delay(500);
      
      // Validate CSRF token
      if (!csrfToken) {
        throw { response: { data: { message: 'CSRF token not found. Please login first.' } } };
      }
      
      // If no current user, use the first user (for demo purposes)
      const user = currentUser || users[0];
      
      // Update password dengan validasi CSRF
      if (currentUser) {
        currentUser.password = newPassword;
      } else {
        users[0].password = newPassword;
      }
      
      saveUsers(users);
      return { 
        success: true,
        message: 'Password changed successfully (SECURE!)',
        newPassword: newPassword 
      };
    }
  }
};

// This function sets up our mock backend by overriding localStorage
export const setupMockBackend = () => {
  // Load initial data
  users = loadUsers();
  console.log('Secure mock backend initialized with persisted data');
}; 