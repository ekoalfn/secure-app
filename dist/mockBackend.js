"use strict";
// This file simulates a secure backend service with security mitigations
Object.defineProperty(exports, "__esModule", { value: true });
exports.setupMockBackend = exports.mockServices = exports.mockAPI = void 0;
// Mock database
let users = [
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
let currentUser = null;
// Mock CSRF tokens store
const csrfTokens = new Set();
// Generate a random token
const generateRandomToken = () => {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
};
// Helper to simulate network delay
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));
// Direct implementation of backend functions - no HTTP calls
const mockServiceImplementations = {
    // Auth services
    auth: {
        // Login implementation
        async loginImpl(email, password) {
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
        async registerImpl(name, email, password) {
            await delay(300);
            if (users.some(u => u.email === email)) {
                throw new Error('Email already in use');
            }
            const newUser = {
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
        async updateProfileImpl(data, csrfToken) {
            await delay(300);
            if (!currentUser) {
                throw new Error('Not authenticated');
            }
            if (!csrfTokens.has(csrfToken)) {
                throw new Error('Invalid CSRF token');
            }
            // Update user data
            if (data.name)
                currentUser.name = data.name;
            if (data.bio)
                currentUser.bio = data.bio;
            if (data.website)
                currentUser.website = data.website;
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
        async changePasswordImpl(oldPassword, newPassword, csrfToken) {
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
exports.mockAPI = {
    // CSRF protection
    csrf: {
        // Generate a new CSRF token
        generateToken() {
            const token = generateRandomToken();
            csrfTokens.add(token);
            return token;
        },
        // Validate a CSRF token
        validateToken(token) {
            return csrfTokens.has(token);
        }
    },
    // Auth endpoints
    auth: {
        // Login endpoint
        async login(email, password) {
            try {
                // Directly call the implementation instead of making an HTTP request
                return await mockServiceImplementations.auth.loginImpl(email, password);
            }
            catch (error) {
                throw error;
            }
        },
        // Register endpoint
        async register(name, email, password) {
            try {
                return await mockServiceImplementations.auth.registerImpl(name, email, password);
            }
            catch (error) {
                throw error;
            }
        },
        // Get current user data
        async getUser() {
            try {
                return await mockServiceImplementations.auth.getUserImpl();
            }
            catch (error) {
                throw error;
            }
        },
        // Logout - Clears session
        async logout() {
            try {
                return await mockServiceImplementations.auth.logoutImpl();
            }
            catch (error) {
                throw error;
            }
        },
        // Get CSRF token
        async getCSRFToken() {
            try {
                return await mockServiceImplementations.auth.getCSRFTokenImpl();
            }
            catch (error) {
                throw error;
            }
        }
    },
    // User endpoints
    users: {
        // Update profile endpoint
        async updateProfile(data, csrfToken) {
            try {
                return await mockServiceImplementations.users.updateProfileImpl(data, csrfToken);
            }
            catch (error) {
                throw error;
            }
        },
        // Change password endpoint
        async changePassword(oldPassword, newPassword, csrfToken) {
            try {
                return await mockServiceImplementations.users.changePasswordImpl(oldPassword, newPassword, csrfToken);
            }
            catch (error) {
                throw error;
            }
        }
    }
};
// Export the direct service implementations for server-side usage
exports.mockServices = {
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
const setupMockBackend = () => {
    // Generate initial CSRF token
    const initialToken = exports.mockAPI.csrf.generateToken();
    document.cookie = `XSRF-TOKEN=${initialToken}; secure; samesite=strict`;
    console.log('Secure mock backend initialized with CSRF protection');
};
exports.setupMockBackend = setupMockBackend;
