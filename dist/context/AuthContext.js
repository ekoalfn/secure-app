"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthProvider = exports.AuthContext = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const mockBackend_1 = require("../mockBackend");
// Create context with a default value
exports.AuthContext = (0, react_1.createContext)({
    isAuthenticated: false,
    user: null,
    loading: true,
    login: async () => { },
    register: async () => { },
    logout: () => { },
    updateProfile: async () => { },
    changePassword: async () => { },
});
const AuthProvider = ({ children }) => {
    const [isAuthenticated, setIsAuthenticated] = (0, react_1.useState)(false);
    const [user, setUser] = (0, react_1.useState)(null);
    const [loading, setLoading] = (0, react_1.useState)(true);
    // Get CSRF token helper function
    const getCsrfToken = () => {
        var _a;
        return ((_a = document.cookie
            .split('; ')
            .find(row => row.startsWith('XSRF-TOKEN='))) === null || _a === void 0 ? void 0 : _a.split('=')[1]) || '';
    };
    (0, react_1.useEffect)(() => {
        // Check for authentication status
        const checkAuthStatus = async () => {
            try {
                const userData = await mockBackend_1.mockAPI.auth.getUser();
                setUser(userData);
                setIsAuthenticated(true);
            }
            catch (err) {
                // If not authenticated or token invalid, reset state
                setUser(null);
                setIsAuthenticated(false);
            }
            finally {
                setLoading(false);
            }
        };
        checkAuthStatus();
    }, []);
    // Login user
    const login = async (email, password) => {
        try {
            console.log('Login attempt for:', email);
            const result = await mockBackend_1.mockAPI.auth.login(email, password);
            console.log('Login successful:', result);
            // Fetch user data
            const userData = await mockBackend_1.mockAPI.auth.getUser();
            console.log('User data retrieved:', userData);
            setUser(userData);
            setIsAuthenticated(true);
        }
        catch (err) {
            console.error('Login error:', err);
            throw err;
        }
    };
    // Register user
    const register = async (name, email, password) => {
        try {
            console.log('Registration attempt for:', email);
            const result = await mockBackend_1.mockAPI.auth.register(name, email, password);
            console.log('Registration successful:', result);
            // Fetch user data
            const userData = await mockBackend_1.mockAPI.auth.getUser();
            console.log('User data retrieved:', userData);
            setUser(userData);
            setIsAuthenticated(true);
        }
        catch (err) {
            console.error('Registration error:', err);
            throw err;
        }
    };
    // Logout user
    const logout = async () => {
        try {
            await mockBackend_1.mockAPI.auth.logout();
            // Reset state
            setUser(null);
            setIsAuthenticated(false);
        }
        catch (err) {
            console.error('Logout error:', err);
            // Even if there's an error, reset client-side state
            setUser(null);
            setIsAuthenticated(false);
        }
    };
    // Update profile
    const updateProfile = async (data) => {
        try {
            const csrfToken = getCsrfToken();
            const updatedUser = await mockBackend_1.mockAPI.users.updateProfile(data, csrfToken);
            setUser({ ...user, ...updatedUser });
        }
        catch (err) {
            throw err;
        }
    };
    // Change password
    const changePassword = async (oldPassword, newPassword) => {
        try {
            const csrfToken = getCsrfToken();
            await mockBackend_1.mockAPI.users.changePassword(oldPassword, newPassword, csrfToken);
        }
        catch (err) {
            throw err;
        }
    };
    return ((0, jsx_runtime_1.jsx)(exports.AuthContext.Provider, { value: {
            isAuthenticated,
            user,
            loading,
            login,
            register,
            logout,
            updateProfile,
            changePassword
        }, children: children }));
};
exports.AuthProvider = AuthProvider;
