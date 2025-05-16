const express = require('express');
const cors = require('cors');
const path = require('path');

// Mock API and services
const mockServices = {
  auth: {
    login: (email, password) => {
      console.log(`Login attempt for ${email}`);
      return { user: { id: '1', name: 'Test User', email } };
    },
    register: (name, email, password) => {
      console.log(`Register: ${name}, ${email}`);
      return { user: { id: '1', name, email } };
    },
    getUser: () => {
      return { id: '1', name: 'Test User', email: 'test@example.com' };
    }
  },
  users: {
    updateProfile: (data, csrfToken) => {
      console.log(`Profile update with token: ${csrfToken}`, data);
      return {
        id: '1',
        name: 'Test User',
        email: data.email || 'test@example.com',
        bio: data.bio || 'Updated bio',
        website: data.website || 'https://example.com'
      };
    },
    changePassword: (oldPassword, newPassword, csrfToken) => {
      console.log(`Password change with token: ${csrfToken}`);
      console.log(`Password changed from ${oldPassword} to ${newPassword}`);
      return { success: true };
    }
  }
};

// CSRF tokens store
const csrfTokens = new Set(['valid-token']);

// Generate a random token
const generateRandomToken = () => {
  return Math.random().toString(36).substring(2, 15);
};

const app = express();
const port = 5100;

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:5000'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Log all requests
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  console.log('Body:', req.body);
  next();
});

// CSRF middleware
const csrfMiddleware = (req, res, next) => {
  // Skip CSRF check for GET, HEAD, OPTIONS
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  const csrfToken = req.body.csrfToken;
  
  if (!csrfToken || !csrfTokens.has(csrfToken)) {
    console.log('CSRF attack detected! Token:', csrfToken);
    return res.status(403).json({
      error: 'Invalid CSRF token',
      message: 'This request has been blocked to protect you from CSRF attacks'
    });
  }

  next();
};

// Auth endpoints
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await mockServices.auth.login(email, password);
    res.json(result);
  } catch (error) {
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const result = await mockServices.auth.register(name, email, password);
    res.json(result);
  } catch (error) {
    res.status(400).json({ message: 'Registration failed' });
  }
});

app.get('/api/users/me', async (req, res) => {
  try {
    const result = await mockServices.auth.getUser();
    res.json(result);
  } catch (error) {
    res.status(401).json({ message: 'Unauthorized' });
  }
});

// CSRF token endpoint
app.get('/api/auth/csrf-token', (req, res) => {
  const token = generateRandomToken();
  csrfTokens.add(token);
  console.log('Generated CSRF token:', token);
  res.json({ csrfToken: token });
});

// User endpoints with CSRF protection
app.put('/api/users/profile', csrfMiddleware, async (req, res) => {
  try {
    const { data, csrfToken } = req.body;
    const result = await mockServices.users.updateProfile(data, csrfToken);
    res.json(result);
  } catch (error) {
    res.status(400).json({ message: 'Update failed' });
  }
});

app.put('/api/users/change-password', csrfMiddleware, async (req, res) => {
  try {
    const { oldPassword, newPassword, csrfToken } = req.body;
    const result = await mockServices.users.changePassword(oldPassword, newPassword, csrfToken);
    res.json(result);
  } catch (error) {
    res.status(400).json({ message: 'Password change failed' });
  }
});

// New endpoints for CSRF simulation
app.post('/api/users/change-password', csrfMiddleware, async (req, res) => {
  try {
    const { oldPassword, newPassword, csrfToken } = req.body;
    console.log('POST change-password attempt with CSRF token:', csrfToken);
    
    // Validate CSRF token before processing
    if (!csrfToken || !csrfTokens.has(csrfToken)) {
      return res.status(403).json({
        error: 'Invalid CSRF token',
        message: 'This request was blocked by CSRF protection'
      });
    }
    
    const result = await mockServices.users.changePassword(oldPassword, newPassword, csrfToken);
    res.json(result);
  } catch (error) {
    res.status(400).json({ message: 'Password change failed' });
  }
});

app.post('/api/users/profile', csrfMiddleware, async (req, res) => {
  try {
    const { data, csrfToken } = req.body;
    console.log('POST profile update attempt with CSRF token:', csrfToken);
    
    // Validate CSRF token before processing
    if (!csrfToken || !csrfTokens.has(csrfToken)) {
      return res.status(403).json({
        error: 'Invalid CSRF token',
        message: 'This request was blocked by CSRF protection'
      });
    }
    
    const result = await mockServices.users.updateProfile(data, csrfToken);
    res.json(result);
  } catch (error) {
    res.status(400).json({ message: 'Update failed' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'Secure server is running' });
});

// Start server
app.listen(port, () => {
  console.log(`Secure server running at http://localhost:${port}`);
}); 