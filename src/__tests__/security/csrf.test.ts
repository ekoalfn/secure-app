import axios from 'axios';
import { csrfProtection } from '../../security/csrfProtection';

describe('CSRF Protection Tests', () => {
  const baseURL = 'http://localhost:3000';
  
  beforeAll(() => {
    // Setup axios dengan base URL
    axios.defaults.baseURL = baseURL;
    // Setup CSRF protection
    csrfProtection.setupAxiosInterceptors(axios);
  });

  test('Request tanpa CSRF token seharusnya ditolak', async () => {
    try {
      // Coba kirim request tanpa token
      await axios.post('/api/change-password', {
        newPassword: 'hackedpassword'
      }, {
        headers: {
          'X-CSRF-Token': undefined
        }
      });
      fail('Request seharusnya ditolak');
    } catch (error: any) {
      expect(error.response.status).toBe(403);
      expect(error.response.data.error).toBe('CSRF validation failed');
    }
  });

  test('Request dengan CSRF token palsu seharusnya ditolak', async () => {
    try {
      await axios.post('/api/change-password', {
        newPassword: 'hackedpassword'
      }, {
        headers: {
          'X-CSRF-Token': 'fake-token'
        }
      });
      fail('Request seharusnya ditolak');
    } catch (error: any) {
      expect(error.response.status).toBe(403);
      expect(error.response.data.error).toBe('CSRF validation failed');
    }
  });

  test('Request dengan CSRF token valid seharusnya diterima', async () => {
    // Dapatkan token yang valid
    const validToken = csrfProtection.getToken();

    const response = await axios.post('/api/change-password', {
      newPassword: 'newvalidpassword'
    }, {
      headers: {
        'X-CSRF-Token': validToken
      }
    });

    expect(response.status).toBe(200);
    expect(response.data.success).toBe(true);
  });

  test('Request dari origin yang tidak diizinkan seharusnya ditolak', async () => {
    const validToken = csrfProtection.getToken();

    try {
      await axios.post('/api/change-password', {
        newPassword: 'hackedpassword'
      }, {
        headers: {
          'X-CSRF-Token': validToken,
          'Origin': 'http://evil-site.com'
        }
      });
      fail('Request seharusnya ditolak');
    } catch (error: any) {
      expect(error.response.status).toBe(403);
      expect(error.response.data.error).toBe('CSRF validation failed');
    }
  });
}); 