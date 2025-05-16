"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const axios_1 = __importDefault(require("axios"));
const csrfProtection_1 = require("../../security/csrfProtection");
describe('CSRF Protection Tests', () => {
    const baseURL = 'http://localhost:3000';
    beforeAll(() => {
        // Setup axios dengan base URL
        axios_1.default.defaults.baseURL = baseURL;
        // Setup CSRF protection
        csrfProtection_1.csrfProtection.setupAxiosInterceptors(axios_1.default);
    });
    test('Request tanpa CSRF token seharusnya ditolak', async () => {
        try {
            // Coba kirim request tanpa token
            await axios_1.default.post('/api/change-password', {
                newPassword: 'hackedpassword'
            }, {
                headers: {
                    'X-CSRF-Token': undefined
                }
            });
            fail('Request seharusnya ditolak');
        }
        catch (error) {
            expect(error.response.status).toBe(403);
            expect(error.response.data.error).toBe('CSRF validation failed');
        }
    });
    test('Request dengan CSRF token palsu seharusnya ditolak', async () => {
        try {
            await axios_1.default.post('/api/change-password', {
                newPassword: 'hackedpassword'
            }, {
                headers: {
                    'X-CSRF-Token': 'fake-token'
                }
            });
            fail('Request seharusnya ditolak');
        }
        catch (error) {
            expect(error.response.status).toBe(403);
            expect(error.response.data.error).toBe('CSRF validation failed');
        }
    });
    test('Request dengan CSRF token valid seharusnya diterima', async () => {
        // Dapatkan token yang valid
        const validToken = csrfProtection_1.csrfProtection.getToken();
        const response = await axios_1.default.post('/api/change-password', {
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
        const validToken = csrfProtection_1.csrfProtection.getToken();
        try {
            await axios_1.default.post('/api/change-password', {
                newPassword: 'hackedpassword'
            }, {
                headers: {
                    'X-CSRF-Token': validToken,
                    'Origin': 'http://evil-site.com'
                }
            });
            fail('Request seharusnya ditolak');
        }
        catch (error) {
            expect(error.response.status).toBe(403);
            expect(error.response.data.error).toBe('CSRF validation failed');
        }
    });
});
