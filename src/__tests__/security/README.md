# Security Testing Framework

Berikut ini adalah pendekatan pengujian keamanan yang diimplementasikan dalam aplikasi ini, sesuai dengan OWASP Top 10 guidelines.

## Unit Tests

Unit test berfokus pada pengujian komponen keamanan secara individual untuk memastikan mereka berfungsi sesuai yang diharapkan.

### 1. Trusted Types Tests (`trustedTypes.test.ts`)

- Menguji sanitasi HTML untuk mencegah XSS
- Menguji validasi URL untuk mencegah serangan berbasis URL
- Menguji helper function `createSanitizedContent`
- Memastikan sanitasi yang tepat menghilangkan kode berbahaya

### 2. CSRF Protection Tests (`csrfProtection.test.ts`)

- Menguji pembuatan token CSRF
- Menguji rotasi token
- Memastikan token disertakan dalam header permintaan non-GET
- Memastikan token tidak disertakan dalam permintaan GET

### 3. Security Headers Tests (`securityHeaders.test.ts`)

- Menguji penerapan Content Security Policy (CSP)
- Memverifikasi X-XSS-Protection header
- Memverifikasi X-Content-Type-Options header
- Memastikan nonce dihasilkan dengan benar untuk CSP

## Integration Tests (`integration.test.tsx`)

Integration test memverifikasi bahwa komponen keamanan bekerja bersama dengan komponen React:

- Memastikan konten berbahaya disanitasi saat dirender dengan `dangerouslySetInnerHTML`
- Memastikan form menyertakan token CSRF
- Menguji berbagai payload XSS untuk memastikan semua disanitasi dengan benar

## Pengujian Manual

Selain pengujian otomatis, pengujian manual berikut sangat direkomendasikan:

1. Pengujian XSS
   - Memasukkan script dan payload HTML berbahaya ke input
   - Verifikasi bahwa payload tidak dieksekusi

2. Pengujian CSRF
   - Mencoba membuat permintaan tanpa token CSRF
   - Memastikan permintaan ditolak

3. Pengujian Security Headers
   - Memeriksa header respons menggunakan browser developer tools
   - Menggunakan OWASP ZAP untuk memverifikasi implementasi

## Tools Pengujian Keamanan

- OWASP ZAP: Untuk scanning kerentanan
- Lighthouse: Untuk audit keamanan web
- Burp Suite: Untuk pengujian penetrasi

## Perbaikan yang Diperlukan

1. Memperbaiki mock untuk localStorage dalam unit test CSRF
2. Menyempurnakan mock dan implementasi untuk integration test
3. Menyelesaikan masalah dengan dependensi dalam App.test.tsx

## Cara Menjalankan Test

```bash
# Menjalankan semua test
npm test

# Menjalankan test yang gagal saja
npm test -- --watchAll=false --onlyFailures

# Menjalankan test keamanan saja
npm test -- security
``` 