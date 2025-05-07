module.exports = {
  extends: [
    'react-app',
    'react-app/jest'
  ],
  plugins: [
    'react',
    'jsx-a11y',
    'import',
    'react-hooks'
  ],
  rules: {
    // Standard security rules
    'react/no-danger': 'warn',
    'react/no-find-dom-node': 'error',
    'react/no-invalid-html-attribute': 'error',
    'react/no-unsafe': 'error',
    'react/jsx-no-script-url': 'error',
    'react/jsx-no-target-blank': 'error',
    'react-hooks/rules-of-hooks': 'error',
    'react-hooks/exhaustive-deps': 'warn'
  },
  settings: {
    react: {
      version: 'detect'
    }
  }
}; 