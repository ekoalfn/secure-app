/**
 * @fileoverview OWASP Security ESLint Plugin
 * @author Security Team
 */

"use strict";

// Export rules
module.exports = {
  rules: {
    "no-unsafe-dangerouslySetInnerHTML": require("./no-unsafe-dangerouslySetInnerHTML")
  },
  configs: {
    recommended: {
      rules: {
        "react-security/no-unsafe-dangerouslySetInnerHTML": "error"
      }
    }
  }
}; 