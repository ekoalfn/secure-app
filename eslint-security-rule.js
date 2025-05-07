module.exports = {
  meta: {
    type: "suggestion",
    docs: {
      description: "Enforce safe usage of dangerouslySetInnerHTML",
      category: "Security",
      recommended: true,
    },
    messages: {
      unsafeDangerouslySetInnerHTML: "dangerouslySetInnerHTML used without proper sanitization. Use DOMPurify.sanitize or trusted types."
    }
  },
  create: function(context) {
    const safeUsagePatterns = [
      "DOMPurify.sanitize", 
      "createSanitizedContent", 
      "sanitizers.htmlSanitizer"
    ];

    return {
      JSXAttribute: function(node) {
        if (node.name.name === "dangerouslySetInnerHTML") {
          const value = node.value;
          
          // Check if it's an expression
          if (value && value.type === "JSXExpressionContainer") {
            const expression = value.expression;
            
            // If it's a direct object with __html property
            if (expression.type === "ObjectExpression") {
              const htmlProp = expression.properties.find(
                prop => prop.key.name === "__html" || (prop.key.value === "__html")
              );
              
              if (htmlProp && htmlProp.value) {
                // Check if it uses a sanitization function
                let isSafe = false;
                
                // Handle different expression types
                if (htmlProp.value.type === "CallExpression") {
                  const callee = htmlProp.value.callee;
                  
                  // Check if it's a member expression like DOMPurify.sanitize
                  if (callee.type === "MemberExpression") {
                    const calleeStr = context.getSourceCode().getText(callee);
                    isSafe = safeUsagePatterns.some(pattern => calleeStr.includes(pattern));
                  }
                }
                
                if (!isSafe) {
                  context.report({
                    node: node,
                    messageId: "unsafeDangerouslySetInnerHTML"
                  });
                }
              }
            }
          }
        }
      }
    };
  }
}; 