/**
 * @fileoverview Rule to detect unsafe usage of dangerouslySetInnerHTML in React
 * @author Security Team
 */
"use strict";
//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------
/** @type {import('eslint').Rule.RuleModule} */
module.exports = {
    meta: {
        type: "suggestion",
        docs: {
            description: "Enforce safe usage of dangerouslySetInnerHTML",
            category: "Security",
            recommended: true,
        },
        fixable: null,
        schema: [],
        messages: {
            unsafeDangerouslySetInnerHTML: "dangerouslySetInnerHTML used without proper sanitization. Use DOMPurify.sanitize or trusted types."
        }
    },
    create: function (context) {
        const safeUsagePatterns = [
            "DOMPurify.sanitize",
            "createSanitizedContent",
            "sanitizers.htmlSanitizer",
            "createSafeHTML"
        ];
        //----------------------------------------------------------------------
        // Public
        //----------------------------------------------------------------------
        return {
            JSXAttribute: function (node) {
                if (node.name.name === "dangerouslySetInnerHTML") {
                    const value = node.value;
                    // Check if it's an expression
                    if (value && value.type === "JSXExpressionContainer") {
                        const expression = value.expression;
                        // If it's a direct object with __html property
                        if (expression.type === "ObjectExpression") {
                            const htmlProp = expression.properties.find(prop => prop.key.name === "__html" || (prop.key.value === "__html"));
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
                                else if (htmlProp.value.type === "MemberExpression") {
                                    // For member expressions like obj.sanitizedHTML
                                    const memberExprStr = context.getSourceCode().getText(htmlProp.value);
                                    isSafe = memberExprStr.includes("sanitized") ||
                                        memberExprStr.includes("Sanitized") ||
                                        memberExprStr.includes("trusted") ||
                                        memberExprStr.includes("Trusted");
                                }
                                else if (htmlProp.value.type === "Identifier") {
                                    // For variables, check the variable name for indicators of sanitization
                                    const identifierName = htmlProp.value.name;
                                    isSafe = identifierName.includes("sanitized") ||
                                        identifierName.includes("Sanitized") ||
                                        identifierName.includes("trusted") ||
                                        identifierName.includes("Trusted") ||
                                        identifierName.includes("safe") ||
                                        identifierName.includes("Safe");
                                }
                                if (!isSafe) {
                                    context.report({
                                        node: node,
                                        messageId: "unsafeDangerouslySetInnerHTML"
                                    });
                                }
                            }
                        }
                        else if (expression.type === "Identifier") {
                            // For variable assignments like dangerouslySetInnerHTML={unsafeVar}
                            const varName = expression.name;
                            const isSafe = varName.includes("sanitized") ||
                                varName.includes("Sanitized") ||
                                varName.includes("trusted") ||
                                varName.includes("Trusted") ||
                                varName.includes("safe") ||
                                varName.includes("Safe");
                            if (!isSafe) {
                                context.report({
                                    node: node,
                                    messageId: "unsafeDangerouslySetInnerHTML"
                                });
                            }
                        }
                        else {
                            // For other expressions, report as potentially unsafe
                            context.report({
                                node: node,
                                messageId: "unsafeDangerouslySetInnerHTML"
                            });
                        }
                    }
                }
            }
        };
    }
};
