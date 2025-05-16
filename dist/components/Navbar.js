"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const react_router_dom_1 = require("react-router-dom");
const AuthContext_1 = require("../context/AuthContext");
const Navbar = () => {
    const { isAuthenticated, logout } = (0, react_1.useContext)(AuthContext_1.AuthContext);
    const navigate = (0, react_router_dom_1.useNavigate)();
    const handleLogout = async () => {
        await logout();
        navigate('/login');
    };
    return ((0, jsx_runtime_1.jsx)("nav", { className: "navbar", children: (0, jsx_runtime_1.jsxs)("div", { className: "navbar-container", children: [(0, jsx_runtime_1.jsx)(react_router_dom_1.Link, { to: "/", className: "navbar-logo", children: "Secure App" }), (0, jsx_runtime_1.jsxs)("ul", { className: "navbar-menu", children: [(0, jsx_runtime_1.jsx)("li", { className: "navbar-item", children: (0, jsx_runtime_1.jsx)(react_router_dom_1.Link, { to: "/", className: "navbar-link", children: "Home" }) }), isAuthenticated ? ((0, jsx_runtime_1.jsxs)(jsx_runtime_1.Fragment, { children: [(0, jsx_runtime_1.jsx)("li", { className: "navbar-item", children: (0, jsx_runtime_1.jsx)(react_router_dom_1.Link, { to: "/profile", className: "navbar-link", children: "Profile" }) }), (0, jsx_runtime_1.jsx)("li", { className: "navbar-item", children: (0, jsx_runtime_1.jsx)(react_router_dom_1.Link, { to: "/change-password", className: "navbar-link", children: "Change Password" }) }), (0, jsx_runtime_1.jsx)("li", { className: "navbar-item", children: (0, jsx_runtime_1.jsx)("button", { onClick: handleLogout, className: "navbar-button", children: "Logout" }) })] })) : ((0, jsx_runtime_1.jsxs)(jsx_runtime_1.Fragment, { children: [(0, jsx_runtime_1.jsx)("li", { className: "navbar-item", children: (0, jsx_runtime_1.jsx)(react_router_dom_1.Link, { to: "/login", className: "navbar-link", children: "Login" }) }), (0, jsx_runtime_1.jsx)("li", { className: "navbar-item", children: (0, jsx_runtime_1.jsx)(react_router_dom_1.Link, { to: "/register", className: "navbar-link", children: "Register" }) })] }))] })] }) }));
};
exports.default = Navbar;
