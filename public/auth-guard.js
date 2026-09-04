/**
 * Universal Auth Guard & Access Control Utilities
 * Supports both Express Node.js Server Middleware and Client-Side JS Guards.
 */

// ============================================================================
// 1. EXPRESS SERVER-SIDE MIDDLEWARE
// ============================================================================

/**
 * Ensures the request is authenticated via session.
 */
function requireAuth(req, res, next) {
  const sessionUser = req.session?.user?.user || req.session?.user;
  if (!sessionUser || !sessionUser.id) {
    return res.status(401).json({ error: 'Unauthorized. Active session required.' });
  }
  next();
}

/**
 * Restricts access to Admin roles.
 */
function requireAdmin(req, res, next) {
  const user = req.session?.user?.user || req.session?.user;
  const role = String(user?.role || '').trim().toLowerCase();
  if (!['admin', 'super_admin', 'superadmin'].includes(role)) {
    return res.status(403).json({ error: 'Forbidden. Administrator privileges required.' });
  }
  next();
}

/**
 * Restricts access specifically to Admin or Super Admin roles.
 */
function requireAdminOrSuper(req, res, next) {
  const user = req.session?.user?.user || req.session?.user;
  const role = String(user?.role || '').trim().toLowerCase();
  if (!['admin', 'super_admin', 'superadmin'].includes(role)) {
    return res.status(403).json({ error: 'Forbidden. Administrator privileges required.' });
  }
  next();
}

/**
 * Restricts access to Managers or higher roles.
 */
function requireManager(req, res, next) {
  const user = req.session?.user?.user || req.session?.user;
  const role = String(user?.role || '').trim().toLowerCase();
  if (!['manager', 'admin', 'super_admin', 'superadmin'].includes(role)) {
    return res.status(403).json({ error: 'Forbidden. Manager privileges required.' });
  }
  next();
}

/**
 * Restricts access to Asset Managers or Admins.
 */
function requireAssetManager(req, res, next) {
  const user = req.session?.user?.user || req.session?.user;
  const role = String(user?.role || '').trim().toLowerCase();
  if (!['asset_manager', 'admin', 'super_admin', 'superadmin'].includes(role)) {
    return res.status(403).json({ error: 'Forbidden. Asset management privileges required.' });
  }
  next();
}

/**
 * Checks module-level access flag for Helpdesk.
 */
function requireHelpdeskAccess(req, res, next) {
  const user = req.session?.user?.user || req.session?.user;
  const role = String(user?.role || '').trim().toLowerCase();
  const isSuperOrAdmin = ['admin', 'super_admin', 'superadmin'].includes(role);

  if (isSuperOrAdmin || user?.access_helpdesk === 1 || user?.access_helpdesk === true) {
    return next();
  }
  return res.status(403).json({ error: 'Forbidden. Helpdesk module access disabled.' });
}

/**
 * Checks module-level access flag for Assets.
 */
function requireAssetAccess(req, res, next) {
  const user = req.session?.user?.user || req.session?.user;
  const role = String(user?.role || '').trim().toLowerCase();
  const isSuperOrAdmin = ['admin', 'super_admin', 'superadmin'].includes(role);

  if (isSuperOrAdmin || user?.access_assets === 1 || user?.access_assets === true) {
    return next();
  }
  return res.status(403).json({ error: 'Forbidden. Asset management module access disabled.' });
}

// ============================================================================
// 2. CLIENT-SIDE BROWSER UTILITIES
// ============================================================================

async function protectPage(allowedRoles = []) {
  try {
    const headers = { 'Accept': 'application/json' };
    const token = typeof localStorage !== 'undefined' ? (localStorage.getItem('token') || localStorage.getItem('jwt')) : null;
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch('/api/auth/me', {
      method: 'GET',
      headers: headers,
      credentials: 'same-origin'
    });

    if (response.status === 401 || response.status === 403) {
      throw new Error('Unauthorized or expired session');
    }

    if (!response.ok) {
      throw new Error(`Authentication check failed: ${response.status}`);
    }

    const user = await response.json();
    const userRole = String(user.role || '').toLowerCase();
    const normalizedAllowed = allowedRoles.map(r => String(r).toLowerCase());

    if (normalizedAllowed.length > 0 && !normalizedAllowed.includes(userRole)) {
      window.location.href = '/login.html';
      return null;
    }

    return user;
  } catch (error) {
    console.warn('Access denied. Redirecting to login:', error.message);
    if (typeof localStorage !== 'undefined') {
      localStorage.removeItem('token');
      localStorage.removeItem('jwt');
    }
    const currentPath = encodeURIComponent(window.location.pathname + window.location.search);
    window.location.href = `/login.html?redirect=${currentPath}`;
    return null;
  }
}

async function authFetch(url, options = {}) {
  const token = typeof localStorage !== 'undefined' ? (localStorage.getItem('token') || localStorage.getItem('jwt')) : null;
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {})
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(url, { ...options, headers, credentials: 'same-origin' });

  if (response.status === 401) {
    if (typeof localStorage !== 'undefined') {
      localStorage.removeItem('token');
      localStorage.removeItem('jwt');
    }
    const currentPath = encodeURIComponent(window.location.pathname + window.location.search);
    window.location.href = `/login.html?redirect=${currentPath}`;
    return null;
  }

  return response;
}

// Attach functions to the global window object if running in browser context
if (typeof window !== 'undefined') {
  window.protectPage = protectPage;
  window.authFetch = authFetch;
}

// Export CommonJS modules for server-side Express context
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    requireAuth,
    requireAdmin,
    requireAdminOrSuper,
    requireManager,
    requireAssetManager,
    requireHelpdeskAccess,
    requireAssetAccess,
    protectPage,
    authFetch
  };
}