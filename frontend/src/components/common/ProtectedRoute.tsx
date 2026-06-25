import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAppSelector } from '../../store/store';

interface Props {
  children: React.ReactNode;
  requiredRole?: string;
}

/**
 * ProtectedRoute — wraps routes that require authentication.
 *
 * Redirects unauthenticated users to /login, preserving the intended
 * destination in location state so we can redirect back after login.
 *
 * Optional requiredRole check: if the user doesn't have the role,
 * redirect away (currently falls back to /dashboard since no /403
 * route is registered yet — future enhancement).
 */
export function ProtectedRoute({ children, requiredRole }: Props) {
  const location = useLocation();
  const { accessToken, user, isAuthenticated } = useAppSelector((s) => s.auth);

  if (!accessToken || !isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (
    requiredRole &&
    user?.role !== requiredRole &&
    user?.role !== 'admin' &&
    user?.role !== 'super_admin'
  ) {
    return <Navigate to="/dashboard" replace />;
  }

  return <>{children}</>;
}
