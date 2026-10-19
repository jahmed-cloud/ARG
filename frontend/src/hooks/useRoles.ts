import { useAppSelector } from '../store/store';

/**
 * Roles that start scans and see tenant-wide data (Entra ID / identity): admins and the contributor group
 * (role "analyst"). Subscription owners and readers (viewer) and auditors do not - the API enforces the same
 * rule (backend/services/access.py TENANT_ROLES).
 */
export const OPERATOR_ROLES = ['super_admin', 'admin', 'analyst'];

export function useCanOperate(): boolean {
  const role = useAppSelector((s) => s.auth.user?.role);
  return !!role && OPERATOR_ROLES.includes(role);
}

/** ARG administrators (admin, super_admin) - e.g. the Estate page; the API enforces the same (require_admin). */
export const ADMIN_ROLES = ['super_admin', 'admin'];

export function useIsAdmin(): boolean {
  const role = useAppSelector((s) => s.auth.user?.role);
  return !!role && ADMIN_ROLES.includes(role);
}
