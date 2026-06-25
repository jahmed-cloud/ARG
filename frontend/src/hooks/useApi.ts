/**
 * useApi — shared authenticated fetch helper.
 *
 * Centralizes:
 *   - Authorization header injection from Redux state
 *   - Base URL resolution from VITE_API_URL
 *   - JSON parsing + error normalization
 *
 * Pages call `const api = useApi()` then `api.get('/findings')`,
 * `api.patch('/findings/123/status', {...})`, etc.
 */
import { useCallback } from 'react';
import { useAppSelector } from '../store/store';

const API_BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8000/api/v1';

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export function useApi() {
  const { accessToken } = useAppSelector((s) => s.auth);

  const request = useCallback(
    async (path: string, options: RequestInit = {}) => {
      const res = await fetch(`${API_BASE}${path}`, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
          ...(options.headers ?? {}),
        },
      });

      if (!res.ok) {
        let detail = `Request failed (${res.status})`;
        try {
          const body = await res.json();
          detail = body.detail ?? detail;
        } catch {
          // response wasn't JSON — keep generic message
        }
        throw new ApiError(detail, res.status);
      }

      const contentType = res.headers.get('content-type') ?? '';
      if (contentType.includes('application/json')) {
        return res.json();
      }
      return res.blob();
    },
    [accessToken]
  );

  return {
    get: (path: string) => request(path, { method: 'GET' }),
    post: (path: string, body?: unknown) =>
      request(path, { method: 'POST', body: body !== undefined ? JSON.stringify(body) : undefined }),
    patch: (path: string, body?: unknown) =>
      request(path, { method: 'PATCH', body: body !== undefined ? JSON.stringify(body) : undefined }),
    put: (path: string, body?: unknown) =>
      request(path, { method: 'PUT', body: body !== undefined ? JSON.stringify(body) : undefined }),
    del: (path: string) => request(path, { method: 'DELETE' }),
    baseUrl: API_BASE,
    accessToken,
  };
}
