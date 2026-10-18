/**
 * Azure Resource Guardian - Redux Store
 * ======================================
 * RTK (Redux Toolkit) store with:
 * - authSlice: JWT tokens, user profile
 */

import { configureStore, createSlice, PayloadAction } from '@reduxjs/toolkit';
import type { TypedUseSelectorHook } from 'react-redux';
import { useDispatch, useSelector } from 'react-redux';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface User {
  id: string;
  email: string;
  username: string;
  fullName: string | null;
  role: string;
  mfaEnabled: boolean;
}

interface AuthState {
  user: User | null;
  accessToken: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
}

// ---------------------------------------------------------------------------
// Auth Slice
// ---------------------------------------------------------------------------

// `user` is a JSON object, unlike the plain-string tokens, so it needs
// explicit serialize/deserialize. A corrupted or stale blob in localStorage
// should never crash the app on load — fall back to null and let the user
// re-authenticate rather than throwing during store initialization.
function loadStoredUser(): User | null {
  try {
    const raw = localStorage.getItem('arg_user');
    return raw ? (JSON.parse(raw) as User) : null;
  } catch {
    return null;
  }
}

const initialAuthState: AuthState = {
  user: loadStoredUser(),
  accessToken: localStorage.getItem('arg_access_token'),
  refreshToken: localStorage.getItem('arg_refresh_token'),
  isAuthenticated: !!localStorage.getItem('arg_access_token'),
  isLoading: false,
};

const authSlice = createSlice({
  name: 'auth',
  initialState: initialAuthState,
  reducers: {
    loginSuccess: (
      state,
      action: PayloadAction<{
        user: User;
        accessToken: string;
        refreshToken: string;
      }>
    ) => {
      state.user = action.payload.user;
      state.accessToken = action.payload.accessToken;
      state.refreshToken = action.payload.refreshToken;
      state.isAuthenticated = true;
      state.isLoading = false;
      // Persist tokens AND user to localStorage — user was previously
      // omitted here, which silently dropped role/profile info (and broke
      // admin-only UI gates) on every page reload despite the token
      // surviving, since isAuthenticated derived from the token alone.
      localStorage.setItem('arg_access_token', action.payload.accessToken);
      localStorage.setItem('arg_refresh_token', action.payload.refreshToken);
      localStorage.setItem('arg_user', JSON.stringify(action.payload.user));
    },
    logout: (state) => {
      state.user = null;
      state.accessToken = null;
      state.refreshToken = null;
      state.isAuthenticated = false;
      localStorage.removeItem('arg_access_token');
      localStorage.removeItem('arg_refresh_token');
      localStorage.removeItem('arg_user');
    },
    setLoading: (state, action: PayloadAction<boolean>) => {
      state.isLoading = action.payload;
    },
    setUser: (state, action: PayloadAction<User>) => {
      state.user = action.payload;
      localStorage.setItem('arg_user', JSON.stringify(action.payload));
    },
  },
});

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

export const store = configureStore({
  reducer: {
    auth: authSlice.reducer,
  },
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;

// Typed hooks
export const useAppDispatch: () => AppDispatch = useDispatch;
export const useAppSelector: TypedUseSelectorHook<RootState> = useSelector;

// Actions
export const { loginSuccess, logout, setLoading, setUser } = authSlice.actions;
