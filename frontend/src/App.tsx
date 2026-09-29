/**
 * Azure Resource Guardian - Main App Component
 * =============================================
 * Sets up:
 * - MUI ThemeProvider with dark/light mode switching
 * - Redux store
 * - React Router with protected routes
 * - Global notification provider
 */

import React, { lazy } from 'react';
import { RouteBoundary } from './components/common/RouteBoundary';
import { Provider } from 'react-redux';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { SnackbarProvider } from 'notistack';
import { CssBaseline } from '@mui/material';

import { store } from './store/store';
import { ARGThemeProvider } from './theme/ThemeProvider';
import { AppLayout } from './components/common/AppLayout';
import { ProtectedRoute } from './components/common/ProtectedRoute';

// Pages
const LoginPage = lazy(() => import('./pages/LoginPage').then(m => ({ default: m.LoginPage })));
const ResetPasswordPage = lazy(() => import('./pages/ResetPasswordPage').then(m => ({ default: m.ResetPasswordPage })));
const OAuthCallbackPage = lazy(() => import('./pages/OAuthCallbackPage').then(m => ({ default: m.OAuthCallbackPage })));
const DashboardPage = lazy(() => import('./pages/DashboardPage').then(m => ({ default: m.DashboardPage })));
const FindingsPage = lazy(() => import('./pages/FindingsPage').then(m => ({ default: m.FindingsPage })));
const CostsPage = lazy(() => import('./pages/CostsPage').then(m => ({ default: m.CostsPage })));
const IdentityPage = lazy(() => import('./pages/IdentityPage').then(m => ({ default: m.IdentityPage })));
const GovernancePage = lazy(() => import('./pages/GovernancePage').then(m => ({ default: m.GovernancePage })));
const DriftPage = lazy(() => import('./pages/DriftPage').then(m => ({ default: m.DriftPage })));
const SecurityPage = lazy(() => import('./pages/SecurityPage').then(m => ({ default: m.SecurityPage })));
const ReportsPage = lazy(() => import('./pages/ReportsPage').then(m => ({ default: m.ReportsPage })));
const RemediationPage = lazy(() => import('./pages/RemediationPage').then(m => ({ default: m.RemediationPage })));
const SubscriptionsPage = lazy(() => import('./pages/SubscriptionsPage').then(m => ({ default: m.SubscriptionsPage })));
const SettingsPage = lazy(() => import('./pages/SettingsPage').then(m => ({ default: m.SettingsPage })));
const ScansPage = lazy(() => import('./pages/ScansPage').then(m => ({ default: m.ScansPage })));
const NotFoundPage = lazy(() => import('./pages/NotFoundPage').then(m => ({ default: m.NotFoundPage })));

const App: React.FC = () => {
  return (
    <Provider store={store}>
      <ARGThemeProvider>
        <CssBaseline />
        <SnackbarProvider
          maxSnack={4}
          anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
          autoHideDuration={4000}
        >
            <BrowserRouter>
              <RouteBoundary>
              <Routes>
                {/* Public routes */}
                <Route path="/login" element={<LoginPage />} />
                <Route path="/reset-password" element={<ResetPasswordPage />} />
                <Route path="/oauth-callback" element={<OAuthCallbackPage />} />

                {/* Protected routes — require authentication */}
                <Route
                  element={
                    <ProtectedRoute>
                      <AppLayout />
                    </ProtectedRoute>
                  }
                >
                  <Route path="/" element={<Navigate to="/dashboard" replace />} />
                  <Route path="/dashboard" element={<DashboardPage />} />
                  <Route path="/findings" element={<FindingsPage />} />
                  <Route path="/costs" element={<CostsPage />} />
                  <Route path="/identity" element={<IdentityPage />} />
                  <Route path="/governance" element={<GovernancePage />} />
                  <Route path="/drift" element={<DriftPage />} />
                  <Route path="/security" element={<SecurityPage />} />
                  <Route path="/reports" element={<ReportsPage />} />
                  <Route path="/remediation" element={<RemediationPage />} />
                  <Route path="/subscriptions" element={<SubscriptionsPage />} />
                  <Route path="/scans" element={<ScansPage />} />
                  <Route path="/settings" element={<SettingsPage />} />
                </Route>

                {/* 404 */}
                <Route path="*" element={<NotFoundPage />} />
              </Routes>
              </RouteBoundary>
            </BrowserRouter>
          </SnackbarProvider>
      </ARGThemeProvider>
    </Provider>
  );
};

export default App;
