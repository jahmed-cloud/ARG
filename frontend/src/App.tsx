/**
 * Azure Resource Guardian - Main App Component
 * =============================================
 * Sets up:
 * - MUI ThemeProvider with dark/light mode switching
 * - Redux store
 * - React Router with protected routes
 * - Global notification provider
 */

import React from 'react';
import { Provider } from 'react-redux';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { SnackbarProvider } from 'notistack';
import { CssBaseline } from '@mui/material';

import { store } from './store/store';
import { ARGThemeProvider } from './theme/ThemeProvider';
import { AppLayout } from './components/common/AppLayout';
import { ProtectedRoute } from './components/common/ProtectedRoute';

// Pages
import { LoginPage } from './pages/LoginPage';
import { ResetPasswordPage } from './pages/ResetPasswordPage';
import { OAuthCallbackPage } from './pages/OAuthCallbackPage';
import { DashboardPage } from './pages/DashboardPage';
import { FindingsPage } from './pages/FindingsPage';
import { CostsPage } from './pages/CostsPage';
import { IdentityPage } from './pages/IdentityPage';
import { GovernancePage } from './pages/GovernancePage';
import { DriftPage } from './pages/DriftPage';
import { SecurityPage } from './pages/SecurityPage';
import { ReportsPage } from './pages/ReportsPage';
import { RemediationPage } from './pages/RemediationPage';
import { SubscriptionsPage } from './pages/SubscriptionsPage';
import { SettingsPage } from './pages/SettingsPage';
import { ScansPage } from './pages/ScansPage';
import { NotFoundPage } from './pages/NotFoundPage';

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
            </BrowserRouter>
          </SnackbarProvider>
      </ARGThemeProvider>
    </Provider>
  );
};

export default App;
