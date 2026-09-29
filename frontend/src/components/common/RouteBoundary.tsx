import React, { Component, Suspense } from 'react';
import { Alert, Box, Button, LinearProgress } from '@mui/material';
import { useLocation } from 'react-router-dom';

class PageErrorBoundary extends Component<React.PropsWithChildren, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }

  render() {
    if (this.state.failed) {
      return <Alert severity="error" action={<Button color="inherit" onClick={() => window.location.reload()}>Reload</Button>}>
        This page could not load. Reload to get the latest version.
      </Alert>;
    }
    return this.props.children;
  }
}

export function RouteBoundary({ children }: React.PropsWithChildren) {
  const { pathname } = useLocation();
  return <PageErrorBoundary key={pathname}>
    <Suspense fallback={<Box role="status" aria-label="Loading page" sx={{ p: 3, width: '100%' }}><LinearProgress /></Box>}>
      {children}
    </Suspense>
  </PageErrorBoundary>;
}
