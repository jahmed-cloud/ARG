import React from 'react';
import { Box, Typography, Button, alpha } from '@mui/material';
import { useNavigate } from 'react-router-dom';

export const NotFoundPage: React.FC = () => {
  const navigate = useNavigate();
  return (
    <Box
      sx={{
        minHeight: '100vh',
        bgcolor: '#0A0F1E',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        textAlign: 'center',
        px: 2,
      }}
    >
      <Typography
        variant="h1"
        sx={{
          fontWeight: 800,
          fontSize: 120,
          background: 'linear-gradient(135deg, #00D4FF 0%, #0066FF 100%)',
          backgroundClip: 'text',
          WebkitBackgroundClip: 'text',
          color: 'transparent',
          lineHeight: 1,
        }}
      >
        404
      </Typography>
      <Typography variant="h6" sx={{ color: '#fff', mt: 2, mb: 1 }}>
        This resource doesn't exist
      </Typography>
      <Typography variant="body2" sx={{ color: alpha('#fff', 0.5), mb: 4 }}>
        Unlike orphaned Azure resources, this page can't be reclaimed — it was never provisioned.
      </Typography>
      <Button
        variant="contained"
        onClick={() => navigate('/dashboard')}
        sx={{ background: 'linear-gradient(135deg, #00D4FF 0%, #0066FF 100%)', fontWeight: 700 }}
      >
        Back to Dashboard
      </Button>
    </Box>
  );
};
