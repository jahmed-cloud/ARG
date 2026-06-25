/**
 * AboutSection — project info, author/contact, and links. Mirrors the
 * "About / Author" section of README.md — keep both in sync if either
 * changes.
 */
import React from 'react';
import { Box, Card, CardContent, Typography, Button, Stack, alpha } from '@mui/material';
import { GitHub, Email, Article, Map, Language } from '@mui/icons-material';

const ARG_VERSION = '1.0.0';

export const AboutSection: React.FC = () => {
  return (
    <Card sx={{ mb: 3 }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 0.5 }}>
          <Box
            sx={{
              width: 32,
              height: 32,
              borderRadius: 1,
              background: 'linear-gradient(135deg, #00D4FF 0%, #0066FF 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 15,
              fontWeight: 800,
              color: '#fff',
              fontFamily: 'monospace',
            }}
          >
            A
          </Box>
          <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
            Azure Resource Guardian
          </Typography>
          <Typography variant="caption" sx={{ color: alpha('#fff', 0.4) }}>
            v{ARG_VERSION}
          </Typography>
        </Box>
        <Typography variant="body2" sx={{ color: alpha('#fff', 0.6), mb: 2.5 }}>
          Discover. Govern. Optimize. A self-hosted Azure governance platform for resource
          discovery, security/cost findings, and Terraform drift detection.
        </Typography>

        <Typography variant="caption" sx={{ display: 'block', color: alpha('#fff', 0.4), mb: 1, textTransform: 'uppercase', letterSpacing: 0.5 }}>
          Built by
        </Typography>
        <Typography variant="body1" sx={{ mb: 2 }}>
          Junaid Ahmed
        </Typography>

        <Stack direction="row" spacing={1.5} flexWrap="wrap" useFlexGap>
          <Button
            size="small"
            variant="outlined"
            startIcon={<GitHub />}
            href="https://github.com/jahmed-cloud/ARG"
            target="_blank"
            rel="noopener noreferrer"
            sx={{ borderColor: alpha('#fff', 0.15), color: '#fff', textTransform: 'none' }}
          >
            GitHub Repository
          </Button>
          <Button
            size="small"
            variant="outlined"
            startIcon={<Article />}
            href="https://hub.docker.com/repositories/jahmed22"
            target="_blank"
            rel="noopener noreferrer"
            sx={{ borderColor: alpha('#fff', 0.15), color: '#fff', textTransform: 'none' }}
          >
            Docker Hub
          </Button>
          <Button
            size="small"
            variant="outlined"
            startIcon={<Map />}
            href="https://github.com/jahmed-cloud/ARG/blob/main/ROADMAP.md"
            target="_blank"
            rel="noopener noreferrer"
            sx={{ borderColor: alpha('#fff', 0.15), color: '#fff', textTransform: 'none' }}
          >
            Roadmap
          </Button>
          <Button
            size="small"
            variant="outlined"
            startIcon={<Language />}
            href="https://jahmed.cloud"
            target="_blank"
            rel="noopener noreferrer"
            sx={{ borderColor: alpha('#fff', 0.15), color: '#fff', textTransform: 'none' }}
          >
            jahmed.cloud
          </Button>
          <Button
            size="small"
            variant="outlined"
            startIcon={<Email />}
            href="mailto:iam@jahmed.cloud"
            sx={{ borderColor: alpha('#fff', 0.15), color: '#fff', textTransform: 'none' }}
          >
            iam@jahmed.cloud
          </Button>
        </Stack>

        <Typography variant="caption" sx={{ display: 'block', mt: 2.5, color: alpha('#fff', 0.3) }}>
          MIT Licensed · Contributions welcome — see{' '}
          <a
            href="https://github.com/jahmed-cloud/ARG/blob/main/CONTRIBUTING.md"
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: alpha('#00D4FF', 0.8) }}
          >
            CONTRIBUTING.md
          </a>
        </Typography>
      </CardContent>
    </Card>
  );
};
