/**
 * AboutSection — project info, author/contact, and links. Mirrors the
 * "About / Author" section of README.md — keep both in sync if either
 * changes. The links themselves live in config/author.ts.
 */
import React from 'react';
import { Box, Card, CardContent, Typography, Button, Stack, alpha } from '@mui/material';
import { GitHub, Email, Article, Map, Language, Favorite } from '@mui/icons-material';
import { AUTHOR, EXTERNAL_LINK, PROJECT_LINKS } from '../../config/author';

const ARG_VERSION = '1.0.0';

const linkButtonSx = { borderColor: alpha('#fff', 0.15), color: '#fff', textTransform: 'none' } as const;

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
          {AUTHOR.name}
        </Typography>

        <Stack direction="row" spacing={1.5} flexWrap="wrap" useFlexGap>
          <Button size="small" variant="outlined" startIcon={<GitHub />} href={PROJECT_LINKS.repository} {...EXTERNAL_LINK} sx={linkButtonSx}>
            GitHub Repository
          </Button>
          <Button size="small" variant="outlined" startIcon={<Article />} href={PROJECT_LINKS.dockerHub} {...EXTERNAL_LINK} sx={linkButtonSx}>
            Docker Hub
          </Button>
          <Button size="small" variant="outlined" startIcon={<Map />} href={PROJECT_LINKS.roadmap} {...EXTERNAL_LINK} sx={linkButtonSx}>
            Roadmap
          </Button>
          <Button size="small" variant="outlined" startIcon={<Language />} href={AUTHOR.website} {...EXTERNAL_LINK} sx={linkButtonSx}>
            {AUTHOR.websiteLabel}
          </Button>
          <Button size="small" variant="outlined" startIcon={<GitHub />} href={AUTHOR.github} {...EXTERNAL_LINK} sx={linkButtonSx}>
            GitHub Profile
          </Button>
          <Button size="small" variant="outlined" startIcon={<Email />} href={`mailto:${AUTHOR.email}`} sx={linkButtonSx}>
            {AUTHOR.email}
          </Button>
        </Stack>

        <Box sx={{ mt: 2.5, pt: 2, borderTop: `1px solid ${alpha('#b8d9ba', 0.12)}` }}>
          <Typography variant="caption" sx={{ display: 'block', color: alpha('#fff', 0.4), mb: 1, textTransform: 'uppercase', letterSpacing: 0.5 }}>
            Support this project
          </Typography>
          <Typography variant="body2" sx={{ color: alpha('#fff', 0.6), mb: 1.5 }}>
            ARG is free and open source. If it saves you time or money, you can support its development
            through GitHub Sponsors or by starring the repository.
          </Typography>
          <Button
            size="small"
            variant="outlined"
            startIcon={<Favorite />}
            href={AUTHOR.sponsor}
            {...EXTERNAL_LINK}
            sx={{ ...linkButtonSx, borderColor: alpha('#b8d9ba', 0.4), color: '#b8d9ba', '& .MuiButton-startIcon svg': { color: '#e8a0b4' } }}
          >
            Sponsor
          </Button>
        </Box>

        <Typography variant="caption" sx={{ display: 'block', mt: 2.5, color: alpha('#fff', 0.3) }}>
          MIT Licensed · Contributions welcome — see{' '}
          <a href={PROJECT_LINKS.contributing} {...EXTERNAL_LINK} style={{ color: alpha('#b8d9ba', 0.8) }}>
            CONTRIBUTING.md
          </a>
        </Typography>
      </CardContent>
    </Card>
  );
};
