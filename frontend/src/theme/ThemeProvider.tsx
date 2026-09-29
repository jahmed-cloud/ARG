/**
 * Azure Resource Guardian - Theme
 * ================================
 * Custom MUI theme with:
 * - ARG brand identity (midnight blue + electric cyan palette)
 * - Dark mode as default (fits the "operations center" use case)
 * - Light mode available via toggle
 * - Consistent typography scale
 * - Component overrides for cleaner data-dense UI
 */

import React, { createContext, useContext, useMemo, useState } from 'react';
import { ThemeProvider, createTheme, alpha } from '@mui/material/styles';
import type { PaletteMode } from '@mui/material';

// Brand palette
const BRAND = {
  navy:       '#101b17',   // Deepest background
  midnight:   '#111e19',   // App background (dark)
  slate:      '#192820',   // Card background (dark)
  border:     '#30423b',   // Subtle borders
  cyan:       '#b8d9ba',   // Primary brand accent
  cyanDark:   '#90bba0',   // Hover state for cyan
  electricBlue: '#789c87', // Secondary (familiar Azure blue)
  success:    '#00C853',
  warning:    '#FFB300',
  error:      '#F44336',
  critical:   '#D32F2F',   // Critical findings
  textPrimary: '#ebece3',
  textSecondary: '#a3b5ad',
};

interface ColorModeContext {
  mode: PaletteMode;
  toggleMode: () => void;
}

export const ColorModeContext = createContext<ColorModeContext>({
  mode: 'dark',
  toggleMode: () => {},
});

export const useColorMode = () => useContext(ColorModeContext);

const getTheme = (mode: PaletteMode) =>
  createTheme({
    palette: {
      mode,
      ...(mode === 'dark'
        ? {
            background: {
              default: BRAND.midnight,
              paper: BRAND.slate,
            },
            primary: {
              main: BRAND.cyan,
              dark: BRAND.cyanDark,
              contrastText: BRAND.navy,
            },
            secondary: {
              main: BRAND.electricBlue,
            },
            text: {
              primary: BRAND.textPrimary,
              secondary: BRAND.textSecondary,
            },
            divider: BRAND.border,
            error:   { main: BRAND.error },
            warning: { main: BRAND.warning },
            success: { main: BRAND.success },
            info:    { main: BRAND.cyan },
          }
        : {
            background: {
              default: '#F0F4F8',
              paper: '#FFFFFF',
            },
            primary: {
              main: '#365b47',   // Azure blue for light mode
              contrastText: '#FFFFFF',
            },
            secondary: {
              main: BRAND.electricBlue,
            },
          }),
    },

    typography: {
      fontFamily: '"Inter", "Segoe UI", -apple-system, sans-serif',
      h1: { fontSize: '2rem', fontWeight: 700, letterSpacing: '-0.02em' },
      h2: { fontSize: '1.75rem', fontWeight: 600, letterSpacing: '-0.015em' },
      h3: { fontSize: '1.5rem', fontWeight: 600, letterSpacing: '-0.01em' },
      h4: { fontSize: '1.25rem', fontWeight: 600 },
      h5: { fontSize: '1.125rem', fontWeight: 600 },
      h6: { fontSize: '1rem', fontWeight: 600 },
      body1: { fontSize: '0.9rem', lineHeight: 1.6 },
      body2: { fontSize: '0.8125rem', lineHeight: 1.5 },
      caption: { fontSize: '0.75rem', letterSpacing: '0.02em' },
      overline: {
        fontSize: '0.6875rem',
        fontWeight: 600,
        letterSpacing: '0.08em',
        textTransform: 'uppercase',
      },
    },

    shape: {
      borderRadius: 5,
    },

    components: {
      MuiCssBaseline: {
        styleOverrides: {
          ':focus-visible': { outline: '3px solid #b8d9ba', outlineOffset: 3 },
          '@media (prefers-reduced-motion: reduce)': {
            '*, *::before, *::after': { animationDuration: '0.01ms !important', transitionDuration: '0.01ms !important' },
          },
        },
      },
      MuiTableContainer: { styleOverrides: { root: { maxWidth: '100%', overflowX: 'auto' } } },
      MuiAppBar: {
        styleOverrides: {
          root: ({ theme }) => ({
            backgroundColor: theme.palette.mode === 'dark' ? BRAND.navy : '#FFFFFF',
            borderBottom: `1px solid ${
              theme.palette.mode === 'dark' ? BRAND.border : '#E0E0E0'
            }`,
            boxShadow: 'none',
          }),
        },
      },

      MuiDrawer: {
        styleOverrides: {
          paper: ({ theme }) => ({
            backgroundColor: theme.palette.mode === 'dark' ? BRAND.navy : '#F8FAFC',
            borderRight: `1px solid ${
              theme.palette.mode === 'dark' ? BRAND.border : '#E0E0E0'
            }`,
          }),
        },
      },

      MuiCard: {
        styleOverrides: {
          root: ({ theme }) => ({
            backgroundImage: 'none',
            boxShadow: 'none',
            border: `1px solid ${
              theme.palette.mode === 'dark' ? BRAND.border : '#E8EDF2'
            }`,
            transition: 'border-color 0.2s ease',
            '&:hover': {
              borderColor: theme.palette.mode === 'dark' ? '#34506C' : '#B7CADA',
            },
          }),
        },
      },

      MuiChip: {
        styleOverrides: {
          root: {
            fontWeight: 500,
            fontSize: '0.75rem',
          },
        },
      },

      MuiButton: {
        styleOverrides: {
          root: {
            textTransform: 'none',
            fontWeight: 600,
            borderRadius: 4,
            boxShadow: 'none',
            '&.Mui-disabled': { background: '#26372f', color: '#84998d', borderColor: '#3a4d40' },
            '&.Mui-focusVisible': { outline: '2px solid #dfe5d5', outlineOffset: 3 },
          },
          containedPrimary: ({ theme }) => ({
            background:
              theme.palette.mode === 'dark'
                ? BRAND.cyan
                : undefined,
            color: theme.palette.mode === 'dark' ? BRAND.navy : '#FFFFFF',
            '&:hover': {
              background:
                theme.palette.mode === 'dark'
                  ? BRAND.cyanDark
                  : undefined,
            },
          }),
        },
      },

      MuiLinearProgress: {
        styleOverrides: {
          root: ({ theme }) => ({
            borderRadius: 4,
            backgroundColor:
              theme.palette.mode === 'dark' ? BRAND.border : '#E0E0E0',
          }),
          bar: ({ theme }) => ({
            borderRadius: 4,
            background:
              theme.palette.mode === 'dark'
                ? `linear-gradient(90deg, ${BRAND.cyan}, ${BRAND.cyanDark})`
                : undefined,
          }),
        },
      },
    },
  });

export const ARGThemeProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [mode, setMode] = useState<PaletteMode>('dark');

  const colorMode = useMemo(
    () => ({
      mode,
      toggleMode: () => setMode((prev) => (prev === 'dark' ? 'light' : 'dark')),
    }),
    [mode]
  );

  const theme = useMemo(() => getTheme(mode), [mode]);

  return (
    <ColorModeContext.Provider value={colorMode}>
      <ThemeProvider theme={theme}>{children}</ThemeProvider>
    </ColorModeContext.Provider>
  );
};
