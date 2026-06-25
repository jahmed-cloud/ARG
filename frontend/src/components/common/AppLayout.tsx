/**
 * AppLayout — the persistent shell wrapping all authenticated pages.
 *
 * Architecture:
 *   - Sidebar: fixed 240px, collapsible to 64px icon-only mode.
 *   - TopBar: full-width app bar with user menu and scan trigger.
 *   - Main content area: scrollable, fills remaining space.
 *
 * Why a fixed sidebar vs a drawer?
 *   Governance dashboards are information-dense. A persistent sidebar lets
 *   analysts navigate quickly without opening/closing a drawer on every jump.
 *   The collapsible icon-only mode reclaims space for wide data tables.
 */

import React, { useState, useEffect } from "react";
import {
  Box,
  Drawer,
  AppBar,
  Toolbar,
  Typography,
  IconButton,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Tooltip,
  Avatar,
  Menu,
  MenuItem,
  Divider,
  Button,
  useTheme,
  useMediaQuery,
  alpha,
} from "@mui/material";
import {
  Dashboard,
  SearchOutlined,
  AttachMoney,
  Security,
  Person,
  Policy,
  CompareArrows,
  Description,
  Build,
  Settings,
  ChevronLeft,
  ChevronRight,
  CloudQueue,
  BugReport,
  Logout,
  Notifications,
  PlayArrow,
  Menu as MenuIcon,
} from "@mui/icons-material";
import { useNavigate, useLocation, Outlet } from "react-router-dom";
import { useAppDispatch, useAppSelector, logout, setUser } from "../../store/store";
import { useApi } from "../../hooks/useApi";

const SIDEBAR_EXPANDED = 240;
const SIDEBAR_COLLAPSED = 64;

interface NavItem {
  label: string;
  path: string;
  icon: React.ReactNode;
  badge?: number;
}

const NAV_ITEMS: NavItem[] = [
  { label: "Dashboard", path: "/dashboard", icon: <Dashboard /> },
  { label: "Findings", path: "/findings", icon: <BugReport /> },
  { label: "Cost Savings", path: "/costs", icon: <AttachMoney /> },
  { label: "Identity", path: "/identity", icon: <Person /> },
  { label: "Governance", path: "/governance", icon: <Policy /> },
  { label: "Security", path: "/security", icon: <Security /> },
  { label: "Terraform Drift", path: "/drift", icon: <CompareArrows /> },
  { label: "Reports", path: "/reports", icon: <Description /> },
  { label: "Remediation", path: "/remediation", icon: <Build /> },
  { label: "Subscriptions", path: "/subscriptions", icon: <CloudQueue /> },
];

export function AppLayout() {
  const theme = useTheme();
  const navigate = useNavigate();
  const location = useLocation();
  const dispatch = useAppDispatch();
  const api = useApi();
  const [collapsed, setCollapsed] = useState(false);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const { user } = useAppSelector((s) => s.auth);

  // Below this width, the sidebar switches from a permanent column that
  // always reserves layout space to a temporary overlay drawer that's
  // closed by default and slides over the content — a permanent 240px
  // sidebar on a ~375-414px phone screen previously consumed roughly
  // 60% of the viewport with no way to hide it at all.
  const isMobile = useMediaQuery(theme.breakpoints.down("sm"));
  const [mobileOpen, setMobileOpen] = useState(false);

  // Refresh the user profile from the server on every app mount. The
  // localStorage copy (used for the very first paint, see store.ts
  // loadStoredUser) is a reasonable starting guess but can go stale —
  // e.g. an admin changes someone's role, or the token in localStorage
  // is old. This keeps role-gated UI (like the Settings tenant admin
  // section) accurate without requiring a full re-login.
  useEffect(() => {
    let cancelled = false;
    api
      .get("/auth/me")
      .then((data) => {
        if (cancelled) return;
        dispatch(
          setUser({
            id: data.id,
            email: data.email,
            username: data.username,
            fullName: data.full_name,
            role: data.role,
            mfaEnabled: data.mfa_enabled,
          })
        );
      })
      .catch(() => {
        // Token may be expired/invalid — ProtectedRoute + the API
        // client's own auth handling will redirect to /login as needed.
        // No action required here.
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname]);

  const sidebarWidth = isMobile ? SIDEBAR_EXPANDED : collapsed ? SIDEBAR_COLLAPSED : SIDEBAR_EXPANDED;

  const handleLogout = () => {
    dispatch(logout());
    navigate("/login");
  };

  return (
    <Box sx={{ display: "flex", minHeight: "100vh", bgcolor: "background.default" }}>
      {/* ── Sidebar ───────────────────────────────────────────────── */}
      <Drawer
        variant={isMobile ? "temporary" : "permanent"}
        open={isMobile ? mobileOpen : true}
        onClose={() => setMobileOpen(false)}
        ModalProps={{ keepMounted: true }}
        sx={{
          width: sidebarWidth,
          flexShrink: 0,
          "& .MuiDrawer-paper": {
            width: sidebarWidth,
            boxSizing: "border-box",
            bgcolor: "#0D1B2A",
            borderRight: `1px solid ${alpha("#00D4FF", 0.12)}`,
            transition: theme.transitions.create("width", {
              easing: theme.transitions.easing.sharp,
              duration: theme.transitions.duration.standard,
            }),
            overflowX: "hidden",
          },
        }}
      >
        {/* Logo */}
        <Box
          sx={{
            display: "flex",
            alignItems: "center",
            px: 2,
            py: 2.5,
            gap: 1.5,
            borderBottom: `1px solid ${alpha("#00D4FF", 0.1)}`,
            minHeight: 64,
          }}
        >
          <Box
            sx={{
              width: 32,
              height: 32,
              borderRadius: 1,
              background: "linear-gradient(135deg, #00D4FF 0%, #0066FF 100%)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              flexShrink: 0,
              fontSize: 16,
              fontWeight: 800,
              color: "#fff",
              fontFamily: "monospace",
            }}
          >
            A
          </Box>
          {!collapsed && (
            <Box>
              <Typography
                variant="subtitle2"
                sx={{
                  fontWeight: 700,
                  color: "#fff",
                  lineHeight: 1,
                  letterSpacing: "-0.02em",
                }}
              >
                ARG
              </Typography>
              <Typography
                variant="caption"
                sx={{ color: "#00D4FF", lineHeight: 1, display: "block" }}
              >
                Resource Guardian
              </Typography>
            </Box>
          )}
        </Box>

        {/* Nav items */}
        <List sx={{ pt: 1, px: 0.5, flex: 1 }}>
          {NAV_ITEMS.map((item) => {
            const active = location.pathname.startsWith(item.path);
            return (
              <ListItem key={item.path} disablePadding sx={{ mb: 0.25 }}>
                <Tooltip title={collapsed ? item.label : ""} placement="right">
                  <ListItemButton
                    onClick={() => navigate(item.path)}
                    sx={{
                      borderRadius: 1.5,
                      minHeight: 42,
                      px: collapsed ? 1.5 : 1.5,
                      bgcolor: active ? alpha("#00D4FF", 0.12) : "transparent",
                      "&:hover": {
                        bgcolor: alpha("#00D4FF", 0.08),
                      },
                      ...(active && {
                        "&::before": {
                          content: '""',
                          position: "absolute",
                          left: 0,
                          top: "20%",
                          height: "60%",
                          width: 3,
                          borderRadius: "0 2px 2px 0",
                          bgcolor: "#00D4FF",
                        },
                      }),
                    }}
                  >
                    <ListItemIcon
                      sx={{
                        minWidth: collapsed ? 0 : 36,
                        color: active ? "#00D4FF" : alpha("#fff", 0.6),
                        "& svg": { fontSize: 20 },
                      }}
                    >
                      {item.icon}
                    </ListItemIcon>
                    {!collapsed && (
                      <ListItemText
                        primary={item.label}
                        primaryTypographyProps={{
                          fontSize: 13,
                          fontWeight: active ? 600 : 400,
                          color: active ? "#fff" : alpha("#fff", 0.7),
                        }}
                      />
                    )}
                  </ListItemButton>
                </Tooltip>
              </ListItem>
            );
          })}
        </List>

        {/* Bottom nav */}
        <Box sx={{ p: 0.5, borderTop: `1px solid ${alpha("#00D4FF", 0.1)}` }}>
          <ListItem disablePadding sx={{ mb: 0.25 }}>
            <Tooltip title={collapsed ? "Settings" : ""} placement="right">
              <ListItemButton
                onClick={() => navigate("/settings")}
                sx={{ borderRadius: 1.5, minHeight: 42, px: 1.5 }}
              >
                <ListItemIcon
                  sx={{ minWidth: collapsed ? 0 : 36, color: alpha("#fff", 0.5), "& svg": { fontSize: 20 } }}
                >
                  <Settings />
                </ListItemIcon>
                {!collapsed && (
                  <ListItemText
                    primary="Settings"
                    primaryTypographyProps={{ fontSize: 13, color: alpha("#fff", 0.6) }}
                  />
                )}
              </ListItemButton>
            </Tooltip>
          </ListItem>

          {/* Collapse toggle — desktop only; meaningless for a temporary
              overlay drawer the user just explicitly opened to read
              full labels. */}
          {!isMobile && (
            <Box sx={{ display: "flex", justifyContent: collapsed ? "center" : "flex-end", px: 1, pb: 1 }}>
              <IconButton
                size="small"
                onClick={() => setCollapsed(!collapsed)}
                sx={{ color: alpha("#fff", 0.4), "&:hover": { color: "#00D4FF" } }}
              >
                {collapsed ? <ChevronRight fontSize="small" /> : <ChevronLeft fontSize="small" />}
              </IconButton>
            </Box>
          )}
        </Box>
      </Drawer>

      {/* ── Main area ─────────────────────────────────────────────── */}
      <Box
        component="main"
        sx={{
          flex: 1,
          display: "flex",
          flexDirection: "column",
          minWidth: 0,
          transition: theme.transitions.create("margin", {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.standard,
          }),
        }}
      >
        {/* TopBar */}
        <AppBar
          position="sticky"
          elevation={0}
          sx={{
            bgcolor: alpha("#0D1B2A", 0.95),
            backdropFilter: "blur(8px)",
            borderBottom: `1px solid ${alpha("#00D4FF", 0.1)}`,
            zIndex: theme.zIndex.drawer - 1,
          }}
        >
          <Toolbar sx={{ gap: { xs: 1, sm: 2 }, px: { xs: 1.5, sm: 3 } }}>
            {isMobile && (
              <IconButton
                size="small"
                edge="start"
                onClick={() => setMobileOpen(true)}
                sx={{ color: alpha("#fff", 0.7), mr: 0.5 }}
              >
                <MenuIcon fontSize="small" />
              </IconButton>
            )}

            {/* Page title injected via context in future — for now just brand */}
            <Typography
              variant="subtitle1"
              noWrap
              sx={{ color: alpha("#fff", 0.6), fontWeight: 400, flex: 1, fontSize: { xs: 14, sm: 16 } }}
            >
              {NAV_ITEMS.find((n) => location.pathname.startsWith(n.path))?.label ?? ""}
            </Typography>

            {/* Takes the user to the Scans page to start a scan there,
                where they can choose which subscription(s) to target —
                deliberately does NOT start a scan directly from here,
                since that would skip subscription selection entirely. */}
            <Button
              variant="contained"
              size="small"
              disableElevation
              onClick={() => navigate("/scans")}
              startIcon={isMobile ? undefined : <PlayArrow sx={{ fontSize: "16px !important" }} />}
              sx={{
                background: "linear-gradient(135deg, #00D4FF 0%, #0066FF 100%)",
                color: "#fff",
                fontWeight: 700,
                fontSize: 13,
                textTransform: "none",
                px: { xs: 1.25, sm: 2 },
                minWidth: { xs: 0, sm: "auto" },
                borderRadius: 1.5,
                boxShadow: "0 2px 8px rgba(0,212,255,0.25)",
                "&:hover": {
                  boxShadow: "0 4px 14px rgba(0,212,255,0.4)",
                  background: "linear-gradient(135deg, #00D4FF 0%, #0066FF 100%)",
                },
              }}
            >
              {isMobile ? <PlayArrow sx={{ fontSize: "18px !important" }} /> : "Start a Scan"}
            </Button>

            <IconButton size="small" sx={{ color: alpha("#fff", 0.6) }}>
              <Notifications fontSize="small" />
            </IconButton>

            {/* User avatar */}
            <IconButton
              size="small"
              onClick={(e) => setAnchorEl(e.currentTarget)}
            >
              <Avatar
                sx={{
                  width: 32,
                  height: 32,
                  fontSize: 13,
                  fontWeight: 700,
                  bgcolor: "primary.main",
                  background: "linear-gradient(135deg, #00D4FF 0%, #0066FF 100%)",
                }}
              >
                {(user?.email?.[0] ?? "U").toUpperCase()}
              </Avatar>
            </IconButton>

            <Menu
              anchorEl={anchorEl}
              open={Boolean(anchorEl)}
              onClose={() => setAnchorEl(null)}
              transformOrigin={{ horizontal: "right", vertical: "top" }}
              anchorOrigin={{ horizontal: "right", vertical: "bottom" }}
              PaperProps={{
                sx: { bgcolor: "#0D1B2A", border: `1px solid ${alpha("#00D4FF", 0.2)}`, minWidth: 180 },
              }}
            >
              <Box sx={{ px: 2, py: 1 }}>
                <Typography variant="body2" sx={{ fontWeight: 600, color: "#fff" }}>
                  {user?.email}
                </Typography>
                <Typography variant="caption" sx={{ color: alpha("#fff", 0.5) }}>
                  {user?.role}
                </Typography>
              </Box>
              <Divider sx={{ borderColor: alpha("#00D4FF", 0.1) }} />
              <MenuItem
                onClick={handleLogout}
                sx={{ color: alpha("#fff", 0.7), gap: 1.5, fontSize: 13 }}
              >
                <Logout fontSize="small" />
                Sign out
              </MenuItem>
            </Menu>
          </Toolbar>
        </AppBar>

        {/* Page content */}
        <Box sx={{ flex: 1, overflow: "auto", p: { xs: 1.5, sm: 3 } }}>
          <Outlet />
        </Box>
      </Box>
    </Box>
  );
}
