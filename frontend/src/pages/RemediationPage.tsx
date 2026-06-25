/**
 * RemediationPage — generate remediation checklists and track staged tasks.
 *
 * Matches backend/api/routes/remediation.py:
 *   POST /remediation/generate-scripts { finding_ids, script_type: 'cli'|'powershell'|'terraform' }
 *     -> streams a .sh/.ps1/.tf checklist file
 *   GET  /remediation/tasks -> staged remediation tasks (approval/execution lifecycle)
 *
 * Note: the downloaded file is a remediation checklist built from each
 * finding's remediation_steps guidance, not an executable script —
 * the schema doesn't persist per-finding executable commands, only
 * freeform guidance text. The UI copy below reflects that honestly
 * rather than implying one-click automation that doesn't exist yet.
 */
import React, { useEffect, useState, useCallback } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  ToggleButtonGroup,
  ToggleButton,
  Button,
  TextField,
  Table,
  TableContainer,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  Chip,
  Alert,
  Tooltip,
  IconButton,
  Pagination,
  Checkbox,
  FormControlLabel,
  Divider,
  alpha,
} from '@mui/material';
import { Download, Terminal, CheckCircle, Undo, FilterAltOff } from '@mui/icons-material';
import { useApi, ApiError } from '../hooks/useApi';
import { useSnackbar } from 'notistack';

const SCRIPT_TYPES = [
  { value: 'cli', label: 'Azure CLI (.sh)' },
  { value: 'powershell', label: 'PowerShell (.ps1)' },
  { value: 'terraform', label: 'Terraform (.tf)' },
];

const SCRIPT_EXTENSIONS: Record<string, string> = {
  cli: 'sh',
  powershell: 'ps1',
  terraform: 'tf',
};

const STATUS_COLORS: Record<string, string> = {
  pending: '#9E9E9E',
  approved: '#2196F3',
  running: '#00D4FF',
  completed: '#4CAF50',
  failed: '#F44336',
  rejected: '#FF9800',
};

interface RemediationTaskItem {
  id: string;
  finding_id: string;
  finding_title: string | null;
  status: string;
  execution_method: string;
  notes: string | null;
  scheduled_at: string | null;
  executed_at: string | null;
  completed_at: string | null;
}

interface FindingWithRemediation {
  id: string;
  title: string;
  severity: string;
  status: string;
  category: string;
  resource_name: string | null;
  remediation_steps: string | null;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#F44336',
  high: '#FF9800',
  medium: '#FFC107',
  low: '#2196F3',
  info: '#9E9E9E',
};

export const RemediationPage: React.FC = () => {
  const api = useApi();
  const { enqueueSnackbar } = useSnackbar();

  const [scriptType, setScriptType] = useState('cli');
  const [selectedFindingIds, setSelectedFindingIds] = useState<Set<string>>(new Set());
  const [generating, setGenerating] = useState(false);
  const [tasks, setTasks] = useState<RemediationTaskItem[]>([]);

  const [findings, setFindings] = useState<FindingWithRemediation[]>([]);
  const [findingsTotal, setFindingsTotal] = useState(0);
  const [findingsPage, setFindingsPage] = useState(1);
  const [findingsLoading, setFindingsLoading] = useState(true);
  const [acknowledging, setAcknowledging] = useState<string | null>(null);

  const loadFindings = useCallback(async () => {
    setFindingsLoading(true);
    try {
      const data = await api.get(
        `/findings?status=open&status=acknowledged&page=${findingsPage}&page_size=20`
      );
      setFindings(data.items);
      setFindingsTotal(data.total);
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to load findings', { variant: 'error' });
    } finally {
      setFindingsLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findingsPage]);

  useEffect(() => {
    loadFindings();
  }, [loadFindings]);

  const handleAcknowledge = async (findingId: string, currentStatus: string) => {
    setAcknowledging(findingId);
    const nextStatus = currentStatus === 'acknowledged' ? 'open' : 'acknowledged';
    try {
      await api.patch(`/findings/${findingId}/status`, { status: nextStatus });
      enqueueSnackbar(
        nextStatus === 'acknowledged' ? 'Finding acknowledged' : 'Finding reopened',
        { variant: 'success' }
      );
      loadFindings();
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to update finding', { variant: 'error' });
    } finally {
      setAcknowledging(null);
    }
  };

  useEffect(() => {
    (async () => {
      try {
        const data = await api.get('/remediation/tasks');
        setTasks(data.items);
      } catch {
        // best-effort — task history isn't critical path for this page
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleGenerate = async () => {
    const findingIds = Array.from(selectedFindingIds);

    if (findingIds.length === 0) {
      enqueueSnackbar('Select at least one finding from the table below', { variant: 'warning' });
      return;
    }

    setGenerating(true);
    try {
      const res = await fetch(`${api.baseUrl}/remediation/generate-scripts`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${api.accessToken}`,
        },
        body: JSON.stringify({ finding_ids: findingIds, script_type: scriptType }),
      });

      if (!res.ok) {
        throw new ApiError(`Checklist generation failed (${res.status})`, res.status);
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `arg-remediation.${SCRIPT_EXTENSIONS[scriptType]}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

      enqueueSnackbar('Remediation checklist downloaded', { variant: 'success' });
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to generate checklist', { variant: 'error' });
    } finally {
      setGenerating(false);
    }
  };

  return (
    <Box>
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 2.5 }}>
        Remediation
      </Typography>

      <Alert severity="info" sx={{ mb: 2.5 }}>
        Downloaded checklists list each finding's remediation guidance as commented action items —
        they are not auto-executable scripts. Always verify the exact commands for your environment
        before running anything.
      </Alert>

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="subtitle2" sx={{ mb: 2, color: alpha('#fff', 0.7) }}>
            <Terminal fontSize="small" sx={{ verticalAlign: 'middle', mr: 1 }} />
            Generate Remediation Checklist
          </Typography>

          <Typography variant="caption" sx={{ color: alpha('#fff', 0.5), display: 'block', mb: 1 }}>
            Format
          </Typography>
          <ToggleButtonGroup
            value={scriptType}
            exclusive
            onChange={(_, v) => v && setScriptType(v)}
            size="small"
            sx={{ mb: 2.5 }}
          >
            {SCRIPT_TYPES.map((t) => (
              <ToggleButton key={t.value} value={t.value}>
                {t.label}
              </ToggleButton>
            ))}
          </ToggleButtonGroup>

          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2.5, p: 1.5, borderRadius: 1, bgcolor: alpha('#fff', 0.04), border: `1px solid ${alpha('#fff', 0.08)}` }}>
            <Box>
              {selectedFindingIds.size === 0 ? (
                <Typography variant="body2" sx={{ color: alpha('#fff', 0.5) }}>
                  Select findings from the table below, then click Generate.
                </Typography>
              ) : (
                <Typography variant="body2">
                  <strong>{selectedFindingIds.size}</strong> finding{selectedFindingIds.size !== 1 ? 's' : ''} selected
                </Typography>
              )}
            </Box>
            {selectedFindingIds.size > 0 && (
              <Button
                size="small"
                startIcon={<FilterAltOff fontSize="small" />}
                onClick={() => setSelectedFindingIds(new Set())}
                sx={{ color: alpha('#fff', 0.5) }}
              >
                Clear
              </Button>
            )}
          </Box>

          <Button
            variant="contained"
            startIcon={<Download />}
            onClick={handleGenerate}
            disabled={generating || selectedFindingIds.size === 0}
            sx={{ background: 'linear-gradient(135deg, #00D4FF 0%, #0066FF 100%)', fontWeight: 700 }}
          >
            {generating ? 'Generating…' : `Generate Checklist${selectedFindingIds.size > 0 ? ` (${selectedFindingIds.size})` : ''}`}
          </Button>
        </CardContent>
      </Card>

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
            <Typography variant="subtitle2" sx={{ color: alpha('#fff', 0.7) }}>
              Findings &amp; Remediation Steps
            </Typography>
            <Typography variant="caption" sx={{ color: alpha('#fff', 0.4) }}>
              Tick findings to include in the checklist above
            </Typography>
          </Box>
          {findingsLoading ? (
            <Typography variant="body2" sx={{ color: alpha('#fff', 0.4), py: 2 }}>
              Loading…
            </Typography>
          ) : findings.length === 0 ? (
            <Typography variant="body2" sx={{ color: alpha('#fff', 0.4), py: 2 }}>
              No open findings — nothing to remediate right now.
            </Typography>
          ) : (
            <>
              <TableContainer sx={{ overflowX: 'auto' }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell padding="checkbox">
                      <Tooltip title={selectedFindingIds.size === findings.length ? 'Deselect all' : 'Select all on this page'}>
                        <Checkbox
                          size="small"
                          indeterminate={selectedFindingIds.size > 0 && selectedFindingIds.size < findings.length}
                          checked={findings.length > 0 && findings.every((f) => selectedFindingIds.has(f.id))}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setSelectedFindingIds((prev) => new Set([...prev, ...findings.map((f) => f.id)]));
                            } else {
                              setSelectedFindingIds((prev) => {
                                const next = new Set(prev);
                                findings.forEach((f) => next.delete(f.id));
                                return next;
                              });
                            }
                          }}
                        />
                      </Tooltip>
                    </TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Finding</TableCell>
                    <TableCell>Remediation Steps</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell align="right">Acknowledge</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {findings.map((f) => (
                    <TableRow
                      key={f.id}
                      hover
                      selected={selectedFindingIds.has(f.id)}
                      onClick={() => {
                        setSelectedFindingIds((prev) => {
                          const next = new Set(prev);
                          if (next.has(f.id)) next.delete(f.id);
                          else next.add(f.id);
                          return next;
                        });
                      }}
                      sx={{ cursor: 'pointer' }}
                    >
                      <TableCell padding="checkbox" onClick={(e) => e.stopPropagation()}>
                        <Checkbox
                          size="small"
                          checked={selectedFindingIds.has(f.id)}
                          onChange={() => {
                            setSelectedFindingIds((prev) => {
                              const next = new Set(prev);
                              if (next.has(f.id)) next.delete(f.id);
                              else next.add(f.id);
                              return next;
                            });
                          }}
                        />
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={f.severity.toUpperCase()}
                          sx={{
                            bgcolor: alpha(SEVERITY_COLORS[f.severity] ?? '#9E9E9E', 0.15),
                            color: SEVERITY_COLORS[f.severity] ?? '#9E9E9E',
                            fontWeight: 700,
                            fontSize: 11,
                          }}
                        />
                      </TableCell>
                      <TableCell sx={{ maxWidth: 220 }}>
                        <Typography variant="body2">{f.title}</Typography>
                        {f.resource_name && (
                          <Typography variant="caption" sx={{ color: alpha('#fff', 0.4) }}>
                            {f.resource_name}
                          </Typography>
                        )}
                      </TableCell>
                      <TableCell sx={{ color: alpha('#fff', 0.6), maxWidth: 420 }}>
                        <Tooltip title={f.remediation_steps ?? ''} arrow placement="top">
                          <Typography
                            variant="body2"
                            sx={{
                              display: '-webkit-box',
                              WebkitLineClamp: 3,
                              WebkitBoxOrient: 'vertical',
                              overflow: 'hidden',
                              whiteSpace: 'pre-line',
                              cursor: f.remediation_steps ? 'help' : 'default',
                            }}
                          >
                            {f.remediation_steps ?? 'No remediation guidance recorded for this finding type.'}
                          </Typography>
                        </Tooltip>
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={f.status}
                          sx={{
                            fontSize: 11,
                            bgcolor: alpha(f.status === 'acknowledged' ? '#4CAF50' : '#9E9E9E', 0.15),
                            color: f.status === 'acknowledged' ? '#4CAF50' : '#9E9E9E',
                          }}
                        />
                      </TableCell>
                      <TableCell align="right">
                        <Tooltip title={f.status === 'acknowledged' ? 'Reopen' : 'Acknowledge'}>
                          <span>
                            <IconButton
                              size="small"
                              onClick={() => handleAcknowledge(f.id, f.status)}
                              disabled={acknowledging === f.id}
                              sx={{ color: f.status === 'acknowledged' ? '#FF9800' : '#4CAF50' }}
                            >
                              {f.status === 'acknowledged' ? <Undo fontSize="small" /> : <CheckCircle fontSize="small" />}
                            </IconButton>
                          </span>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              </TableContainer>
              {Math.ceil(findingsTotal / 20) > 1 && (
                <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
                  <Pagination
                    count={Math.ceil(findingsTotal / 20)}
                    page={findingsPage}
                    onChange={(_, p) => setFindingsPage(p)}
                    color="primary"
                    size="small"
                  />
                </Box>
              )}
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <Typography variant="subtitle2" sx={{ mb: 2, color: alpha('#fff', 0.7) }}>
            Staged Remediation Tasks
          </Typography>
          {tasks.length === 0 ? (
            <Typography variant="body2" sx={{ color: alpha('#fff', 0.4), py: 2 }}>
              No remediation tasks staged yet.
            </Typography>
          ) : (
            <TableContainer sx={{ overflowX: 'auto' }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Finding</TableCell>
                  <TableCell>Method</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Scheduled</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {tasks.map((t) => (
                  <TableRow key={t.id} hover>
                    <TableCell>{t.finding_title ?? t.finding_id}</TableCell>
                    <TableCell sx={{ color: alpha('#fff', 0.6) }}>{t.execution_method}</TableCell>
                    <TableCell>
                      <Chip
                        size="small"
                        label={t.status}
                        sx={{
                          fontSize: 11,
                          bgcolor: alpha(STATUS_COLORS[t.status] ?? '#9E9E9E', 0.15),
                          color: STATUS_COLORS[t.status] ?? '#9E9E9E',
                        }}
                      />
                    </TableCell>
                    <TableCell sx={{ color: alpha('#fff', 0.5) }}>
                      {t.scheduled_at ? new Date(t.scheduled_at).toLocaleString() : '—'}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            </TableContainer>
          )}
        </CardContent>
      </Card>
    </Box>
  );
};
