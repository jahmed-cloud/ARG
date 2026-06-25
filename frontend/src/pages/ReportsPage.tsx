/**
 * ReportsPage — generate and download governance reports.
 *
 * Matches backend/api/routes/reports.py:
 *   POST /reports/generate { report_type, output_format, title, include_resolved }
 *     -> streams a file (pdf/excel/csv/json) as attachment
 *   GET  /reports -> list of previously generated reports stored in DB
 *
 * Since /reports/generate returns a binary blob rather than JSON, we
 * can't use the shared useApi() JSON helper directly — we do a raw
 * fetch here and trigger a browser download via an object URL.
 */
import React, { useEffect, useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  ToggleButtonGroup,
  ToggleButton,
  Button,
  FormControlLabel,
  Checkbox,
  Table,
  TableContainer,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  Chip,
  IconButton,
  Tooltip,
  alpha,
} from '@mui/material';
import { Download, PictureAsPdf, TableChart, DataObject, Description, DeleteOutline } from '@mui/icons-material';
import { useApi, ApiError } from '../hooks/useApi';
import { useSnackbar } from 'notistack';

const REPORT_TYPES = [
  { value: 'board', label: 'Board' },
  { value: 'executive', label: 'Executive' },
  { value: 'technical', label: 'Technical' },
];

const FORMATS = [
  { value: 'pdf', label: 'PDF', icon: <PictureAsPdf fontSize="small" /> },
  { value: 'excel', label: 'Excel', icon: <TableChart fontSize="small" /> },
  { value: 'csv', label: 'CSV', icon: <TableChart fontSize="small" /> },
  { value: 'json', label: 'JSON', icon: <DataObject fontSize="small" /> },
];

const FORMAT_EXTENSIONS: Record<string, string> = {
  pdf: 'pdf',
  excel: 'xlsx',
  csv: 'csv',
  json: 'json',
};

interface ReportRecord {
  id: string;
  title: string;
  report_type: string;
  output_format: string;
  is_ready: boolean;
  error_message: string | null;
  expires_at: string | null;
}

export const ReportsPage: React.FC = () => {
  const api = useApi();
  const { enqueueSnackbar } = useSnackbar();

  const [reportType, setReportType] = useState('technical');
  const [outputFormat, setOutputFormat] = useState('pdf');
  const [includeResolved, setIncludeResolved] = useState(false);
  const [generating, setGenerating] = useState(false);

  const [history, setHistory] = useState<ReportRecord[]>([]);

  const loadHistory = async () => {
    try {
      const data = await api.get('/reports');
      setHistory(data.items);
    } catch {
      // Non-critical — history is best-effort
    }
  };

  useEffect(() => {
    loadHistory();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleDownloadExisting = async (r: ReportRecord) => {
    try {
      const res = await fetch(`${api.baseUrl}/reports/${r.id}/download`, {
        headers: { Authorization: `Bearer ${api.accessToken}` },
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new ApiError(body.detail ?? `Download failed (${res.status})`, res.status);
      }
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${r.title}.${FORMAT_EXTENSIONS[r.output_format] ?? 'bin'}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to download report', { variant: 'error' });
    }
  };

  const handleDeleteReport = async (r: ReportRecord) => {
    try {
      await api.del(`/reports/${r.id}`);
      enqueueSnackbar('Report removed', { variant: 'success' });
      loadHistory();
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to remove report', { variant: 'error' });
    }
  };

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      const res = await fetch(`${api.baseUrl}/reports/generate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${api.accessToken}`,
        },
        body: JSON.stringify({
          report_type: reportType,
          output_format: outputFormat,
          include_resolved: includeResolved,
        }),
      });

      if (!res.ok) {
        throw new ApiError(`Report generation failed (${res.status})`, res.status);
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `arg-report.${FORMAT_EXTENSIONS[outputFormat]}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

      enqueueSnackbar('Report downloaded', { variant: 'success' });
      loadHistory();
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Failed to generate report', { variant: 'error' });
    } finally {
      setGenerating(false);
    }
  };

  return (
    <Box>
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 2.5 }}>
        Reports
      </Typography>

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="subtitle2" sx={{ mb: 2, color: alpha('#fff', 0.7) }}>
            Generate New Report
          </Typography>

          <Typography variant="caption" sx={{ color: alpha('#fff', 0.5), display: 'block', mb: 1 }}>
            Report depth
          </Typography>
          <ToggleButtonGroup
            value={reportType}
            exclusive
            onChange={(_, v) => v && setReportType(v)}
            size="small"
            sx={{ mb: 2.5 }}
          >
            {REPORT_TYPES.map((t) => (
              <ToggleButton key={t.value} value={t.value}>
                {t.label}
              </ToggleButton>
            ))}
          </ToggleButtonGroup>

          <Typography variant="caption" sx={{ color: alpha('#fff', 0.5), display: 'block', mb: 1 }}>
            Format
          </Typography>
          <ToggleButtonGroup
            value={outputFormat}
            exclusive
            onChange={(_, v) => v && setOutputFormat(v)}
            size="small"
            sx={{ mb: 2.5 }}
          >
            {FORMATS.map((f) => (
              <ToggleButton key={f.value} value={f.value} sx={{ gap: 0.75 }}>
                {f.icon}
                {f.label}
              </ToggleButton>
            ))}
          </ToggleButtonGroup>

          <FormControlLabel
            control={<Checkbox checked={includeResolved} onChange={(e) => setIncludeResolved(e.target.checked)} />}
            label="Include resolved findings"
            sx={{ display: 'block', mb: 2.5 }}
          />

          <Button
            variant="contained"
            startIcon={<Download />}
            onClick={handleGenerate}
            disabled={generating}
            sx={{ background: 'linear-gradient(135deg, #00D4FF 0%, #0066FF 100%)', fontWeight: 700 }}
          >
            {generating ? 'Generating…' : 'Generate & Download'}
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <Typography variant="subtitle2" sx={{ mb: 2, color: alpha('#fff', 0.7) }}>
            <Description fontSize="small" sx={{ verticalAlign: 'middle', mr: 1 }} />
            Report History
          </Typography>
          {history.length === 0 ? (
            <Typography variant="body2" sx={{ color: alpha('#fff', 0.4), py: 2 }}>
              No reports generated yet. Use the form above to create one.
            </Typography>
          ) : (
            <TableContainer sx={{ overflowX: 'auto' }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Title</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>Format</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Expires</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {history.map((r) => (
                  <TableRow key={r.id} hover>
                    <TableCell>{r.title}</TableCell>
                    <TableCell sx={{ color: alpha('#fff', 0.6) }}>{r.report_type}</TableCell>
                    <TableCell sx={{ color: alpha('#fff', 0.6) }}>{r.output_format}</TableCell>
                    <TableCell>
                      <Chip
                        size="small"
                        label={r.is_ready ? 'Ready' : r.error_message ? 'Failed' : 'Pending'}
                        sx={{
                          fontSize: 11,
                          bgcolor: alpha(r.is_ready ? '#4CAF50' : r.error_message ? '#F44336' : '#9E9E9E', 0.15),
                          color: r.is_ready ? '#4CAF50' : r.error_message ? '#F44336' : '#9E9E9E',
                        }}
                      />
                    </TableCell>
                    <TableCell sx={{ color: alpha('#fff', 0.5) }}>
                      {r.expires_at ? new Date(r.expires_at).toLocaleString() : '—'}
                    </TableCell>
                    <TableCell align="right">
                      {r.is_ready && (
                        <Tooltip title="Download">
                          <IconButton size="small" onClick={() => handleDownloadExisting(r)}>
                            <Download fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      )}
                      <Tooltip title="Remove">
                        <IconButton size="small" onClick={() => handleDeleteReport(r)} sx={{ color: alpha('#F44336', 0.8) }}>
                          <DeleteOutline fontSize="small" />
                        </IconButton>
                      </Tooltip>
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
