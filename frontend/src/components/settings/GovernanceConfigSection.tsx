/**
 * GovernanceConfigSection — admin UI for editing required tags and
 * naming convention patterns used by governance scanners.
 */
import React, { useEffect, useState } from 'react';
import {
  Box, Card, CardContent, Typography, TextField, Button,
  Chip, Stack, Alert, Divider, IconButton, Tooltip, alpha,
} from '@mui/material';
import { Add, DeleteOutline, RestartAlt, Save } from '@mui/icons-material';
import { useApi, ApiError } from '../../hooks/useApi';
import { useSnackbar } from 'notistack';

interface GovernanceConfigData {
  required_tags: string[];
  naming_patterns: Record<string, string>;
  naming_pattern_descriptions: Record<string, string>;
  is_default: boolean;
}

export const GovernanceConfigSection: React.FC = () => {
  const api = useApi();
  const { enqueueSnackbar } = useSnackbar();

  const [config, setConfig] = useState<GovernanceConfigData | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  // Editable state
  const [tags, setTags] = useState<string[]>([]);
  const [newTag, setNewTag] = useState('');
  const [patterns, setPatterns] = useState<Record<string, string>>({});
  const [newResourceType, setNewResourceType] = useState('');
  const [newPattern, setNewPattern] = useState('');
  const [patternErrors, setPatternErrors] = useState<Record<string, string>>({});

  useEffect(() => {
    api.get('/governance/config').then((data) => {
      setConfig(data);
      setTags(data.required_tags);
      setPatterns(data.naming_patterns);
    }).catch(() => {
      enqueueSnackbar('Failed to load governance config', { variant: 'error' });
    }).finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const validatePattern = (pattern: string): string => {
    try { new RegExp(pattern); return ''; }
    catch (e: any) { return e.message; }
  };

  const addTag = () => {
    const t = newTag.trim().toLowerCase();
    if (!t || tags.includes(t)) return;
    setTags([...tags, t]);
    setNewTag('');
  };

  const removeTag = (tag: string) => setTags(tags.filter((t) => t !== tag));

  const updatePattern = (type: string, value: string) => {
    setPatterns((prev) => ({ ...prev, [type]: value }));
    const err = value ? validatePattern(value) : '';
    setPatternErrors((prev) => ({ ...prev, [type]: err }));
  };

  const removePattern = (type: string) => {
    setPatterns((prev) => { const n = { ...prev }; delete n[type]; return n; });
    setPatternErrors((prev) => { const n = { ...prev }; delete n[type]; return n; });
  };

  const addPattern = () => {
    const t = newResourceType.trim().toLowerCase();
    const p = newPattern.trim();
    if (!t || !p) return;
    const err = validatePattern(p);
    if (err) { enqueueSnackbar(`Invalid pattern: ${err}`, { variant: 'error' }); return; }
    setPatterns((prev) => ({ ...prev, [t]: p }));
    setNewResourceType('');
    setNewPattern('');
  };

  const handleSave = async () => {
    const hasErrors = Object.values(patternErrors).some(Boolean);
    if (hasErrors) { enqueueSnackbar('Fix pattern errors before saving', { variant: 'warning' }); return; }
    setSaving(true);
    try {
      await api.put('/governance/config', { required_tags: tags, naming_patterns: patterns });
      enqueueSnackbar('Governance config saved — changes take effect on next scan', { variant: 'success' });
    } catch (e) {
      enqueueSnackbar(e instanceof ApiError ? e.message : 'Save failed', { variant: 'error' });
    } finally {
      setSaving(false);
    }
  };

  const handleReset = async () => {
    try {
      const defaults = await api.get('/governance/config/defaults');
      setTags(defaults.required_tags);
      setPatterns(defaults.naming_patterns);
      setPatternErrors({});
      enqueueSnackbar('Reset to defaults — click Save to apply', { variant: 'info' });
    } catch {
      enqueueSnackbar('Failed to load defaults', { variant: 'error' });
    }
  };

  if (loading) return null;

  return (
    <Card sx={{ mb: 3 }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 0.5 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
            Governance Configuration
          </Typography>
          <Tooltip title="Reset to built-in defaults">
            <Button size="small" startIcon={<RestartAlt />} onClick={handleReset} sx={{ color: alpha('#fff', 0.5) }}>
              Reset to defaults
            </Button>
          </Tooltip>
        </Box>
        <Typography variant="body2" sx={{ color: alpha('#fff', 0.5), mb: 2.5 }}>
          Configure which tags are required and which naming conventions apply.
          Changes take effect on the next scan.
          {config?.is_default && (
            <> Using built-in defaults — save to persist custom values.</>
          )}
        </Typography>

        {/* Required Tags */}
        <Typography variant="subtitle2" sx={{ mb: 1, color: alpha('#fff', 0.7) }}>
          Required Tags
        </Typography>
        <Typography variant="caption" sx={{ color: alpha('#fff', 0.4), display: 'block', mb: 1.5 }}>
          Every scanned resource must have these tag keys. Missing tags raise a finding.
        </Typography>
        <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ mb: 1.5 }}>
          {tags.map((tag) => (
            <Chip
              key={tag}
              label={tag}
              size="small"
              onDelete={() => removeTag(tag)}
              sx={{ bgcolor: alpha('#00D4FF', 0.1), color: '#00D4FF', borderColor: alpha('#00D4FF', 0.3) }}
              variant="outlined"
            />
          ))}
        </Stack>
        <Box sx={{ display: 'flex', gap: 1, mb: 3 }}>
          <TextField
            size="small"
            placeholder="e.g. team"
            value={newTag}
            onChange={(e) => setNewTag(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && addTag()}
            sx={{ flex: 1 }}
          />
          <Button size="small" variant="outlined" startIcon={<Add />} onClick={addTag} disabled={!newTag.trim()}>
            Add Tag
          </Button>
        </Box>

        <Divider sx={{ mb: 3, borderColor: alpha('#fff', 0.08) }} />

        {/* Naming Patterns */}
        <Typography variant="subtitle2" sx={{ mb: 1, color: alpha('#fff', 0.7) }}>
          Naming Convention Patterns
        </Typography>
        <Typography variant="caption" sx={{ color: alpha('#fff', 0.4), display: 'block', mb: 2 }}>
          Regex patterns (case-insensitive) per resource type. Resources not matching their pattern raise a finding.
        </Typography>

        <Alert severity="info" sx={{ mb: 2, fontSize: 12 }}>
          Patterns are matched case-insensitively. Use standard regex — e.g.{' '}
          <code>^vm-[a-z0-9]+-[a-z]+-\d{'{'}{3}{'}'}$</code>.
          Resource types must be lowercase, e.g.{' '}
          <code>microsoft.compute/virtualmachines</code>.
        </Alert>

        {Object.entries(patterns).map(([rtype, pattern]) => (
          <Box key={rtype} sx={{ mb: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
              <Typography variant="caption" sx={{ color: alpha('#00D4FF', 0.8), fontFamily: 'monospace', flex: 1 }}>
                {rtype}
              </Typography>
              {config?.naming_pattern_descriptions?.[rtype] && (
                <Typography variant="caption" sx={{ color: alpha('#fff', 0.4) }}>
                  {config.naming_pattern_descriptions[rtype]}
                </Typography>
              )}
              <Tooltip title="Remove this pattern">
                <IconButton size="small" onClick={() => removePattern(rtype)} sx={{ color: alpha('#F44336', 0.7) }}>
                  <DeleteOutline fontSize="small" />
                </IconButton>
              </Tooltip>
            </Box>
            <TextField
              size="small"
              fullWidth
              value={pattern}
              onChange={(e) => updatePattern(rtype, e.target.value)}
              error={!!patternErrors[rtype]}
              helperText={patternErrors[rtype] || undefined}
              sx={{ fontFamily: 'monospace' }}
              inputProps={{ style: { fontFamily: 'monospace', fontSize: 13 } }}
            />
          </Box>
        ))}

        <Box sx={{ display: 'flex', gap: 1, mb: 3, flexWrap: 'wrap' }}>
          <TextField
            size="small"
            placeholder="Resource type (e.g. microsoft.compute/virtualmachines)"
            value={newResourceType}
            onChange={(e) => setNewResourceType(e.target.value)}
            sx={{ flex: 2, minWidth: 200 }}
            inputProps={{ style: { fontFamily: 'monospace', fontSize: 12 } }}
          />
          <TextField
            size="small"
            placeholder="Regex pattern"
            value={newPattern}
            onChange={(e) => setNewPattern(e.target.value)}
            sx={{ flex: 2, minWidth: 200 }}
            inputProps={{ style: { fontFamily: 'monospace', fontSize: 12 } }}
          />
          <Button
            size="small"
            variant="outlined"
            startIcon={<Add />}
            onClick={addPattern}
            disabled={!newResourceType.trim() || !newPattern.trim()}
          >
            Add
          </Button>
        </Box>

        <Button
          variant="contained"
          startIcon={<Save />}
          onClick={handleSave}
          disabled={saving}
          sx={{ background: 'linear-gradient(135deg, #00D4FF 0%, #0066FF 100%)', fontWeight: 700 }}
        >
          {saving ? 'Saving…' : 'Save Configuration'}
        </Button>
      </CardContent>
    </Card>
  );
};
