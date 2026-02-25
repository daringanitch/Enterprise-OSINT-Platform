/**
 * Settings Page – Service Configuration & API Key Management
 *
 * Lets users:
 *   • See every intelligence service, what it does, and whether it's free
 *   • Toggle services on/off
 *   • Add / test / remove API keys
 *   • Switch between Demo mode and Live mode
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Typography,
  Switch,
  Chip,
  CircularProgress,
  Tabs,
  Tab,
  Collapse,
  IconButton,
  InputAdornment,
  OutlinedInput,
  FormControl,
  Tooltip,
  Alert,
  AlertTitle,
  Divider,
  LinearProgress,
  styled,
  alpha,
} from '@mui/material';
import {
  CheckCircle as CheckCircleIcon,
  Cancel as CancelIcon,
  Warning as WarningIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon,
  OpenInNew as OpenInNewIcon,
  Science as ScienceIcon,
  Delete as DeleteIcon,
  Save as SaveIcon,
  RadioButtonChecked as LiveIcon,
  Movie as DemoIcon,
  NetworkCheck as NetworkIcon,
  Security as SecurityIcon,
  PersonSearch as SocialIcon,
  SmartToy as AiIcon,
  Lock as BreachIcon,
  Done as DoneIcon,
  Error as ErrorIcon,
} from '@mui/icons-material';
import { motion, AnimatePresence } from 'framer-motion';
import { cyberColors, designTokens, glassmorphism } from '../utils/theme';
import { pageVariants } from '../utils/animations';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ServiceStatus {
  id: string;
  name: string;
  description: string;
  category: string;
  tier: 'free' | 'freemium' | 'paid';
  tier_note: string;
  works_without_key: boolean;
  env_var: string | null;
  signup_url: string | null;
  docs_url: string | null;
  rate_limit_note: string | null;
  enabled: boolean;
  key_status: 'not_required' | 'configured' | 'missing';
  key_preview: string | null;
  operational: boolean;
}

interface Summary {
  total: number;
  enabled: number;
  operational: number;
  needs_key: number;
}

interface ModeStatus {
  current_mode: string;
  user_preference: string | null;
  auto_fallback_enabled: boolean;
  last_mode_switch: string | null;
}

type TestResult = { ok: boolean; message: string } | null;

// ---------------------------------------------------------------------------
// Styled components
// ---------------------------------------------------------------------------

const PageContainer = styled(motion.div)({
  padding: '24px 28px',
  maxWidth: 1100,
  margin: '0 auto',
});

const PageTitle = styled(Typography)({
  fontFamily: designTokens.typography.fontFamily.display,
  fontSize: '1.75rem',
  fontWeight: 700,
  color: cyberColors.text.primary,
  marginBottom: 4,
});

const PageSubtitle = styled(Typography)({
  color: cyberColors.text.secondary,
  fontSize: '0.95rem',
  marginBottom: 24,
});

const GlassCard = styled(Box)({
  ...glassmorphism.card,
  padding: 20,
  borderRadius: designTokens.borderRadius.lg,
  marginBottom: 16,
});

const ServiceCard = styled(motion.div)<{ operational?: boolean }>(({ operational }) => ({
  ...glassmorphism.card,
  padding: '18px 20px',
  borderRadius: designTokens.borderRadius.lg,
  marginBottom: 12,
  borderLeft: `3px solid ${operational ? cyberColors.neon.green : cyberColors.dark.steel}`,
  transition: 'border-color 0.2s',
}));

const SectionTitle = styled(Typography)({
  fontFamily: designTokens.typography.fontFamily.display,
  fontSize: '0.85rem',
  fontWeight: 600,
  color: cyberColors.neon.cyan,
  textTransform: 'uppercase',
  letterSpacing: '0.08em',
  marginBottom: 12,
  marginTop: 24,
});

const KeyInput = styled(OutlinedInput)({
  fontFamily: 'monospace',
  fontSize: '0.85rem',
  color: cyberColors.text.primary,
  backgroundColor: alpha(cyberColors.dark.charcoal, 0.6),
  '& .MuiOutlinedInput-notchedOutline': {
    borderColor: alpha(cyberColors.neon.cyan, 0.2),
  },
  '&:hover .MuiOutlinedInput-notchedOutline': {
    borderColor: alpha(cyberColors.neon.cyan, 0.5),
  },
  '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
    borderColor: cyberColors.neon.cyan,
  },
});

const TierBadge = styled(Chip)<{ tier: 'free' | 'freemium' | 'paid' }>(({ tier }) => {
  const colors = {
    free: { bg: alpha(cyberColors.neon.green, 0.15), color: cyberColors.neon.green, border: alpha(cyberColors.neon.green, 0.4) },
    freemium: { bg: alpha(cyberColors.neon.cyan, 0.12), color: cyberColors.neon.cyan, border: alpha(cyberColors.neon.cyan, 0.35) },
    paid: { bg: alpha(cyberColors.neon.orange, 0.12), color: cyberColors.neon.orange, border: alpha(cyberColors.neon.orange, 0.35) },
  };
  const c = colors[tier];
  return {
    height: 22,
    fontSize: '0.7rem',
    fontWeight: 700,
    backgroundColor: c.bg,
    color: c.color,
    border: `1px solid ${c.border}`,
    '& .MuiChip-label': { padding: '0 8px' },
  };
});

const CategoryChip = styled(Chip)({
  height: 28,
  fontSize: '0.78rem',
  cursor: 'pointer',
  '& .MuiChip-label': { padding: '0 10px' },
});

const ActionBtn = styled('button')<{ variant?: 'primary' | 'danger' | 'ghost' }>(({ variant = 'ghost' }) => {
  const styles: Record<string, React.CSSProperties> = {
    primary: {
      background: alpha(cyberColors.neon.cyan, 0.12),
      color: cyberColors.neon.cyan,
      border: `1px solid ${alpha(cyberColors.neon.cyan, 0.4)}`,
    },
    danger: {
      background: alpha(cyberColors.neon.red, 0.1),
      color: cyberColors.neon.red,
      border: `1px solid ${alpha(cyberColors.neon.red, 0.3)}`,
    },
    ghost: {
      background: 'transparent',
      color: cyberColors.text.secondary,
      border: `1px solid ${alpha(cyberColors.text.secondary, 0.2)}`,
    },
  };
  return {
    ...styles[variant],
    borderRadius: 6,
    padding: '5px 12px',
    fontSize: '0.78rem',
    fontWeight: 600,
    cursor: 'pointer',
    display: 'inline-flex',
    alignItems: 'center',
    gap: 4,
    transition: 'all 0.15s',
    '&:hover': { opacity: 0.8 },
    '&:disabled': { opacity: 0.4, cursor: 'not-allowed' },
  } as any;
});

const ModeToggleCard = styled(Box)<{ active?: boolean; modecolor?: string }>(({ active, modecolor }) => ({
  ...glassmorphism.card,
  padding: '20px 24px',
  borderRadius: designTokens.borderRadius.lg,
  border: active ? `2px solid ${modecolor}` : `2px solid transparent`,
  cursor: 'pointer',
  transition: 'all 0.2s',
  '&:hover': {
    borderColor: modecolor,
    opacity: 0.9,
  },
}));

// ---------------------------------------------------------------------------
// Category icon map
// ---------------------------------------------------------------------------

const categoryIcons: Record<string, React.ReactNode> = {
  network: <NetworkIcon sx={{ fontSize: 16 }} />,
  threat: <SecurityIcon sx={{ fontSize: 16 }} />,
  social: <SocialIcon sx={{ fontSize: 16 }} />,
  ai: <AiIcon sx={{ fontSize: 16 }} />,
  breach: <BreachIcon sx={{ fontSize: 16 }} />,
};

const categoryColors: Record<string, string> = {
  network: cyberColors.neon.electricBlue,
  threat: cyberColors.neon.red,
  social: cyberColors.neon.magenta,
  ai: cyberColors.neon.purple,
  breach: cyberColors.neon.orange,
};

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

async function apiFetch(path: string, options: RequestInit = {}) {
  const token = localStorage.getItem('token');
  const res = await fetch(`/api${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

interface ServiceCardProps {
  service: ServiceStatus;
  onToggle: (id: string, enabled: boolean) => void;
  onSaveKey: (id: string, key: string) => Promise<void>;
  onDeleteKey: (id: string) => Promise<void>;
  onTestKey: (id: string, key?: string) => Promise<TestResult>;
}

function ServiceRow({ service, onToggle, onSaveKey, onDeleteKey, onTestKey }: ServiceCardProps) {
  const [expanded, setExpanded] = useState(false);
  const [keyValue, setKeyValue] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<TestResult>(null);

  const needsKey = service.env_var && service.key_status === 'missing' && !service.works_without_key;
  const hasKey = service.key_status === 'configured';

  const handleSave = async () => {
    if (!keyValue.trim()) return;
    setSaving(true);
    setTestResult(null);
    try {
      await onSaveKey(service.id, keyValue.trim());
      setKeyValue('');
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    const result = await onTestKey(service.id, keyValue.trim() || undefined);
    setTestResult(result);
    setTesting(false);
  };

  const handleDelete = async () => {
    setTestResult(null);
    await onDeleteKey(service.id);
  };

  const keyStatusIcon = () => {
    if (service.key_status === 'not_required') return <CheckCircleIcon sx={{ fontSize: 14, color: cyberColors.neon.green }} />;
    if (service.key_status === 'configured') return <CheckCircleIcon sx={{ fontSize: 14, color: cyberColors.neon.green }} />;
    if (service.works_without_key) return <WarningIcon sx={{ fontSize: 14, color: cyberColors.neon.orange }} />;
    return <CancelIcon sx={{ fontSize: 14, color: cyberColors.text.muted }} />;
  };

  const statusLabel = () => {
    if (!service.enabled) return 'Disabled';
    if (service.operational) return 'Operational';
    if (service.works_without_key) return 'Limited (no key)';
    return 'Needs API Key';
  };

  const statusColor = () => {
    if (!service.enabled) return cyberColors.text.muted;
    if (service.operational) return cyberColors.neon.green;
    if (service.works_without_key) return cyberColors.neon.orange;
    return cyberColors.text.muted;
  };

  return (
    <ServiceCard
      operational={service.operational}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
    >
      {/* Header row */}
      <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
        {/* Category icon */}
        <Box sx={{
          width: 36, height: 36, borderRadius: '50%', flexShrink: 0,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          backgroundColor: alpha(categoryColors[service.category] || cyberColors.neon.cyan, 0.12),
          color: categoryColors[service.category] || cyberColors.neon.cyan,
          mt: 0.3,
        }}>
          {categoryIcons[service.category]}
        </Box>

        {/* Name + badges + description */}
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 1, mb: 0.5 }}>
            <Typography sx={{
              fontWeight: 700, fontSize: '0.95rem',
              color: cyberColors.text.primary,
              fontFamily: designTokens.typography.fontFamily.display,
            }}>
              {service.name}
            </Typography>
            <TierBadge tier={service.tier} label={service.tier.toUpperCase()} />
            <Chip
              size="small"
              label={statusLabel()}
              sx={{
                height: 20, fontSize: '0.68rem', fontWeight: 600,
                backgroundColor: alpha(statusColor(), 0.12),
                color: statusColor(),
                border: `1px solid ${alpha(statusColor(), 0.35)}`,
                '& .MuiChip-label': { padding: '0 7px' },
              }}
            />
          </Box>

          <Typography sx={{ color: cyberColors.text.secondary, fontSize: '0.83rem', lineHeight: 1.4, mb: 0.5 }}>
            {service.description}
          </Typography>

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, flexWrap: 'wrap', mt: 0.5 }}>
            <Typography sx={{ color: cyberColors.text.muted, fontSize: '0.75rem' }}>
              {service.tier_note}
            </Typography>
            {service.rate_limit_note && (
              <Typography sx={{ color: cyberColors.text.muted, fontSize: '0.75rem' }}>
                · {service.rate_limit_note}
              </Typography>
            )}
            {service.signup_url && (
              <a href={service.signup_url} target="_blank" rel="noopener noreferrer"
                style={{ color: cyberColors.neon.cyan, fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: 2, textDecoration: 'none' }}>
                Get free key <OpenInNewIcon sx={{ fontSize: 11 }} />
              </a>
            )}
          </Box>
        </Box>

        {/* Controls */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexShrink: 0 }}>
          {/* Key status dot */}
          <Tooltip title={
            service.key_status === 'not_required' ? 'No API key needed' :
            service.key_status === 'configured' ? `Key configured: ${service.key_preview}` :
            'No API key configured'
          }>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              {keyStatusIcon()}
            </Box>
          </Tooltip>

          {/* Expand key config */}
          {service.env_var && (
            <Tooltip title="Configure API key">
              <IconButton
                size="small"
                onClick={() => setExpanded(e => !e)}
                sx={{ color: cyberColors.text.secondary, p: 0.5 }}
              >
                {expanded ? <ExpandLessIcon sx={{ fontSize: 18 }} /> : <ExpandMoreIcon sx={{ fontSize: 18 }} />}
              </IconButton>
            </Tooltip>
          )}

          {/* Enable/disable toggle */}
          <Tooltip title={service.enabled ? 'Disable service' : 'Enable service'}>
            <Switch
              checked={service.enabled}
              onChange={(_, checked) => onToggle(service.id, checked)}
              size="small"
              sx={{
                '& .MuiSwitch-switchBase.Mui-checked': { color: cyberColors.neon.cyan },
                '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': {
                  backgroundColor: alpha(cyberColors.neon.cyan, 0.5),
                },
              }}
            />
          </Tooltip>
        </Box>
      </Box>

      {/* Expanded API key section */}
      <Collapse in={expanded && !!service.env_var}>
        <Box sx={{ mt: 2, pt: 2, borderTop: `1px solid ${alpha(cyberColors.neon.cyan, 0.1)}` }}>
          <Typography sx={{ fontSize: '0.78rem', color: cyberColors.text.muted, mb: 1 }}>
            Environment variable: <code style={{ color: cyberColors.neon.cyan }}>{service.env_var}</code>
          </Typography>

          {/* Existing key display */}
          {hasKey && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1.5 }}>
              <Typography sx={{ fontSize: '0.8rem', color: cyberColors.text.secondary, fontFamily: 'monospace' }}>
                Stored: <span style={{ color: cyberColors.neon.green }}>{service.key_preview}</span>
              </Typography>
              <ActionBtn variant="danger" onClick={handleDelete} style={{ marginLeft: 'auto' }}>
                <DeleteIcon style={{ fontSize: 13 }} /> Remove
              </ActionBtn>
            </Box>
          )}

          {/* Key input */}
          <FormControl fullWidth size="small" sx={{ mb: 1.5 }}>
            <KeyInput
              type={showKey ? 'text' : 'password'}
              value={keyValue}
              onChange={e => setKeyValue(e.target.value)}
              placeholder={hasKey ? 'Enter new key to replace existing…' : `Paste your ${service.name} API key…`}
              size="small"
              onKeyDown={e => e.key === 'Enter' && handleSave()}
              endAdornment={
                <InputAdornment position="end">
                  <IconButton size="small" onClick={() => setShowKey(s => !s)}
                    sx={{ color: cyberColors.text.muted }}>
                    {showKey ? <VisibilityOffIcon sx={{ fontSize: 16 }} /> : <VisibilityIcon sx={{ fontSize: 16 }} />}
                  </IconButton>
                </InputAdornment>
              }
            />
          </FormControl>

          {/* Action buttons */}
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            <ActionBtn
              variant="primary"
              onClick={handleSave}
              disabled={!keyValue.trim() || saving}
            >
              {saving ? <CircularProgress size={11} sx={{ color: 'inherit' }} /> : <SaveIcon style={{ fontSize: 13 }} />}
              {saving ? 'Saving…' : 'Save Key'}
            </ActionBtn>

            <ActionBtn
              variant="ghost"
              onClick={handleTest}
              disabled={testing || (!keyValue.trim() && !hasKey)}
            >
              {testing
                ? <CircularProgress size={11} sx={{ color: 'inherit' }} />
                : <ScienceIcon style={{ fontSize: 13 }} />}
              {testing ? 'Testing…' : 'Test Connection'}
            </ActionBtn>

            {service.signup_url && (
              <a
                href={service.signup_url}
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 4,
                  padding: '5px 12px', borderRadius: 6, fontSize: '0.78rem', fontWeight: 600,
                  background: 'transparent', color: cyberColors.text.secondary,
                  border: `1px solid ${alpha(cyberColors.text.secondary, 0.2)}`,
                  textDecoration: 'none', cursor: 'pointer',
                }}
              >
                <OpenInNewIcon style={{ fontSize: 12 }} /> Get Free Key
              </a>
            )}
          </Box>

          {/* Test result */}
          <AnimatePresence>
            {testResult && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
              >
                <Box sx={{
                  mt: 1.5, p: 1.5, borderRadius: 1,
                  display: 'flex', alignItems: 'center', gap: 1,
                  backgroundColor: alpha(testResult.ok ? cyberColors.neon.green : cyberColors.neon.red, 0.1),
                  border: `1px solid ${alpha(testResult.ok ? cyberColors.neon.green : cyberColors.neon.red, 0.3)}`,
                }}>
                  {testResult.ok
                    ? <DoneIcon sx={{ fontSize: 16, color: cyberColors.neon.green }} />
                    : <ErrorIcon sx={{ fontSize: 16, color: cyberColors.neon.red }} />}
                  <Typography sx={{ fontSize: '0.8rem', color: testResult.ok ? cyberColors.neon.green : cyberColors.neon.red }}>
                    {testResult.message}
                  </Typography>
                </Box>
              </motion.div>
            )}
          </AnimatePresence>
        </Box>
      </Collapse>
    </ServiceCard>
  );
}

// ---------------------------------------------------------------------------
// Main Settings component
// ---------------------------------------------------------------------------

export default function Settings() {
  const [tab, setTab] = useState(0);
  const [services, setServices] = useState<ServiceStatus[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [modeStatus, setModeStatus] = useState<ModeStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; msg: string } | null>(null);

  // Filters
  const [catFilter, setCatFilter] = useState<string>('all');
  const [tierFilter, setTierFilter] = useState<string>('all');

  const notify = (type: 'success' | 'error', msg: string) => {
    setNotification({ type, msg });
    setTimeout(() => setNotification(null), 4000);
  };

  // ── Data loading ────────────────────────────────────────────────────────

  const load = useCallback(async () => {
    try {
      const [svcData, modeData] = await Promise.all([
        apiFetch('/settings/services'),
        apiFetch('/settings/mode'),
      ]);
      setServices(svcData.services);
      setSummary(svcData.summary);
      setModeStatus(modeData);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // ── Service actions ─────────────────────────────────────────────────────

  const handleToggle = async (serviceId: string, enabled: boolean) => {
    try {
      await apiFetch(`/settings/services/${serviceId}/${enabled ? 'enable' : 'disable'}`, { method: 'POST' });
      setServices(prev => prev.map(s => s.id === serviceId ? { ...s, enabled, operational: enabled && (s.works_without_key || s.key_status === 'configured') } : s));
      notify('success', `${enabled ? 'Enabled' : 'Disabled'} service`);
    } catch (e: any) {
      notify('error', e.message);
    }
  };

  const handleSaveKey = async (serviceId: string, key: string) => {
    const data = await apiFetch(`/settings/services/${serviceId}/key`, {
      method: 'POST',
      body: JSON.stringify({ api_key: key }),
    });
    if (!data.ok) throw new Error(data.error);
    // Refresh that service in state
    setServices(prev => prev.map(s => s.id === serviceId
      ? { ...s, enabled: true, key_status: 'configured', key_preview: data.key_preview, operational: true }
      : s));
    notify('success', 'API key saved and service enabled');
  };

  const handleDeleteKey = async (serviceId: string) => {
    const data = await apiFetch(`/settings/services/${serviceId}/key`, { method: 'DELETE' });
    if (!data.ok) throw new Error(data.error);
    setServices(prev => prev.map(s => s.id === serviceId
      ? { ...s, key_status: 'missing', key_preview: null, enabled: !data.auto_disabled && s.enabled, operational: false }
      : s));
    notify('success', 'API key removed');
  };

  const handleTestKey = async (serviceId: string, key?: string): Promise<TestResult> => {
    try {
      const body = key ? { api_key: key } : {};
      const data = await apiFetch(`/settings/services/${serviceId}/test`, {
        method: 'POST',
        body: JSON.stringify(body),
      });
      return data;
    } catch (e: any) {
      return { ok: false, message: e.message };
    }
  };

  const handleModeSwitch = async (mode: 'demo' | 'live') => {
    try {
      const data = await apiFetch('/settings/mode', {
        method: 'POST',
        body: JSON.stringify({ mode }),
      });
      setModeStatus(prev => prev ? { ...prev, current_mode: data.mode } : prev);
      notify('success', data.message);
    } catch (e: any) {
      notify('error', e.message);
    }
  };

  // ── Filtering ───────────────────────────────────────────────────────────

  const categories = ['all', ...Array.from(new Set(services.map(s => s.category)))];
  const tiers = ['all', 'free', 'freemium', 'paid'];

  const filtered = services.filter(s => {
    if (catFilter !== 'all' && s.category !== catFilter) return false;
    if (tierFilter !== 'all' && s.tier !== tierFilter) return false;
    return true;
  });

  // ── Computed stats ──────────────────────────────────────────────────────

  const freeCount = services.filter(s => s.tier === 'free' || s.works_without_key).length;
  const operationalCount = services.filter(s => s.operational).length;

  // ── Render ──────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: 400, gap: 2 }}>
        <CircularProgress sx={{ color: cyberColors.neon.cyan }} />
        <Typography sx={{ color: cyberColors.text.secondary }}>Loading service configuration…</Typography>
      </Box>
    );
  }

  if (error) {
    return (
      <PageContainer variants={pageVariants} initial="initial" animate="animate">
        <Alert severity="error" sx={{ mt: 4 }}>
          <AlertTitle>Failed to load settings</AlertTitle>
          {error} — make sure the backend is running.
        </Alert>
      </PageContainer>
    );
  }

  const isDemo = modeStatus?.current_mode === 'demo';
  const isLive = modeStatus?.current_mode === 'production';

  return (
    <PageContainer variants={pageVariants} initial="initial" animate="animate">
      {/* Page header */}
      <PageTitle>Platform Configuration</PageTitle>
      <PageSubtitle>
        Enable intelligence services, add API keys, and choose your operating mode.
        The platform works out of the box with free services — API keys are optional.
      </PageSubtitle>

      {/* Floating notification */}
      <AnimatePresence>
        {notification && (
          <motion.div
            initial={{ opacity: 0, y: -12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -12 }}
            style={{ position: 'fixed', top: 80, right: 24, zIndex: 9999, maxWidth: 360 }}
          >
            <Alert
              severity={notification.type}
              icon={notification.type === 'success' ? <DoneIcon /> : <ErrorIcon />}
              sx={{
                backgroundColor: alpha(notification.type === 'success' ? cyberColors.neon.green : cyberColors.neon.red, 0.12),
                border: `1px solid ${alpha(notification.type === 'success' ? cyberColors.neon.green : cyberColors.neon.red, 0.4)}`,
                color: cyberColors.text.primary,
                borderRadius: 2,
              }}
            >
              {notification.msg}
            </Alert>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Status summary bar */}
      {summary && (
        <GlassCard sx={{ display: 'flex', gap: 3, flexWrap: 'wrap', alignItems: 'center', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Box sx={{ width: 10, height: 10, borderRadius: '50%', backgroundColor: isDemo ? cyberColors.neon.orange : cyberColors.neon.green }} />
            <Typography sx={{ fontSize: '0.85rem', color: cyberColors.text.primary, fontWeight: 600 }}>
              {isDemo ? 'Demo Mode' : 'Live Mode'}
            </Typography>
          </Box>
          <Divider orientation="vertical" flexItem sx={{ borderColor: alpha(cyberColors.neon.cyan, 0.15) }} />
          <Typography sx={{ fontSize: '0.83rem', color: cyberColors.text.secondary }}>
            <span style={{ color: cyberColors.neon.green, fontWeight: 700 }}>{operationalCount}</span> of {summary.total} services operational
          </Typography>
          <Divider orientation="vertical" flexItem sx={{ borderColor: alpha(cyberColors.neon.cyan, 0.15) }} />
          <Typography sx={{ fontSize: '0.83rem', color: cyberColors.text.secondary }}>
            <span style={{ color: cyberColors.neon.cyan, fontWeight: 700 }}>{freeCount}</span> services available free (no key needed)
          </Typography>
          {summary.needs_key > 0 && (
            <>
              <Divider orientation="vertical" flexItem sx={{ borderColor: alpha(cyberColors.neon.cyan, 0.15) }} />
              <Typography sx={{ fontSize: '0.83rem', color: cyberColors.neon.orange }}>
                {summary.needs_key} enabled service{summary.needs_key > 1 ? 's' : ''} need{summary.needs_key === 1 ? 's' : ''} an API key
              </Typography>
            </>
          )}
        </GlassCard>
      )}

      {/* Tabs */}
      <Tabs
        value={tab}
        onChange={(_, v) => setTab(v)}
        sx={{
          mb: 3,
          '& .MuiTab-root': { color: cyberColors.text.secondary, textTransform: 'none', fontSize: '0.9rem' },
          '& .Mui-selected': { color: `${cyberColors.neon.cyan} !important` },
          '& .MuiTabs-indicator': { backgroundColor: cyberColors.neon.cyan },
        }}
      >
        <Tab label="Intelligence Services" />
        <Tab label="Mode & General" />
      </Tabs>

      {/* ── TAB 0: Services ─────────────────────────────────────────────── */}
      {tab === 0 && (
        <Box>
          {/* Free-first info banner */}
          <Alert
            severity="info"
            icon={<CheckCircleIcon sx={{ color: cyberColors.neon.green }} />}
            sx={{
              mb: 3,
              backgroundColor: alpha(cyberColors.neon.green, 0.06),
              border: `1px solid ${alpha(cyberColors.neon.green, 0.25)}`,
              color: cyberColors.text.primary,
              borderRadius: 2,
              '& .MuiAlert-message': { width: '100%' },
            }}
          >
            <AlertTitle sx={{ color: cyberColors.neon.green, fontWeight: 700, fontSize: '0.9rem' }}>
              Works out of the box — no API keys required
            </AlertTitle>
            DNS lookups, WHOIS, certificate transparency, IP geolocation, MalwareBazaar, and ThreatFox are all
            free and active right now. Add optional API keys below to unlock more data sources like VirusTotal,
            AbuseIPDB, or AI-powered analysis.
          </Alert>

          {/* Filter chips */}
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 3 }}>
            <Typography sx={{ color: cyberColors.text.muted, fontSize: '0.78rem', alignSelf: 'center', mr: 0.5 }}>
              Category:
            </Typography>
            {categories.map(cat => (
              <CategoryChip
                key={cat}
                label={cat === 'all' ? 'All' : cat.charAt(0).toUpperCase() + cat.slice(1)}
                icon={cat !== 'all' ? (categoryIcons[cat] as any) : undefined}
                onClick={() => setCatFilter(cat)}
                variant={catFilter === cat ? 'filled' : 'outlined'}
                sx={{
                  color: catFilter === cat ? '#000' : (cat !== 'all' ? categoryColors[cat] : cyberColors.text.secondary),
                  backgroundColor: catFilter === cat ? (cat !== 'all' ? categoryColors[cat] : cyberColors.neon.cyan) : 'transparent',
                  borderColor: cat !== 'all' ? categoryColors[cat] : alpha(cyberColors.text.secondary, 0.3),
                }}
              />
            ))}

            <Divider orientation="vertical" flexItem sx={{ borderColor: alpha(cyberColors.neon.cyan, 0.15), mx: 1 }} />

            <Typography sx={{ color: cyberColors.text.muted, fontSize: '0.78rem', alignSelf: 'center', mr: 0.5 }}>
              Tier:
            </Typography>
            {tiers.map(tier => (
              <CategoryChip
                key={tier}
                label={tier === 'all' ? 'All' : tier.charAt(0).toUpperCase() + tier.slice(1)}
                onClick={() => setTierFilter(tier)}
                variant={tierFilter === tier ? 'filled' : 'outlined'}
                sx={{
                  color: tierFilter === tier ? '#000' : cyberColors.text.secondary,
                  backgroundColor: tierFilter === tier ? cyberColors.neon.cyan : 'transparent',
                  borderColor: alpha(cyberColors.text.secondary, 0.3),
                }}
              />
            ))}
          </Box>

          {/* Services grouped */}
          {['free', 'freemium', 'paid'].map(tier => {
            const tierServices = filtered.filter(s => s.tier === tier);
            if (!tierServices.length) return null;

            const tierConfig = {
              free: { label: 'Free — No API Key Needed', color: cyberColors.neon.green },
              freemium: { label: 'Free Tier Available — Get a Free API Key', color: cyberColors.neon.cyan },
              paid: { label: 'Optional Premium Services', color: cyberColors.neon.orange },
            }[tier as 'free' | 'freemium' | 'paid'];

            return (
              <Box key={tier}>
                <SectionTitle sx={{ color: tierConfig.color }}>{tierConfig.label}</SectionTitle>
                {tierServices.map(svc => (
                  <ServiceRow
                    key={svc.id}
                    service={svc}
                    onToggle={handleToggle}
                    onSaveKey={handleSaveKey}
                    onDeleteKey={handleDeleteKey}
                    onTestKey={handleTestKey}
                  />
                ))}
              </Box>
            );
          })}

          {filtered.length === 0 && (
            <Box sx={{ textAlign: 'center', py: 6 }}>
              <Typography sx={{ color: cyberColors.text.muted }}>No services match the selected filters.</Typography>
            </Box>
          )}
        </Box>
      )}

      {/* ── TAB 1: Mode & General ──────────────────────────────────────── */}
      {tab === 1 && (
        <Box>
          <SectionTitle sx={{ mt: 0 }}>Operating Mode</SectionTitle>

          <Alert severity="info" sx={{
            mb: 3, borderRadius: 2,
            backgroundColor: alpha(cyberColors.neon.electricBlue, 0.07),
            border: `1px solid ${alpha(cyberColors.neon.electricBlue, 0.25)}`,
            color: cyberColors.text.secondary, fontSize: '0.85rem',
          }}>
            <strong style={{ color: cyberColors.text.primary }}>Demo mode</strong> uses realistic synthetic
            data so you can explore the platform without making any real API calls.
            Switch to <strong style={{ color: cyberColors.text.primary }}>Live mode</strong> when you're ready
            to run real investigations.
          </Alert>

          <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
            {/* Demo mode card */}
            <ModeToggleCard
              sx={{ flex: '1 1 280px' }}
              active={isDemo}
              modecolor={cyberColors.neon.orange}
              onClick={() => handleModeSwitch('demo')}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
                <DemoIcon sx={{ color: cyberColors.neon.orange, fontSize: 28 }} />
                <Box>
                  <Typography sx={{ fontWeight: 700, color: cyberColors.text.primary, fontSize: '1rem' }}>
                    Demo Mode
                  </Typography>
                  {isDemo && (
                    <Chip label="ACTIVE" size="small" sx={{
                      height: 18, fontSize: '0.65rem', fontWeight: 700,
                      backgroundColor: alpha(cyberColors.neon.orange, 0.15),
                      color: cyberColors.neon.orange, border: `1px solid ${alpha(cyberColors.neon.orange, 0.4)}`,
                      '& .MuiChip-label': { px: 0.8 },
                    }} />
                  )}
                </Box>
              </Box>
              <Typography sx={{ color: cyberColors.text.secondary, fontSize: '0.83rem', lineHeight: 1.5 }}>
                All data is synthetic. Safe to explore — no API credits consumed, no external calls made.
                Great for evaluation and testing.
              </Typography>
              <Box sx={{ mt: 1.5 }}>
                {['No API keys required', 'Realistic sample investigations', 'Full UI exploration', 'No rate limits'].map(f => (
                  <Box key={f} sx={{ display: 'flex', alignItems: 'center', gap: 0.8, mb: 0.5 }}>
                    <CheckCircleIcon sx={{ fontSize: 14, color: cyberColors.neon.green }} />
                    <Typography sx={{ fontSize: '0.78rem', color: cyberColors.text.secondary }}>{f}</Typography>
                  </Box>
                ))}
              </Box>
            </ModeToggleCard>

            {/* Live mode card */}
            <ModeToggleCard
              sx={{ flex: '1 1 280px' }}
              active={isLive}
              modecolor={cyberColors.neon.green}
              onClick={() => handleModeSwitch('live')}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
                <LiveIcon sx={{ color: cyberColors.neon.green, fontSize: 28 }} />
                <Box>
                  <Typography sx={{ fontWeight: 700, color: cyberColors.text.primary, fontSize: '1rem' }}>
                    Live Mode
                  </Typography>
                  {isLive && (
                    <Chip label="ACTIVE" size="small" sx={{
                      height: 18, fontSize: '0.65rem', fontWeight: 700,
                      backgroundColor: alpha(cyberColors.neon.green, 0.15),
                      color: cyberColors.neon.green, border: `1px solid ${alpha(cyberColors.neon.green, 0.4)}`,
                      '& .MuiChip-label': { px: 0.8 },
                    }} />
                  )}
                </Box>
              </Box>
              <Typography sx={{ color: cyberColors.text.secondary, fontSize: '0.83rem', lineHeight: 1.5 }}>
                Real intelligence gathering using enabled services. Free services work immediately.
                Add API keys on the Services tab to unlock more data sources.
              </Typography>
              <Box sx={{ mt: 1.5 }}>
                {[
                  'Real DNS, WHOIS, cert data (always free)',
                  'Optional: VirusTotal, AbuseIPDB, etc.',
                  'Optional: OpenAI for AI summaries',
                  'All configured API keys active',
                ].map(f => (
                  <Box key={f} sx={{ display: 'flex', alignItems: 'center', gap: 0.8, mb: 0.5 }}>
                    <CheckCircleIcon sx={{ fontSize: 14, color: cyberColors.neon.green }} />
                    <Typography sx={{ fontSize: '0.78rem', color: cyberColors.text.secondary }}>{f}</Typography>
                  </Box>
                ))}
              </Box>
            </ModeToggleCard>
          </Box>

          {/* Mode info */}
          {modeStatus?.last_mode_switch && (
            <Typography sx={{ mt: 2, color: cyberColors.text.muted, fontSize: '0.78rem' }}>
              Last switched: {new Date(modeStatus.last_mode_switch).toLocaleString()}
            </Typography>
          )}

          <SectionTitle sx={{ mt: 4 }}>Quick Start Guide</SectionTitle>
          <GlassCard>
            {[
              {
                step: '1', color: cyberColors.neon.green,
                title: 'Explore in Demo Mode',
                desc: 'The platform starts in Demo Mode with sample data. Try creating an investigation and reviewing the results without any setup.',
              },
              {
                step: '2', color: cyberColors.neon.cyan,
                title: 'Add Free API Keys (Optional)',
                desc: 'VirusTotal, AbuseIPDB, and AlienVault OTX all have free tiers that significantly expand your intelligence gathering. Sign up takes under 2 minutes.',
              },
              {
                step: '3', color: cyberColors.neon.magenta,
                title: 'Switch to Live Mode',
                desc: 'Once you\'ve added your optional keys, flip to Live Mode. Free services (DNS, WHOIS, crt.sh) will immediately start returning real data — even with no keys.',
              },
              {
                step: '4', color: cyberColors.neon.orange,
                title: 'Add OpenAI for AI Summaries (Optional)',
                desc: 'Adding an OpenAI key enables AI-powered threat profiles and executive summaries. At ~$0.01–0.03 per investigation it\'s very affordable.',
              },
            ].map((item, i) => (
              <Box key={i} sx={{ display: 'flex', gap: 2, mb: i < 3 ? 2 : 0 }}>
                <Box sx={{
                  width: 32, height: 32, borderRadius: '50%', flexShrink: 0,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  backgroundColor: alpha(item.color, 0.15),
                  border: `1px solid ${alpha(item.color, 0.4)}`,
                  color: item.color, fontWeight: 700, fontSize: '0.85rem',
                }}>
                  {item.step}
                </Box>
                <Box>
                  <Typography sx={{ fontWeight: 600, color: cyberColors.text.primary, fontSize: '0.9rem', mb: 0.3 }}>
                    {item.title}
                  </Typography>
                  <Typography sx={{ color: cyberColors.text.secondary, fontSize: '0.82rem', lineHeight: 1.5 }}>
                    {item.desc}
                  </Typography>
                </Box>
                {i < 3 && <Divider sx={{ display: 'none' }} />}
              </Box>
            ))}
          </GlassCard>
        </Box>
      )}
    </PageContainer>
  );
}
