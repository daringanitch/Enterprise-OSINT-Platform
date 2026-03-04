/**
 * EnrichmentPanel — "Investigate This" unified IOC enrichment timeline
 *
 * Connects to GET /api/enrich via Server-Sent Events and renders a live
 * progress feed as each intelligence source resolves. Each source card
 * transitions through: queued → loading → success/error/timeout.
 *
 * Usage:
 *   <EnrichmentPanel value="malware-c2.net" type="domain" />
 *
 * Embed anywhere — investigation detail page, command palette shortcut,
 * right-click context menu on an EntityChip, new investigation wizard.
 */

import React, {
  useState,
  useEffect,
  useRef,
  useCallback,
  useMemo,
} from 'react';
import {
  Box,
  Typography,
  LinearProgress,
  Chip,
  IconButton,
  Tooltip,
  Collapse,
  styled,
} from '@mui/material';
import DnsIcon from '@mui/icons-material/Dns';
import SecurityIcon from '@mui/icons-material/Security';
import PeopleIcon from '@mui/icons-material/People';
import PsychologyIcon from '@mui/icons-material/Psychology';
import AccountBalanceIcon from '@mui/icons-material/AccountBalance';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import HourglassEmptyIcon from '@mui/icons-material/HourglassEmpty';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import StopIcon from '@mui/icons-material/Stop';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import { cyberColors, designTokens, glassmorphism } from '../../utils/theme';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:5001';

// ─── Icon map ─────────────────────────────────────────────────────────────────

const SOURCE_ICONS: Record<string, React.ElementType> = {
  dns: DnsIcon,
  security: SecurityIcon,
  people: PeopleIcon,
  psychology: PsychologyIcon,
  account_balance: AccountBalanceIcon,
};

// ─── Types ────────────────────────────────────────────────────────────────────

type SourceStatus = 'queued' | 'loading' | 'success' | 'error' | 'timeout';

interface SourceState {
  id: string;
  label: string;
  icon: string;
  description: string;
  status: SourceStatus;
  findings: unknown[];
  confidence: number;
  risk_score: number;
  summary: string;
  duration_ms?: number;
  error?: string;
  expanded: boolean;
}

interface Summary {
  value: string;
  type: string;
  total_findings: number;
  max_risk: number;
  sources_queried: number;
  sources_successful: number;
  threat_categories: string[];
  duration_ms: number;
  timestamp: string;
}

// ─── Styled ───────────────────────────────────────────────────────────────────

const PanelRoot = styled(Box)({
  display: 'flex',
  flexDirection: 'column',
  gap: 0,
});

const PanelHeader = styled(Box)({
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  marginBottom: 16,
});

const SourceCard = styled(Box)<{ status: SourceStatus }>(({ status }) => {
  const borderColor = {
    queued: `${cyberColors.dark.steel}40`,
    loading: `${cyberColors.neon.cyan}50`,
    success: `${cyberColors.neon.green}40`,
    error: `${cyberColors.neon.red}40`,
    timeout: `${cyberColors.neon.orange}40`,
  }[status];

  return {
    ...glassmorphism.card,
    border: `1px solid ${borderColor}`,
    borderRadius: 10,
    padding: '12px 16px',
    marginBottom: 8,
    transition: 'border-color 0.3s ease, box-shadow 0.3s ease',
    ...(status === 'loading' && {
      boxShadow: `0 0 12px ${cyberColors.neon.cyan}15`,
    }),
    ...(status === 'success' && {
      boxShadow: `0 0 8px ${cyberColors.neon.green}10`,
    }),
  };
});

const StatusIcon: React.FC<{ status: SourceStatus; size?: number }> = ({ status, size = 18 }) => {
  const sx = { fontSize: size };
  switch (status) {
    case 'success': return <CheckCircleIcon sx={{ ...sx, color: cyberColors.neon.green }} />;
    case 'error':   return <ErrorIcon sx={{ ...sx, color: cyberColors.neon.red }} />;
    case 'timeout': return <ErrorIcon sx={{ ...sx, color: cyberColors.neon.orange }} />;
    case 'loading': return <HourglassEmptyIcon sx={{ ...sx, color: cyberColors.neon.cyan, animation: 'spin 1.4s linear infinite' }} />;
    default:        return <HourglassEmptyIcon sx={{ ...sx, color: cyberColors.text.muted }} />;
  }
};

const RiskBadge = styled(Chip)<{ risk: number }>(({ risk }) => {
  const color = risk >= 8 ? cyberColors.neon.red
    : risk >= 6 ? cyberColors.neon.orange
    : risk >= 4 ? '#F59E0B'
    : risk >= 2 ? cyberColors.neon.cyan
    : cyberColors.neon.green;
  return {
    height: 20,
    fontSize: '0.65rem',
    fontWeight: 700,
    backgroundColor: `${color}18`,
    color,
    border: `1px solid ${color}35`,
  };
});

const SummaryBox = styled(Box)({
  ...glassmorphism.card,
  borderRadius: 10,
  padding: '16px',
  border: `1px solid ${cyberColors.neon.cyan}30`,
  boxShadow: `0 0 20px ${cyberColors.neon.cyan}10`,
  marginTop: 8,
});

// ─── Component ────────────────────────────────────────────────────────────────

export interface EnrichmentPanelProps {
  value: string;
  type: string;
  /** Auto-start on mount */
  autoStart?: boolean;
  /** Called when enrichment completes */
  onComplete?: (summary: Summary) => void;
}

export const EnrichmentPanel: React.FC<EnrichmentPanelProps> = ({
  value,
  type,
  autoStart = true,
  onComplete,
}) => {
  const [sources, setSources] = useState<SourceState[]>([]);
  const [running, setRunning] = useState(false);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [globalProgress, setGlobalProgress] = useState(0);
  const esRef = useRef<EventSource | null>(null);

  const stop = useCallback(() => {
    esRef.current?.close();
    esRef.current = null;
    setRunning(false);
    setSources((prev) =>
      prev.map((s) => s.status === 'loading' ? { ...s, status: 'error', error: 'Cancelled' } : s),
    );
  }, []);

  const start = useCallback(() => {
    if (!value || !type) return;
    setSources([]);
    setSummary(null);
    setGlobalProgress(0);
    setRunning(true);

    const url = `${API_BASE}/api/enrich?value=${encodeURIComponent(value)}&type=${encodeURIComponent(type)}`;
    const token = localStorage.getItem('auth_token');
    // EventSource doesn't support custom headers — use a fetch-based SSE reader
    const ctrl = new AbortController();

    fetch(url, {
      headers: {
        Accept: 'text/event-stream',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      signal: ctrl.signal,
    })
      .then(async (res) => {
        if (!res.body) return;
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value: chunk } = await reader.read();
          if (done) break;
          buffer += decoder.decode(chunk, { stream: true });

          // Parse SSE frames
          const frames = buffer.split('\n\n');
          buffer = frames.pop() || '';

          for (const frame of frames) {
            const lines = frame.split('\n');
            let eventType = 'message';
            let dataStr = '';
            for (const line of lines) {
              if (line.startsWith('event: ')) eventType = line.slice(7).trim();
              if (line.startsWith('data: ')) dataStr = line.slice(6).trim();
            }
            if (!dataStr) continue;

            try {
              const data = JSON.parse(dataStr);
              handleSSEEvent(eventType, data);
            } catch {
              // malformed frame
            }
          }
        }
        setRunning(false);
      })
      .catch((err) => {
        if (err.name !== 'AbortError') {
          setRunning(false);
        }
      });

    // Store abort controller for stop()
    esRef.current = { close: () => ctrl.abort() } as EventSource;
  }, [value, type]);

  const handleSSEEvent = useCallback((event: string, data: Record<string, unknown>) => {
    switch (event) {
      case 'source_start':
        setSources((prev) => [
          ...prev,
          {
            id: data.source as string,
            label: data.label as string,
            icon: data.icon as string,
            description: data.description as string,
            status: 'loading',
            findings: [],
            confidence: 0,
            risk_score: 0,
            summary: '',
            expanded: false,
          },
        ]);
        break;

      case 'source_result':
        setSources((prev) => {
          const updated = prev.map((s) =>
            s.id === data.source
              ? {
                  ...s,
                  status: 'success' as SourceStatus,
                  findings: (data.findings as unknown[]) || [],
                  confidence: (data.confidence as number) || 0,
                  risk_score: (data.risk_score as number) || 0,
                  summary: (data.summary as string) || '',
                  duration_ms: data.duration_ms as number,
                }
              : s,
          );
          const done = updated.filter((s) => s.status !== 'loading' && s.status !== 'queued').length;
          setGlobalProgress((done / updated.length) * 100);
          return updated;
        });
        break;

      case 'source_error':
        setSources((prev) =>
          prev.map((s) =>
            s.id === data.source
              ? {
                  ...s,
                  status: (data.status as SourceStatus) || 'error',
                  error: data.error as string,
                  duration_ms: data.duration_ms as number,
                }
              : s,
          ),
        );
        break;

      case 'summary':
        setSummary(data as unknown as Summary);
        setGlobalProgress(100);
        onComplete?.(data as unknown as Summary);
        break;

      case 'done':
        setRunning(false);
        break;
    }
  }, [onComplete]);

  useEffect(() => {
    if (autoStart && value && type) start();
    return () => esRef.current?.close();
  }, [value, type]); // eslint-disable-line react-hooks/exhaustive-deps

  const toggleExpand = useCallback((id: string) => {
    setSources((prev) => prev.map((s) => s.id === id ? { ...s, expanded: !s.expanded } : s));
  }, []);

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <PanelRoot>
      {/* Header */}
      <PanelHeader>
        <Box>
          <Typography
            sx={{ fontFamily: designTokens.typography.fontFamily.mono, color: cyberColors.neon.cyan, fontWeight: 600, fontSize: '1.05rem' }}
          >
            {value}
          </Typography>
          <Typography sx={{ fontSize: '0.72rem', color: cyberColors.text.muted }}>
            {type.replace('_', ' ')} · fan-out enrichment
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
          {running && (
            <Typography sx={{ fontSize: '0.72rem', color: cyberColors.neon.cyan, animation: 'pulse 1.5s infinite' }}>
              Enriching…
            </Typography>
          )}
          {running ? (
            <Tooltip title="Stop enrichment">
              <IconButton size="small" onClick={stop} sx={{ color: cyberColors.neon.red }}>
                <StopIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          ) : (
            <Tooltip title="Re-run enrichment">
              <IconButton size="small" onClick={start} sx={{ color: cyberColors.neon.cyan }}>
                <PlayArrowIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          )}
        </Box>
      </PanelHeader>

      {/* Global progress */}
      {(running || globalProgress > 0) && (
        <Box sx={{ mb: 2 }}>
          <LinearProgress
            variant={running && sources.length === 0 ? 'indeterminate' : 'determinate'}
            value={globalProgress}
            sx={{
              height: 3,
              borderRadius: 2,
              backgroundColor: `${cyberColors.neon.cyan}15`,
              '& .MuiLinearProgress-bar': { backgroundColor: cyberColors.neon.cyan },
            }}
          />
          <Typography sx={{ fontSize: '0.65rem', color: cyberColors.text.muted, mt: 0.5 }}>
            {Math.round(globalProgress)}% · {sources.filter((s) => s.status === 'success').length}/{sources.length} sources
          </Typography>
        </Box>
      )}

      {/* Source cards */}
      {sources.map((src) => {
        const IconComponent = SOURCE_ICONS[src.icon] || SecurityIcon;
        return (
          <SourceCard key={src.id} status={src.status}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
              <Box
                sx={{
                  width: 34, height: 34, borderRadius: 8, flexShrink: 0,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  backgroundColor: `${cyberColors.neon.cyan}10`,
                  color: cyberColors.neon.cyan,
                }}
              >
                <IconComponent sx={{ fontSize: '1.1rem' }} />
              </Box>

              <Box sx={{ flex: 1, minWidth: 0 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Typography sx={{ fontSize: '0.85rem', fontWeight: 600, color: cyberColors.text.primary }}>
                    {src.label}
                  </Typography>
                  {src.status === 'loading' && (
                    <LinearProgress sx={{ width: 60, height: 2, borderRadius: 1, backgroundColor: `${cyberColors.neon.cyan}20`, '& .MuiLinearProgress-bar': { backgroundColor: cyberColors.neon.cyan } }} />
                  )}
                  {src.status === 'success' && src.risk_score > 0 && (
                    <RiskBadge risk={src.risk_score} label={`Risk ${src.risk_score.toFixed(1)}`} size="small" />
                  )}
                  {(src.status === 'error' || src.status === 'timeout') && (
                    <Chip
                      size="small"
                      label={src.status}
                      sx={{ height: 18, fontSize: '0.62rem', backgroundColor: `${cyberColors.neon.red}15`, color: cyberColors.neon.red }}
                    />
                  )}
                </Box>
                <Typography sx={{ fontSize: '0.7rem', color: cyberColors.text.muted }}>
                  {src.status === 'success'
                    ? `${src.findings.length} findings · ${src.duration_ms}ms`
                    : src.status === 'loading'
                    ? 'Querying…'
                    : src.error || src.description}
                </Typography>
              </Box>

              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, flexShrink: 0 }}>
                <StatusIcon status={src.status} />
                {src.status === 'success' && src.findings.length > 0 && (
                  <IconButton size="small" onClick={() => toggleExpand(src.id)} sx={{ color: cyberColors.text.muted, p: 0.25 }}>
                    {src.expanded ? <ExpandLessIcon sx={{ fontSize: '1rem' }} /> : <ExpandMoreIcon sx={{ fontSize: '1rem' }} />}
                  </IconButton>
                )}
              </Box>
            </Box>

            {/* Expanded findings */}
            <Collapse in={src.expanded}>
              <Box sx={{ mt: 1.5, pt: 1.5, borderTop: `1px solid ${cyberColors.dark.steel}40` }}>
                {src.summary && (
                  <Typography sx={{ fontSize: '0.78rem', color: cyberColors.text.secondary, mb: 1 }}>
                    {src.summary}
                  </Typography>
                )}
                {(src.findings as Array<{ type?: string; value?: string; description?: string; severity?: string }>).slice(0, 5).map((f, i) => (
                  <Box
                    key={i}
                    sx={{
                      display: 'flex', gap: 1, alignItems: 'flex-start',
                      mb: 0.75, pb: 0.75,
                      borderBottom: i < Math.min(src.findings.length, 5) - 1 ? `1px solid ${cyberColors.dark.steel}30` : 'none',
                    }}
                  >
                    <Box sx={{ width: 6, height: 6, borderRadius: '50%', mt: '5px', flexShrink: 0, backgroundColor: f.severity === 'critical' ? cyberColors.neon.red : f.severity === 'high' ? cyberColors.neon.orange : cyberColors.neon.cyan }} />
                    <Box>
                      {f.value && (
                        <Typography sx={{ fontSize: '0.75rem', fontFamily: designTokens.typography.fontFamily.mono, color: cyberColors.neon.cyan }}>
                          {f.value}
                        </Typography>
                      )}
                      {f.description && (
                        <Typography sx={{ fontSize: '0.72rem', color: cyberColors.text.secondary }}>
                          {f.description}
                        </Typography>
                      )}
                    </Box>
                  </Box>
                ))}
                {src.findings.length > 5 && (
                  <Typography sx={{ fontSize: '0.7rem', color: cyberColors.text.muted, fontStyle: 'italic' }}>
                    +{src.findings.length - 5} more findings
                  </Typography>
                )}
              </Box>
            </Collapse>
          </SourceCard>
        );
      })}

      {/* Summary card */}
      {summary && (
        <SummaryBox>
          <Typography sx={{ fontSize: '0.72rem', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: cyberColors.text.muted, mb: 1 }}>
            Enrichment Summary
          </Typography>
          <Box sx={{ display: 'flex', gap: 3, flexWrap: 'wrap', mb: 1 }}>
            <Box>
              <Typography sx={{ fontSize: '1.4rem', fontWeight: 700, color: cyberColors.text.primary, fontFamily: designTokens.typography.fontFamily.mono }}>
                {summary.total_findings}
              </Typography>
              <Typography sx={{ fontSize: '0.7rem', color: cyberColors.text.muted }}>findings</Typography>
            </Box>
            <Box>
              <Typography sx={{ fontSize: '1.4rem', fontWeight: 700, color: summary.max_risk >= 7 ? cyberColors.neon.red : summary.max_risk >= 4 ? cyberColors.neon.orange : cyberColors.neon.green, fontFamily: designTokens.typography.fontFamily.mono }}>
                {summary.max_risk.toFixed(1)}
              </Typography>
              <Typography sx={{ fontSize: '0.7rem', color: cyberColors.text.muted }}>max risk</Typography>
            </Box>
            <Box>
              <Typography sx={{ fontSize: '1.4rem', fontWeight: 700, color: cyberColors.neon.cyan, fontFamily: designTokens.typography.fontFamily.mono }}>
                {summary.sources_successful}/{summary.sources_queried}
              </Typography>
              <Typography sx={{ fontSize: '0.7rem', color: cyberColors.text.muted }}>sources</Typography>
            </Box>
            <Box>
              <Typography sx={{ fontSize: '1.4rem', fontWeight: 700, color: cyberColors.text.secondary, fontFamily: designTokens.typography.fontFamily.mono }}>
                {(summary.duration_ms / 1000).toFixed(1)}s
              </Typography>
              <Typography sx={{ fontSize: '0.7rem', color: cyberColors.text.muted }}>elapsed</Typography>
            </Box>
          </Box>
          {summary.threat_categories.length > 0 && (
            <Box sx={{ display: 'flex', gap: 0.75, flexWrap: 'wrap' }}>
              {summary.threat_categories.map((cat) => (
                <Chip
                  key={cat}
                  label={cat}
                  size="small"
                  sx={{
                    height: 20, fontSize: '0.65rem',
                    backgroundColor: `${cyberColors.neon.red}12`,
                    color: cyberColors.neon.red,
                    border: `1px solid ${cyberColors.neon.red}25`,
                  }}
                />
              ))}
            </Box>
          )}
        </SummaryBox>
      )}

      {/* Spin keyframe */}
      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }
      `}</style>
    </PanelRoot>
  );
};

export default EnrichmentPanel;
