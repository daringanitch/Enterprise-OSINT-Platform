/**
 * EvidenceChain
 *
 * Visual attribution chain for intelligence findings:
 *   Source → Raw Finding → Inference → Conclusion
 *
 * Each node shows:
 *  - Source label + icon (VirusTotal, Shodan, DNS, etc.)
 *  - Collection timestamp + FreshnessIndicator
 *  - Confidence score as a colored progress bar
 *  - The specific value or text that was observed
 *
 * An overall "chain confidence" is computed as the geometric mean of all
 * node confidences — so a single weak link degrades the whole chain,
 * which is the correct epistemics for intelligence analysis.
 *
 * Usage:
 *   <EvidenceChain nodes={finding.evidence_chain} conclusion={finding.conclusion} />
 */

import React, { useMemo, useState } from 'react';
import {
  Box,
  Typography,
  LinearProgress,
  Chip,
  Tooltip,
  Collapse,
  IconButton,
  styled,
} from '@mui/material';
import DnsIcon from '@mui/icons-material/Dns';
import SecurityIcon from '@mui/icons-material/Security';
import AnalyticsIcon from '@mui/icons-material/Analytics';
import PsychologyIcon from '@mui/icons-material/Psychology';
import LanguageIcon from '@mui/icons-material/Language';
import RouterIcon from '@mui/icons-material/Router';
import FingerprintIcon from '@mui/icons-material/Fingerprint';
import StorageIcon from '@mui/icons-material/Storage';
import BugReportIcon from '@mui/icons-material/BugReport';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import { cyberColors, designTokens, glassmorphism } from '../../utils/theme';
import { FreshnessIndicator } from '../common/FreshnessIndicator';

// ─── Types ────────────────────────────────────────────────────────────────────

export type EvidenceNodeType = 'source' | 'finding' | 'inference' | 'conclusion';

export interface EvidenceNode {
  id: string;
  type: EvidenceNodeType;
  /** Human-readable label for this node, e.g. "VirusTotal Detection" */
  label: string;
  /** The intelligence source, e.g. "virustotal", "shodan", "dns", "ai_analysis" */
  source: string;
  /** The actual value or text observed */
  value: string;
  /** 0–1 confidence for this specific piece of evidence */
  confidence: number;
  /** ISO timestamp of when this was collected */
  collected_at: string | null;
  /** Optional supporting detail (raw JSON, URL, etc.) */
  detail?: string;
  /** Whether this node has been corroborated by another independent source */
  corroborated?: boolean;
}

export interface EvidenceChainProps {
  nodes: EvidenceNode[];
  /** The final conclusion this chain supports */
  conclusion?: string;
  /** Overall assessment written by the analyst or AI */
  assessment?: string;
  /** Compact mode — collapse detail by default */
  compact?: boolean;
  className?: string;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const SOURCE_ICONS: Record<string, React.ElementType> = {
  virustotal: BugReportIcon,
  shodan: RouterIcon,
  dns: DnsIcon,
  whois: LanguageIcon,
  abuseipdb: SecurityIcon,
  ai_analysis: PsychologyIcon,
  correlation: AnalyticsIcon,
  fingerprint: FingerprintIcon,
  database: StorageIcon,
};

const SOURCE_LABELS: Record<string, string> = {
  virustotal: 'VirusTotal',
  shodan: 'Shodan',
  dns: 'DNS',
  whois: 'WHOIS',
  abuseipdb: 'AbuseIPDB',
  otx: 'OTX',
  ai_analysis: 'AI Analysis',
  correlation: 'Correlation Engine',
  manual: 'Analyst Note',
};

const NODE_TYPE_COLORS: Record<EvidenceNodeType, string> = {
  source: cyberColors.neon.cyan,
  finding: cyberColors.neon.green,
  inference: cyberColors.neon.orange,
  conclusion: cyberColors.neon.purple,
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Geometric mean of confidence scores — a single weak link lowers the whole chain.
 * Returns a value in [0, 1].
 */
function chainConfidence(nodes: EvidenceNode[]): number {
  if (nodes.length === 0) return 0;
  const product = nodes.reduce((acc, n) => acc * Math.max(0.01, n.confidence), 1);
  return Math.pow(product, 1 / nodes.length);
}

function confidenceLabel(c: number): { label: string; color: string } {
  if (c >= 0.85) return { label: 'High', color: cyberColors.neon.green };
  if (c >= 0.65) return { label: 'Medium', color: cyberColors.neon.orange };
  if (c >= 0.4)  return { label: 'Low', color: '#F59E0B' };
  return { label: 'Speculative', color: cyberColors.neon.red };
}

// ─── Styled ───────────────────────────────────────────────────────────────────

const ChainRoot = styled(Box)({
  display: 'flex',
  flexDirection: 'column',
  gap: 0,
});

const NodeCard = styled(Box)<{ nodetype: EvidenceNodeType }>(({ nodetype }) => ({
  ...glassmorphism.card,
  borderLeft: `3px solid ${NODE_TYPE_COLORS[nodetype]}`,
  borderRadius: 8,
  padding: '10px 14px',
  position: 'relative',
}));

const Connector = styled(Box)({
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  height: 20,
  color: cyberColors.text.muted,
});

const ConfidenceBar = styled(LinearProgress)<{ conf: number }>(({ conf }) => {
  const color = conf >= 0.85
    ? cyberColors.neon.green
    : conf >= 0.65
    ? cyberColors.neon.orange
    : conf >= 0.4
    ? '#F59E0B'
    : cyberColors.neon.red;
  return {
    height: 3,
    borderRadius: 2,
    marginTop: 6,
    backgroundColor: `${color}20`,
    '& .MuiLinearProgress-bar': { backgroundColor: color },
  };
});

const TypeBadge = styled(Chip)<{ nodetype: EvidenceNodeType }>(({ nodetype }) => ({
  height: 18,
  fontSize: '0.58rem',
  fontWeight: 700,
  textTransform: 'uppercase',
  letterSpacing: '0.06em',
  backgroundColor: `${NODE_TYPE_COLORS[nodetype]}15`,
  color: NODE_TYPE_COLORS[nodetype],
  border: `1px solid ${NODE_TYPE_COLORS[nodetype]}35`,
}));

const SummaryBox = styled(Box)({
  ...glassmorphism.card,
  borderRadius: 10,
  padding: '14px 16px',
  border: `1px solid ${cyberColors.neon.purple}30`,
});

// ─── Sub-component: Evidence Node ─────────────────────────────────────────────

const EvidenceNodeCard: React.FC<{ node: EvidenceNode; index: number }> = ({ node, index }) => {
  const [expanded, setExpanded] = useState(false);
  const SourceIcon = SOURCE_ICONS[node.source] || SecurityIcon;
  const sourceLabel = SOURCE_LABELS[node.source] || node.source;

  return (
    <NodeCard nodetype={node.type}>
      <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1.5 }}>
        {/* Step number */}
        <Box
          sx={{
            width: 24, height: 24, borderRadius: '50%', flexShrink: 0,
            backgroundColor: `${NODE_TYPE_COLORS[node.type]}15`,
            border: `1px solid ${NODE_TYPE_COLORS[node.type]}50`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}
        >
          <Typography sx={{ fontSize: '0.65rem', fontWeight: 700, color: NODE_TYPE_COLORS[node.type] }}>
            {index + 1}
          </Typography>
        </Box>

        <Box sx={{ flex: 1, minWidth: 0 }}>
          {/* Header row */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap', mb: 0.5 }}>
            <TypeBadge label={node.type} nodetype={node.type} size="small" />
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <SourceIcon sx={{ fontSize: '0.75rem', color: cyberColors.text.muted }} />
              <Typography sx={{ fontSize: '0.7rem', color: cyberColors.text.muted }}>
                {sourceLabel}
              </Typography>
            </Box>
            {node.collected_at && (
              <FreshnessIndicator lastSeen={node.collected_at} size="compact" />
            )}
            {node.corroborated && (
              <Tooltip title="Corroborated by an independent source">
                <CheckCircleIcon sx={{ fontSize: '0.8rem', color: cyberColors.neon.green }} />
              </Tooltip>
            )}
          </Box>

          {/* Label */}
          <Typography sx={{ fontSize: '0.82rem', fontWeight: 600, color: cyberColors.text.primary, mb: 0.25 }}>
            {node.label}
          </Typography>

          {/* Value */}
          <Typography
            sx={{
              fontSize: '0.78rem',
              fontFamily: designTokens.typography.fontFamily.mono,
              color: NODE_TYPE_COLORS[node.type],
              backgroundColor: `${NODE_TYPE_COLORS[node.type]}08`,
              borderRadius: 1,
              px: 1, py: 0.25,
              display: 'inline-block',
              maxWidth: '100%',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
            title={node.value}
          >
            {node.value}
          </Typography>

          {/* Confidence bar */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.75 }}>
            <Typography sx={{ fontSize: '0.65rem', color: cyberColors.text.muted, flexShrink: 0 }}>
              Confidence
            </Typography>
            <ConfidenceBar
              variant="determinate"
              value={node.confidence * 100}
              conf={node.confidence}
              sx={{ flex: 1 }}
            />
            <Typography
              sx={{
                fontSize: '0.68rem',
                fontWeight: 700,
                color: confidenceLabel(node.confidence).color,
                flexShrink: 0,
                fontFamily: designTokens.typography.fontFamily.mono,
              }}
            >
              {Math.round(node.confidence * 100)}%
            </Typography>
          </Box>

          {/* Detail (expandable) */}
          {node.detail && (
            <>
              <Box sx={{ display: 'flex', alignItems: 'center', mt: 0.5 }}>
                <IconButton
                  size="small"
                  onClick={() => setExpanded((v) => !v)}
                  sx={{ color: cyberColors.text.muted, p: 0.25 }}
                >
                  {expanded ? <ExpandLessIcon sx={{ fontSize: '0.9rem' }} /> : <ExpandMoreIcon sx={{ fontSize: '0.9rem' }} />}
                </IconButton>
                <Typography sx={{ fontSize: '0.65rem', color: cyberColors.text.muted }}>
                  {expanded ? 'Hide' : 'Show'} raw detail
                </Typography>
              </Box>
              <Collapse in={expanded}>
                <Box
                  sx={{
                    mt: 0.5, p: 1,
                    backgroundColor: `${cyberColors.dark.steel}15`,
                    borderRadius: 1,
                    fontFamily: designTokens.typography.fontFamily.mono,
                    fontSize: '0.68rem',
                    color: cyberColors.text.secondary,
                    overflowX: 'auto',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                    maxHeight: 120,
                    overflowY: 'auto',
                  }}
                >
                  {node.detail}
                </Box>
              </Collapse>
            </>
          )}
        </Box>
      </Box>
    </NodeCard>
  );
};

// ─── Main component ───────────────────────────────────────────────────────────

export const EvidenceChain: React.FC<EvidenceChainProps> = ({
  nodes,
  conclusion,
  assessment,
  compact = false,
  className,
}) => {
  const [showAll, setShowAll] = useState(!compact);
  const chainConf = useMemo(() => chainConfidence(nodes), [nodes]);
  const { label: confLabel, color: confColor } = confidenceLabel(chainConf);

  const visibleNodes = showAll ? nodes : nodes.slice(0, 2);

  if (nodes.length === 0) {
    return (
      <Box sx={{ p: 2, textAlign: 'center' }}>
        <Typography sx={{ fontSize: '0.82rem', color: cyberColors.text.muted, fontStyle: 'italic' }}>
          No evidence chain available for this finding.
        </Typography>
      </Box>
    );
  }

  return (
    <ChainRoot className={className}>
      {/* Chain header */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1.5 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography sx={{ fontSize: '0.72rem', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: cyberColors.text.muted }}>
            Evidence Chain
          </Typography>
          <Chip
            label={`${nodes.length} nodes`}
            size="small"
            sx={{ height: 18, fontSize: '0.62rem', backgroundColor: `${cyberColors.dark.steel}20`, color: cyberColors.text.muted }}
          />
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Tooltip title="Chain confidence: geometric mean of all node confidences. A weak link degrades the whole chain.">
            <InfoOutlinedIcon sx={{ fontSize: '0.85rem', color: cyberColors.text.muted, cursor: 'help' }} />
          </Tooltip>
          <Typography sx={{ fontSize: '0.7rem', fontWeight: 700, color: confColor }}>
            {confLabel} ({Math.round(chainConf * 100)}%)
          </Typography>
          {chainConf < 0.5 && (
            <WarningAmberIcon sx={{ fontSize: '0.85rem', color: cyberColors.neon.orange }} />
          )}
        </Box>
      </Box>

      {/* Chain confidence bar */}
      <ConfidenceBar
        variant="determinate"
        value={chainConf * 100}
        conf={chainConf}
        sx={{ mb: 2, height: 4 }}
      />

      {/* Nodes */}
      {visibleNodes.map((node, i) => (
        <React.Fragment key={node.id}>
          <EvidenceNodeCard node={node} index={i} />
          {i < visibleNodes.length - 1 && (
            <Connector>
              <ArrowForwardIcon sx={{ fontSize: '1rem', transform: 'rotate(90deg)' }} />
            </Connector>
          )}
        </React.Fragment>
      ))}

      {/* Show more / less */}
      {nodes.length > 2 && (
        <Box sx={{ textAlign: 'center', mt: 0.5 }}>
          <Typography
            component="span"
            onClick={() => setShowAll((v) => !v)}
            sx={{
              fontSize: '0.72rem',
              color: cyberColors.neon.cyan,
              cursor: 'pointer',
              '&:hover': { textDecoration: 'underline' },
            }}
          >
            {showAll ? 'Show less' : `Show all ${nodes.length} nodes`}
          </Typography>
        </Box>
      )}

      {/* Conclusion + Assessment */}
      {(conclusion || assessment) && (
        <>
          <Connector>
            <ArrowForwardIcon sx={{ fontSize: '1rem', transform: 'rotate(90deg)', color: cyberColors.neon.purple }} />
          </Connector>
          <SummaryBox>
            {conclusion && (
              <>
                <Typography sx={{ fontSize: '0.65rem', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: cyberColors.neon.purple, mb: 0.5 }}>
                  Conclusion
                </Typography>
                <Typography
                  sx={{
                    fontSize: '0.85rem',
                    fontWeight: 600,
                    color: cyberColors.text.primary,
                    fontFamily: designTokens.typography.fontFamily.mono,
                    backgroundColor: `${cyberColors.neon.purple}08`,
                    borderRadius: 1, px: 1, py: 0.5,
                    mb: assessment ? 1 : 0,
                  }}
                >
                  {conclusion}
                </Typography>
              </>
            )}
            {assessment && (
              <>
                <Typography sx={{ fontSize: '0.65rem', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: cyberColors.text.muted, mb: 0.5 }}>
                  Assessment
                </Typography>
                <Typography sx={{ fontSize: '0.82rem', color: cyberColors.text.secondary, lineHeight: 1.6 }}>
                  {assessment}
                </Typography>
              </>
            )}
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, mt: 1.5 }}>
              <Typography sx={{ fontSize: '0.65rem', color: cyberColors.text.muted }}>
                Chain confidence:
              </Typography>
              <Typography sx={{ fontSize: '0.7rem', fontWeight: 700, color: confColor, fontFamily: designTokens.typography.fontFamily.mono }}>
                {confLabel} ({Math.round(chainConf * 100)}%)
              </Typography>
              {chainConf < 0.5 && (
                <Typography sx={{ fontSize: '0.65rem', color: cyberColors.neon.orange }}>
                  — treat as hypothesis, not established fact
                </Typography>
              )}
            </Box>
          </SummaryBox>
        </>
      )}
    </ChainRoot>
  );
};

export default EvidenceChain;
