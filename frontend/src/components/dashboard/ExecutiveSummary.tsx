/**
 * ExecutiveSummary Component
 *
 * One-glance investigation overview card for executives.
 *
 * Features:
 * - Threat level badge with glow effect
 * - Key findings (top 3-5 bullet points)
 * - Risk trajectory indicator
 * - Priority-ordered recommended actions
 * - Overall confidence score
 */

import React from 'react';
import {
  Box,
  Typography,
  Chip,
  Divider,
  LinearProgress,
  alpha,
  styled,
} from '@mui/material';
import { motion } from 'framer-motion';
import AssessmentIcon from '@mui/icons-material/Assessment';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import TrendingDownIcon from '@mui/icons-material/TrendingDown';
import TrendingFlatIcon from '@mui/icons-material/TrendingFlat';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import LightbulbOutlinedIcon from '@mui/icons-material/LightbulbOutlined';
import { cyberColors, designTokens, glassmorphism } from '../../utils/theme';
import { staggerContainer, staggerItem } from '../../utils/animations';

// =============================================================================
// Types
// =============================================================================

export type ThreatLevel = 'critical' | 'high' | 'medium' | 'low' | 'none';
export type RiskTrajectory = 'increasing' | 'decreasing' | 'stable';

export interface KeyFinding {
  id: string;
  text: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category?: string;
}

export interface RecommendedAction {
  id: string;
  text: string;
  priority: 'immediate' | 'high' | 'medium' | 'low';
  completed?: boolean;
}

export interface ExecutiveSummaryProps {
  /** Investigation title/target */
  title: string;
  /** Investigation status */
  status: 'completed' | 'in_progress' | 'pending';
  /** Overall threat level */
  threatLevel: ThreatLevel;
  /** Risk trajectory over time */
  riskTrajectory: RiskTrajectory;
  /** Key findings from investigation */
  findings: KeyFinding[];
  /** Recommended actions */
  recommendations: RecommendedAction[];
  /** Overall assessment confidence (0-100) */
  confidenceScore: number;
  /** Summary text (1-2 sentences) */
  summary?: string;
  /** Total entities analyzed */
  entitiesAnalyzed?: number;
  /** Total data sources used */
  dataSourcesUsed?: number;
  /** Time taken for investigation */
  investigationDuration?: string;
  /** Test ID */
  testId?: string;
}

// =============================================================================
// Configuration
// =============================================================================

const threatLevelConfig: Record<ThreatLevel, { color: string; label: string; icon: React.ReactNode }> = {
  critical: {
    color: cyberColors.neon.magenta,
    label: 'CRITICAL THREAT',
    icon: <ErrorOutlineIcon />,
  },
  high: {
    color: cyberColors.neon.red,
    label: 'HIGH THREAT',
    icon: <WarningAmberIcon />,
  },
  medium: {
    color: cyberColors.neon.orange,
    label: 'MEDIUM THREAT',
    icon: <WarningAmberIcon />,
  },
  low: {
    color: cyberColors.neon.yellow,
    label: 'LOW THREAT',
    icon: <CheckCircleOutlineIcon />,
  },
  none: {
    color: cyberColors.neon.green,
    label: 'NO THREAT',
    icon: <CheckCircleOutlineIcon />,
  },
};

const severityColors = {
  critical: cyberColors.neon.magenta,
  high: cyberColors.neon.red,
  medium: cyberColors.neon.orange,
  low: cyberColors.neon.yellow,
};

const priorityColors = {
  immediate: cyberColors.neon.magenta,
  high: cyberColors.neon.red,
  medium: cyberColors.neon.orange,
  low: cyberColors.neon.green,
};

// =============================================================================
// Styled Components
// =============================================================================

const SummaryContainer = styled(motion.div)(({ theme }) => ({
  ...glassmorphism.card,
  borderRadius: designTokens.borderRadius.lg,
  overflow: 'hidden',
  position: 'relative',
}));

const ThreatBadge = styled(motion.div)<{ threatColor: string }>(({ threatColor }) => ({
  display: 'inline-flex',
  alignItems: 'center',
  gap: 8,
  padding: '8px 16px',
  borderRadius: designTokens.borderRadius.md,
  background: alpha(threatColor, 0.15),
  border: `2px solid ${threatColor}`,
  color: threatColor,
  fontWeight: 700,
  fontSize: '0.875rem',
  fontFamily: designTokens.typography.fontFamily.display,
  letterSpacing: '0.05em',
  boxShadow: `0 0 20px ${alpha(threatColor, 0.4)}, inset 0 0 20px ${alpha(threatColor, 0.1)}`,
  animation: 'threatPulse 2s ease-in-out infinite',
  '@keyframes threatPulse': {
    '0%, 100%': {
      boxShadow: `0 0 20px ${alpha(threatColor, 0.4)}, inset 0 0 20px ${alpha(threatColor, 0.1)}`,
    },
    '50%': {
      boxShadow: `0 0 40px ${alpha(threatColor, 0.6)}, inset 0 0 30px ${alpha(threatColor, 0.2)}`,
    },
  },
}));

const FindingItem = styled(motion.div)<{ severityColor: string }>(({ severityColor }) => ({
  display: 'flex',
  alignItems: 'flex-start',
  gap: 8,
  padding: 8,
  marginBottom: 4,
  borderRadius: designTokens.borderRadius.sm,
  background: alpha(severityColor, 0.05),
  borderLeft: `3px solid ${severityColor}`,
}));

const ActionItem = styled(motion.div)<{ completed?: boolean }>(({ completed }) => ({
  display: 'flex',
  alignItems: 'center',
  gap: 8,
  padding: 8,
  marginBottom: 4,
  borderRadius: designTokens.borderRadius.sm,
  background: completed ? alpha(cyberColors.neon.green, 0.1) : alpha(cyberColors.dark.steel, 0.3),
  opacity: completed ? 0.6 : 1,
}));

const MetricBox = styled(Box)(({ theme }) => ({
  textAlign: 'center',
  padding: '8px 12px',
  borderRadius: designTokens.borderRadius.sm,
  background: alpha(cyberColors.dark.steel, 0.5),
  flex: 1,
}));

const ConfidenceBar = styled(Box)(({ theme }) => ({
  height: 8,
  borderRadius: 4,
  background: alpha(cyberColors.dark.ash, 0.5),
  overflow: 'hidden',
}));

// =============================================================================
// Component
// =============================================================================

export const ExecutiveSummary: React.FC<ExecutiveSummaryProps> = ({
  title,
  status,
  threatLevel,
  riskTrajectory,
  findings,
  recommendations,
  confidenceScore,
  summary,
  entitiesAnalyzed,
  dataSourcesUsed,
  investigationDuration,
  testId,
}) => {
  const threatConfig = threatLevelConfig[threatLevel];

  return (
    <SummaryContainer
      data-testid={testId}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      {/* Top gradient bar */}
      <Box
        sx={{
          height: 4,
          background: `linear-gradient(90deg, ${threatConfig.color}, ${cyberColors.neon.cyan})`,
          boxShadow: `0 0 20px ${threatConfig.color}`,
        }}
      />

      {/* Header Section */}
      <Box sx={{ p: 3, pb: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', mb: 2 }}>
          <Box>
            <Typography
              variant="overline"
              sx={{ color: cyberColors.text.muted, letterSpacing: '0.1em' }}
            >
              EXECUTIVE SUMMARY
            </Typography>
            <Typography
              variant="h5"
              sx={{
                fontFamily: designTokens.typography.fontFamily.display,
                color: cyberColors.text.primary,
                fontWeight: 700,
              }}
            >
              {title}
            </Typography>
            <Chip
              label={status.replace('_', ' ').toUpperCase()}
              size="small"
              sx={{
                mt: 1,
                height: 20,
                fontSize: '0.65rem',
                bgcolor:
                  status === 'completed'
                    ? alpha(cyberColors.neon.green, 0.2)
                    : status === 'in_progress'
                    ? alpha(cyberColors.neon.orange, 0.2)
                    : alpha(cyberColors.text.muted, 0.2),
                color:
                  status === 'completed'
                    ? cyberColors.neon.green
                    : status === 'in_progress'
                    ? cyberColors.neon.orange
                    : cyberColors.text.muted,
              }}
            />
          </Box>
          <ThreatBadge threatColor={threatConfig.color}>
            {threatConfig.icon}
            {threatConfig.label}
          </ThreatBadge>
        </Box>

        {/* Risk Trajectory */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
          <Typography variant="caption" sx={{ color: cyberColors.text.secondary }}>
            Risk Trajectory:
          </Typography>
          <Chip
            icon={
              riskTrajectory === 'increasing' ? (
                <TrendingUpIcon fontSize="small" />
              ) : riskTrajectory === 'decreasing' ? (
                <TrendingDownIcon fontSize="small" />
              ) : (
                <TrendingFlatIcon fontSize="small" />
              )
            }
            label={riskTrajectory.charAt(0).toUpperCase() + riskTrajectory.slice(1)}
            size="small"
            sx={{
              height: 22,
              fontSize: '0.7rem',
              bgcolor: alpha(
                riskTrajectory === 'increasing'
                  ? cyberColors.neon.red
                  : riskTrajectory === 'decreasing'
                  ? cyberColors.neon.green
                  : cyberColors.neon.orange,
                0.2
              ),
              color:
                riskTrajectory === 'increasing'
                  ? cyberColors.neon.red
                  : riskTrajectory === 'decreasing'
                  ? cyberColors.neon.green
                  : cyberColors.neon.orange,
            }}
          />
        </Box>

        {/* Summary Text */}
        {summary && (
          <Typography
            variant="body2"
            sx={{
              color: cyberColors.text.secondary,
              mb: 2,
              p: 1.5,
              borderRadius: designTokens.borderRadius.sm,
              background: alpha(cyberColors.dark.steel, 0.3),
              borderLeft: `3px solid ${cyberColors.neon.cyan}`,
            }}
          >
            {summary}
          </Typography>
        )}

        {/* Metrics Row */}
        <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
          {entitiesAnalyzed !== undefined && (
            <MetricBox>
              <Typography
                variant="h6"
                sx={{
                  fontFamily: designTokens.typography.fontFamily.mono,
                  color: cyberColors.neon.cyan,
                }}
              >
                {entitiesAnalyzed}
              </Typography>
              <Typography variant="caption" sx={{ color: cyberColors.text.muted }}>
                Entities
              </Typography>
            </MetricBox>
          )}
          {dataSourcesUsed !== undefined && (
            <MetricBox>
              <Typography
                variant="h6"
                sx={{
                  fontFamily: designTokens.typography.fontFamily.mono,
                  color: cyberColors.neon.magenta,
                }}
              >
                {dataSourcesUsed}
              </Typography>
              <Typography variant="caption" sx={{ color: cyberColors.text.muted }}>
                Sources
              </Typography>
            </MetricBox>
          )}
          {investigationDuration && (
            <MetricBox>
              <Typography
                variant="h6"
                sx={{
                  fontFamily: designTokens.typography.fontFamily.mono,
                  color: cyberColors.neon.green,
                }}
              >
                {investigationDuration}
              </Typography>
              <Typography variant="caption" sx={{ color: cyberColors.text.muted }}>
                Duration
              </Typography>
            </MetricBox>
          )}
        </Box>

        {/* Confidence Score */}
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
            <Typography variant="caption" sx={{ color: cyberColors.text.secondary }}>
              Assessment Confidence
            </Typography>
            <Typography
              variant="caption"
              sx={{
                color: cyberColors.neon.cyan,
                fontFamily: designTokens.typography.fontFamily.mono,
              }}
            >
              {confidenceScore}%
            </Typography>
          </Box>
          <ConfidenceBar>
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${confidenceScore}%` }}
              transition={{ duration: 1, ease: 'easeOut' }}
              style={{
                height: '100%',
                borderRadius: 4,
                background: designTokens.colors.gradients.primary,
                boxShadow: `0 0 10px ${cyberColors.neon.cyan}`,
              }}
            />
          </ConfidenceBar>
        </Box>
      </Box>

      <Divider sx={{ borderColor: alpha(cyberColors.neon.cyan, 0.1) }} />

      {/* Key Findings */}
      <Box sx={{ p: 2 }}>
        <Typography
          variant="caption"
          sx={{
            color: cyberColors.neon.red,
            fontWeight: 600,
            letterSpacing: '0.05em',
            display: 'block',
            mb: 1,
          }}
        >
          KEY FINDINGS
        </Typography>
        <motion.div variants={staggerContainer} initial="initial" animate="enter">
          {findings.slice(0, 5).map((finding) => (
            <FindingItem
              key={finding.id}
              severityColor={severityColors[finding.severity]}
              variants={staggerItem}
            >
              <Box
                sx={{
                  width: 6,
                  height: 6,
                  borderRadius: '50%',
                  bgcolor: severityColors[finding.severity],
                  flexShrink: 0,
                  mt: 0.5,
                }}
              />
              <Box sx={{ flex: 1 }}>
                <Typography
                  variant="caption"
                  sx={{ color: cyberColors.text.primary, display: 'block' }}
                >
                  {finding.text}
                </Typography>
                {finding.category && (
                  <Typography
                    variant="caption"
                    sx={{
                      color: cyberColors.text.muted,
                      fontSize: '0.6rem',
                      fontFamily: designTokens.typography.fontFamily.mono,
                    }}
                  >
                    {finding.category}
                  </Typography>
                )}
              </Box>
            </FindingItem>
          ))}
        </motion.div>
      </Box>

      <Divider sx={{ borderColor: alpha(cyberColors.neon.cyan, 0.1) }} />

      {/* Recommended Actions */}
      <Box sx={{ p: 2 }}>
        <Typography
          variant="caption"
          sx={{
            color: cyberColors.neon.green,
            fontWeight: 600,
            letterSpacing: '0.05em',
            display: 'flex',
            alignItems: 'center',
            gap: 0.5,
            mb: 1,
          }}
        >
          <LightbulbOutlinedIcon sx={{ fontSize: 14 }} />
          RECOMMENDED ACTIONS
        </Typography>
        <motion.div variants={staggerContainer} initial="initial" animate="enter">
          {recommendations.slice(0, 4).map((action, index) => (
            <ActionItem
              key={action.id}
              completed={action.completed}
              variants={staggerItem}
            >
              <Box
                sx={{
                  width: 20,
                  height: 20,
                  borderRadius: '50%',
                  bgcolor: alpha(priorityColors[action.priority], 0.2),
                  border: `1px solid ${priorityColors[action.priority]}`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: priorityColors[action.priority],
                  fontSize: '0.65rem',
                  fontWeight: 700,
                  flexShrink: 0,
                }}
              >
                {index + 1}
              </Box>
              <Typography
                variant="caption"
                sx={{
                  color: action.completed ? cyberColors.text.muted : cyberColors.text.primary,
                  textDecoration: action.completed ? 'line-through' : 'none',
                  flex: 1,
                }}
              >
                {action.text}
              </Typography>
              <Chip
                label={action.priority}
                size="small"
                sx={{
                  height: 16,
                  fontSize: '0.5rem',
                  bgcolor: alpha(priorityColors[action.priority], 0.2),
                  color: priorityColors[action.priority],
                }}
              />
            </ActionItem>
          ))}
        </motion.div>
      </Box>
    </SummaryContainer>
  );
};

export default ExecutiveSummary;
