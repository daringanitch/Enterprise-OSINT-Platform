/**
 * RiskCommandCenter Component
 *
 * Executive-level risk visualization with 6-category breakdown,
 * animated gauge, trend analysis, and AI recommendations.
 *
 * Features:
 * - Central gauge with animated needle (0-100)
 * - 6 radial risk categories
 * - 7-day trend sparklines per category
 * - Top risk factors with severity badges
 * - AI-generated mitigation recommendations
 */

import React, { useMemo } from 'react';
import {
  Box,
  Typography,
  Chip,
  Tooltip,
  LinearProgress,
  Grid,
  alpha,
  styled,
} from '@mui/material';
import { motion } from 'framer-motion';
import ShieldIcon from '@mui/icons-material/Shield';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import TrendingDownIcon from '@mui/icons-material/TrendingDown';
import TrendingFlatIcon from '@mui/icons-material/TrendingFlat';
import WarningIcon from '@mui/icons-material/Warning';
import SecurityIcon from '@mui/icons-material/Security';
import StorageIcon from '@mui/icons-material/Storage';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import PolicyIcon from '@mui/icons-material/Policy';
import BugReportIcon from '@mui/icons-material/BugReport';
import LightbulbIcon from '@mui/icons-material/Lightbulb';
import { cyberColors, designTokens, glassmorphism } from '../../utils/theme';

// =============================================================================
// Types
// =============================================================================

export type RiskCategory =
  | 'infrastructure'
  | 'threat'
  | 'credential'
  | 'reputation'
  | 'compliance'
  | 'data_exposure';

export interface CategoryRisk {
  category: RiskCategory;
  score: number; // 0-100
  trend: 'up' | 'down' | 'stable';
  trendPercentage: number;
  history: number[]; // 7-day history
  topFactors: string[];
}

export interface RiskFactor {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: RiskCategory;
  impact: number;
}

export interface Recommendation {
  id: string;
  title: string;
  description: string;
  priority: 'immediate' | 'high' | 'medium' | 'low';
  effort: 'low' | 'medium' | 'high';
  category: RiskCategory;
}

export interface RiskCommandCenterProps {
  /** Overall risk score (0-100) */
  overallScore: number;
  /** Risk trend direction */
  overallTrend: 'up' | 'down' | 'stable';
  /** Category-level risk breakdown */
  categories: CategoryRisk[];
  /** Top risk factors */
  riskFactors: RiskFactor[];
  /** AI-generated recommendations */
  recommendations: Recommendation[];
  /** Title */
  title?: string;
  /** Loading state */
  loading?: boolean;
  /** Risk factor click handler */
  onRiskFactorClick?: (factor: RiskFactor) => void;
  /** Recommendation click handler */
  onRecommendationClick?: (rec: Recommendation) => void;
  /** Test ID */
  testId?: string;
}

// =============================================================================
// Category Configuration
// =============================================================================

const categoryConfig: Record<RiskCategory, { icon: React.ReactNode; label: string; color: string }> = {
  infrastructure: {
    icon: <StorageIcon />,
    label: 'Infrastructure',
    color: cyberColors.neon.cyan,
  },
  threat: {
    icon: <BugReportIcon />,
    label: 'Threat',
    color: cyberColors.neon.red,
  },
  credential: {
    icon: <VpnKeyIcon />,
    label: 'Credential',
    color: cyberColors.neon.orange,
  },
  reputation: {
    icon: <VerifiedUserIcon />,
    label: 'Reputation',
    color: cyberColors.neon.purple,
  },
  compliance: {
    icon: <PolicyIcon />,
    label: 'Compliance',
    color: cyberColors.neon.electricBlue,
  },
  data_exposure: {
    icon: <SecurityIcon />,
    label: 'Data Exposure',
    color: cyberColors.neon.magenta,
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

const CommandCenterContainer = styled(Box)(({ theme }) => ({
  ...glassmorphism.card,
  borderRadius: designTokens.borderRadius.lg,
  overflow: 'hidden',
}));

const HeaderSection = styled(Box)(({ theme }) => ({
  padding: '16px 20px',
  borderBottom: `1px solid ${alpha(cyberColors.neon.cyan, 0.1)}`,
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
}));

const GaugeContainer = styled(Box)(({ theme }) => ({
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'center',
  justifyContent: 'center',
  padding: '20px',
}));

const CategoryCard = styled(motion.div)<{ categoryColor: string }>(({ categoryColor }) => ({
  ...glassmorphism.interactive,
  borderRadius: designTokens.borderRadius.md,
  padding: 12,
  borderLeft: `3px solid ${categoryColor}`,
  cursor: 'pointer',
}));

const SparklineContainer = styled(Box)(({ theme }) => ({
  height: 24,
  display: 'flex',
  alignItems: 'flex-end',
  gap: 2,
}));

const SparklineBar = styled(motion.div)<{ color: string }>(({ color }) => ({
  width: 4,
  borderRadius: 1,
  background: color,
  boxShadow: `0 0 4px ${color}`,
}));

const RiskFactorCard = styled(motion.div)(({ theme }) => ({
  ...glassmorphism.interactive,
  borderRadius: designTokens.borderRadius.sm,
  padding: 10,
  marginBottom: 6,
  cursor: 'pointer',
}));

const RecommendationCard = styled(motion.div)<{ priority: string }>(({ priority }) => ({
  ...glassmorphism.interactive,
  borderRadius: designTokens.borderRadius.sm,
  padding: 10,
  marginBottom: 6,
  cursor: 'pointer',
  borderLeft: `3px solid ${priorityColors[priority as keyof typeof priorityColors] || cyberColors.neon.cyan}`,
}));

// =============================================================================
// Risk Gauge Component
// =============================================================================

const RiskGaugeComponent: React.FC<{ value: number; trend: 'up' | 'down' | 'stable' }> = ({
  value,
  trend,
}) => {
  const size = 200;
  const strokeWidth = 16;
  const center = size / 2;
  const radius = (size - strokeWidth) / 2 - 10;

  // Gauge arc (from -135 to 135 degrees, 270 total)
  const startAngle = -135;
  const endAngle = 135;
  const totalAngle = endAngle - startAngle;
  const valueAngle = startAngle + (value / 100) * totalAngle;

  const polarToCartesian = (cx: number, cy: number, r: number, angle: number) => {
    const rad = (angle * Math.PI) / 180;
    return {
      x: cx + r * Math.cos(rad),
      y: cy + r * Math.sin(rad),
    };
  };

  const describeArc = (x: number, y: number, r: number, startAng: number, endAng: number) => {
    const start = polarToCartesian(x, y, r, endAng);
    const end = polarToCartesian(x, y, r, startAng);
    const largeArcFlag = endAng - startAng <= 180 ? 0 : 1;
    return `M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArcFlag} 0 ${end.x} ${end.y}`;
  };

  // Color based on risk level
  const gaugeColor =
    value >= 75 ? cyberColors.neon.magenta :
    value >= 50 ? cyberColors.neon.red :
    value >= 25 ? cyberColors.neon.orange :
    cyberColors.neon.green;

  const riskLabel =
    value >= 75 ? 'CRITICAL' :
    value >= 50 ? 'HIGH' :
    value >= 25 ? 'MEDIUM' : 'LOW';

  return (
    <Box sx={{ position: 'relative', width: size, height: size * 0.7 }}>
      <svg width={size} height={size * 0.7} style={{ overflow: 'visible' }}>
        <defs>
          <filter id="gaugeGlow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="4" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor={cyberColors.neon.green} />
            <stop offset="33%" stopColor={cyberColors.neon.orange} />
            <stop offset="66%" stopColor={cyberColors.neon.red} />
            <stop offset="100%" stopColor={cyberColors.neon.magenta} />
          </linearGradient>
        </defs>

        {/* Background arc */}
        <path
          d={describeArc(center, center, radius, startAngle, endAngle)}
          fill="none"
          stroke={alpha(cyberColors.dark.ash, 0.5)}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
        />

        {/* Value arc */}
        <motion.path
          d={describeArc(center, center, radius, startAngle, valueAngle)}
          fill="none"
          stroke="url(#gaugeGradient)"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          filter="url(#gaugeGlow)"
          initial={{ pathLength: 0 }}
          animate={{ pathLength: 1 }}
          transition={{ duration: 1.5, ease: 'easeOut' }}
        />

        {/* Tick marks */}
        {[0, 25, 50, 75, 100].map((tick) => {
          const angle = startAngle + (tick / 100) * totalAngle;
          const inner = polarToCartesian(center, center, radius - 12, angle);
          const outer = polarToCartesian(center, center, radius + 6, angle);
          return (
            <line
              key={tick}
              x1={inner.x}
              y1={inner.y}
              x2={outer.x}
              y2={outer.y}
              stroke={cyberColors.text.muted}
              strokeWidth={2}
            />
          );
        })}

        {/* Needle */}
        <motion.g
          initial={{ rotate: startAngle }}
          animate={{ rotate: valueAngle }}
          transition={{ type: 'spring', stiffness: 50, damping: 15, delay: 0.5 }}
          style={{ transformOrigin: `${center}px ${center}px` }}
        >
          <line
            x1={center}
            y1={center}
            x2={center}
            y2={center - radius + 20}
            stroke={gaugeColor}
            strokeWidth={3}
            strokeLinecap="round"
            filter="url(#gaugeGlow)"
          />
          <circle cx={center} cy={center} r={8} fill={gaugeColor} filter="url(#gaugeGlow)" />
        </motion.g>
      </svg>

      {/* Center text */}
      <Box
        sx={{
          position: 'absolute',
          top: '55%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          textAlign: 'center',
        }}
      >
        <motion.div
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          transition={{ delay: 0.8, type: 'spring' }}
        >
          <Typography
            variant="h3"
            sx={{
              fontFamily: designTokens.typography.fontFamily.mono,
              fontWeight: 700,
              color: gaugeColor,
              textShadow: `0 0 20px ${gaugeColor}`,
              lineHeight: 1,
            }}
          >
            {Math.round(value)}
          </Typography>
          <Typography
            variant="caption"
            sx={{
              color: gaugeColor,
              fontWeight: 700,
              letterSpacing: '0.1em',
            }}
          >
            {riskLabel}
          </Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', mt: 0.5 }}>
            {trend === 'up' && <TrendingUpIcon sx={{ fontSize: 14, color: cyberColors.neon.red }} />}
            {trend === 'down' && <TrendingDownIcon sx={{ fontSize: 14, color: cyberColors.neon.green }} />}
            {trend === 'stable' && <TrendingFlatIcon sx={{ fontSize: 14, color: cyberColors.neon.orange }} />}
          </Box>
        </motion.div>
      </Box>
    </Box>
  );
};

// =============================================================================
// Sparkline Component
// =============================================================================

const Sparkline: React.FC<{ data: number[]; color: string; maxHeight?: number }> = ({
  data,
  color,
  maxHeight = 24,
}) => {
  const maxValue = Math.max(...data, 1);
  return (
    <SparklineContainer>
      {data.map((value, index) => (
        <SparklineBar
          key={index}
          color={color}
          initial={{ height: 0 }}
          animate={{ height: `${(value / maxValue) * maxHeight}px` }}
          transition={{ delay: index * 0.05, duration: 0.3 }}
        />
      ))}
    </SparklineContainer>
  );
};

// =============================================================================
// Component
// =============================================================================

export const RiskCommandCenter: React.FC<RiskCommandCenterProps> = ({
  overallScore,
  overallTrend,
  categories,
  riskFactors,
  recommendations,
  title = 'Risk Command Center',
  loading = false,
  onRiskFactorClick,
  onRecommendationClick,
  testId,
}) => {
  // Sort risk factors by severity
  const sortedFactors = useMemo(() => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    return [...riskFactors].sort(
      (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
    );
  }, [riskFactors]);

  // Sort recommendations by priority
  const sortedRecommendations = useMemo(() => {
    const priorityOrder = { immediate: 0, high: 1, medium: 2, low: 3 };
    return [...recommendations].sort(
      (a, b) => priorityOrder[a.priority] - priorityOrder[b.priority]
    );
  }, [recommendations]);

  if (loading) {
    return (
      <CommandCenterContainer data-testid={testId} sx={{ p: 4, textAlign: 'center' }}>
        <LinearProgress
          sx={{
            bgcolor: alpha(cyberColors.neon.cyan, 0.1),
            '& .MuiLinearProgress-bar': {
              background: designTokens.colors.gradients.primary,
            },
          }}
        />
        <Typography variant="body2" sx={{ mt: 2, color: cyberColors.text.secondary }}>
          Calculating risk assessment...
        </Typography>
      </CommandCenterContainer>
    );
  }

  return (
    <CommandCenterContainer data-testid={testId}>
      {/* Header */}
      <HeaderSection>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <ShieldIcon sx={{ color: cyberColors.neon.cyan }} />
          <Box>
            <Typography
              variant="h6"
              sx={{
                fontFamily: designTokens.typography.fontFamily.display,
                color: cyberColors.text.primary,
                fontSize: '1rem',
              }}
            >
              {title}
            </Typography>
            <Typography variant="caption" sx={{ color: cyberColors.text.secondary }}>
              Real-time risk assessment across {categories.length} categories
            </Typography>
          </Box>
        </Box>
      </HeaderSection>

      <Grid container>
        {/* Left: Gauge + Categories */}
        <Grid item xs={12} md={6} sx={{ borderRight: { md: `1px solid ${alpha(cyberColors.neon.cyan, 0.1)}` } }}>
          {/* Central Gauge */}
          <GaugeContainer>
            <RiskGaugeComponent value={overallScore} trend={overallTrend} />
          </GaugeContainer>

          {/* Category Breakdown */}
          <Box sx={{ p: 2, pt: 0 }}>
            <Typography
              variant="caption"
              sx={{
                color: cyberColors.neon.cyan,
                fontWeight: 600,
                display: 'block',
                mb: 1,
                letterSpacing: '0.05em',
              }}
            >
              CATEGORY BREAKDOWN
            </Typography>
            <Grid container spacing={1}>
              {categories.map((cat, index) => {
                const config = categoryConfig[cat.category];
                return (
                  <Grid item xs={6} key={cat.category}>
                    <CategoryCard
                      categoryColor={config.color}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.05 }}
                      whileHover={{ scale: 1.02 }}
                    >
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                        <Box sx={{ color: config.color, fontSize: 16 }}>{config.icon}</Box>
                        <Typography
                          variant="caption"
                          sx={{ fontWeight: 600, color: cyberColors.text.primary }}
                        >
                          {config.label}
                        </Typography>
                      </Box>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography
                          variant="h6"
                          sx={{
                            fontFamily: designTokens.typography.fontFamily.mono,
                            color: config.color,
                            fontWeight: 700,
                          }}
                        >
                          {cat.score}
                        </Typography>
                        {cat.trend === 'up' && (
                          <TrendingUpIcon sx={{ fontSize: 14, color: cyberColors.neon.red }} />
                        )}
                        {cat.trend === 'down' && (
                          <TrendingDownIcon sx={{ fontSize: 14, color: cyberColors.neon.green }} />
                        )}
                        {cat.trend === 'stable' && (
                          <TrendingFlatIcon sx={{ fontSize: 14, color: cyberColors.text.muted }} />
                        )}
                      </Box>
                      <Sparkline data={cat.history} color={config.color} />
                    </CategoryCard>
                  </Grid>
                );
              })}
            </Grid>
          </Box>
        </Grid>

        {/* Right: Risk Factors + Recommendations */}
        <Grid item xs={12} md={6}>
          {/* Top Risk Factors */}
          <Box sx={{ p: 2, borderBottom: `1px solid ${alpha(cyberColors.neon.cyan, 0.1)}` }}>
            <Typography
              variant="caption"
              sx={{
                color: cyberColors.neon.red,
                fontWeight: 600,
                display: 'block',
                mb: 1,
                letterSpacing: '0.05em',
              }}
            >
              <WarningIcon sx={{ fontSize: 12, mr: 0.5, verticalAlign: 'middle' }} />
              TOP RISK FACTORS
            </Typography>
            <Box sx={{ maxHeight: 200, overflowY: 'auto' }}>
              {sortedFactors.slice(0, 5).map((factor, index) => (
                <RiskFactorCard
                  key={factor.id}
                  onClick={() => onRiskFactorClick?.(factor)}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.05 }}
                  whileHover={{ x: 4 }}
                >
                  <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1 }}>
                    <Chip
                      label={factor.severity.toUpperCase()}
                      size="small"
                      sx={{
                        height: 18,
                        fontSize: '0.55rem',
                        fontWeight: 700,
                        bgcolor: alpha(severityColors[factor.severity], 0.2),
                        color: severityColors[factor.severity],
                      }}
                    />
                    <Box sx={{ flex: 1, minWidth: 0 }}>
                      <Typography
                        variant="caption"
                        sx={{
                          fontWeight: 600,
                          color: cyberColors.text.primary,
                          display: 'block',
                        }}
                      >
                        {factor.title}
                      </Typography>
                      <Typography
                        variant="caption"
                        sx={{
                          color: cyberColors.text.secondary,
                          fontSize: '0.65rem',
                          display: 'block',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {factor.description}
                      </Typography>
                    </Box>
                  </Box>
                </RiskFactorCard>
              ))}
            </Box>
          </Box>

          {/* AI Recommendations */}
          <Box sx={{ p: 2 }}>
            <Typography
              variant="caption"
              sx={{
                color: cyberColors.neon.green,
                fontWeight: 600,
                display: 'block',
                mb: 1,
                letterSpacing: '0.05em',
              }}
            >
              <LightbulbIcon sx={{ fontSize: 12, mr: 0.5, verticalAlign: 'middle' }} />
              RECOMMENDED ACTIONS
            </Typography>
            <Box sx={{ maxHeight: 180, overflowY: 'auto' }}>
              {sortedRecommendations.slice(0, 4).map((rec, index) => (
                <RecommendationCard
                  key={rec.id}
                  priority={rec.priority}
                  onClick={() => onRecommendationClick?.(rec)}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.05 }}
                  whileHover={{ x: 4 }}
                >
                  <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1 }}>
                    <Box sx={{ flex: 1, minWidth: 0 }}>
                      <Typography
                        variant="caption"
                        sx={{
                          fontWeight: 600,
                          color: cyberColors.text.primary,
                          display: 'block',
                        }}
                      >
                        {rec.title}
                      </Typography>
                      <Typography
                        variant="caption"
                        sx={{
                          color: cyberColors.text.secondary,
                          fontSize: '0.65rem',
                          display: 'block',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {rec.description}
                      </Typography>
                    </Box>
                    <Box sx={{ display: 'flex', gap: 0.5 }}>
                      <Chip
                        label={rec.priority}
                        size="small"
                        sx={{
                          height: 16,
                          fontSize: '0.5rem',
                          fontWeight: 700,
                          bgcolor: alpha(priorityColors[rec.priority], 0.2),
                          color: priorityColors[rec.priority],
                        }}
                      />
                      <Tooltip title={`Effort: ${rec.effort}`}>
                        <Chip
                          label={rec.effort[0].toUpperCase()}
                          size="small"
                          sx={{
                            height: 16,
                            fontSize: '0.5rem',
                            bgcolor: alpha(cyberColors.text.muted, 0.2),
                          }}
                        />
                      </Tooltip>
                    </Box>
                  </Box>
                </RecommendationCard>
              ))}
            </Box>
          </Box>
        </Grid>
      </Grid>
    </CommandCenterContainer>
  );
};

export default RiskCommandCenter;
