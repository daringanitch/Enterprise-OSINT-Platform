/**
 * StatCard Component
 *
 * Card displaying a single statistic with optional trend indicator and sparkline.
 */

import React, { useMemo } from 'react';
import {
  Box,
  Paper,
  Typography,
  useTheme,
  Skeleton,
  Tooltip,
} from '@mui/material';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import TrendingDownIcon from '@mui/icons-material/TrendingDown';
import TrendingFlatIcon from '@mui/icons-material/TrendingFlat';
import {
  AreaChart,
  Area,
  ResponsiveContainer,
} from 'recharts';

export interface StatCardProps {
  /** Main title/label */
  title: string;
  /** Main value to display */
  value: string | number;
  /** Value suffix (e.g., '%', 'ms') */
  suffix?: string;
  /** Previous value for trend calculation */
  previousValue?: number;
  /** Trend direction (overrides calculated trend) */
  trend?: 'up' | 'down' | 'flat';
  /** Is trending up good? (affects color) */
  trendUpIsGood?: boolean;
  /** Percentage change */
  changePercent?: number;
  /** Description or subtitle */
  description?: string;
  /** Icon to display */
  icon?: React.ReactNode;
  /** Icon background color */
  iconColor?: string;
  /** Sparkline data */
  sparklineData?: number[];
  /** Sparkline color */
  sparklineColor?: string;
  /** Loading state */
  loading?: boolean;
  /** Card variant */
  variant?: 'default' | 'outlined' | 'gradient';
  /** Gradient colors for gradient variant */
  gradientColors?: [string, string];
  /** Click handler */
  onClick?: () => void;
  /** Test ID for testing */
  testId?: string;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  suffix,
  previousValue,
  trend: propTrend,
  trendUpIsGood = true,
  changePercent: propChangePercent,
  description,
  icon,
  iconColor,
  sparklineData,
  sparklineColor,
  loading = false,
  variant = 'default',
  gradientColors = ['#1976d2', '#42a5f5'],
  onClick,
  testId,
}) => {
  const theme = useTheme();

  // Calculate trend from values if not provided
  const { trend, changePercent } = useMemo(() => {
    if (propTrend !== undefined) {
      return { trend: propTrend, changePercent: propChangePercent };
    }

    if (previousValue !== undefined && typeof value === 'number') {
      const change = value - previousValue;
      const percent = previousValue !== 0
        ? ((change / Math.abs(previousValue)) * 100)
        : 0;

      return {
        trend: change > 0 ? 'up' : change < 0 ? 'down' : 'flat',
        changePercent: propChangePercent ?? percent,
      };
    }

    return { trend: undefined, changePercent: propChangePercent };
  }, [value, previousValue, propTrend, propChangePercent]);

  const trendColor = useMemo(() => {
    if (!trend || trend === 'flat') return theme.palette.text.secondary;
    const isGood = (trend === 'up' && trendUpIsGood) || (trend === 'down' && !trendUpIsGood);
    return isGood ? theme.palette.success.main : theme.palette.error.main;
  }, [trend, trendUpIsGood, theme]);

  const TrendIcon = useMemo(() => {
    if (!trend) return null;
    switch (trend) {
      case 'up':
        return TrendingUpIcon;
      case 'down':
        return TrendingDownIcon;
      default:
        return TrendingFlatIcon;
    }
  }, [trend]);

  const sparklineChartData = useMemo(() => {
    if (!sparklineData?.length) return null;
    return sparklineData.map((value, index) => ({ value, index }));
  }, [sparklineData]);

  const paperStyles = useMemo(() => {
    const baseStyles = {
      p: 2.5,
      height: '100%',
      cursor: onClick ? 'pointer' : 'default',
      transition: 'transform 0.2s, box-shadow 0.2s',
      '&:hover': onClick
        ? {
            transform: 'translateY(-2px)',
            boxShadow: 4,
          }
        : undefined,
    };

    switch (variant) {
      case 'outlined':
        return {
          ...baseStyles,
          border: 2,
          borderColor: 'primary.main',
        };
      case 'gradient':
        return {
          ...baseStyles,
          background: `linear-gradient(135deg, ${gradientColors[0]}, ${gradientColors[1]})`,
          color: 'white',
        };
      default:
        return baseStyles;
    }
  }, [variant, gradientColors, onClick]);

  const textColor = variant === 'gradient' ? 'inherit' : undefined;
  const secondaryTextColor = variant === 'gradient' ? 'rgba(255,255,255,0.7)' : 'text.secondary';

  if (loading) {
    return (
      <Paper data-testid={testId} elevation={variant === 'outlined' ? 0 : 1} sx={paperStyles}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
          <Skeleton variant="text" width={100} height={24} />
          {icon && <Skeleton variant="circular" width={40} height={40} />}
        </Box>
        <Skeleton variant="text" width={80} height={40} />
        <Skeleton variant="text" width={120} height={20} sx={{ mt: 1 }} />
      </Paper>
    );
  }

  return (
    <Paper
      data-testid={testId}
      elevation={variant === 'outlined' ? 0 : 1}
      sx={paperStyles}
      onClick={onClick}
    >
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <Box sx={{ flex: 1 }}>
          <Typography
            variant="body2"
            color={secondaryTextColor}
            gutterBottom
            sx={{ fontWeight: 500 }}
          >
            {title}
          </Typography>
          <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 0.5 }}>
            <Typography
              variant="h4"
              color={textColor}
              fontWeight="bold"
              sx={{ lineHeight: 1.2 }}
            >
              {value}
            </Typography>
            {suffix && (
              <Typography variant="h6" color={secondaryTextColor}>
                {suffix}
              </Typography>
            )}
          </Box>
        </Box>

        {icon && (
          <Box
            sx={{
              width: 48,
              height: 48,
              borderRadius: 2,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              bgcolor: variant === 'gradient'
                ? 'rgba(255,255,255,0.2)'
                : iconColor || 'primary.light',
              color: variant === 'gradient' ? 'inherit' : 'primary.main',
            }}
          >
            {icon}
          </Box>
        )}
      </Box>

      {/* Trend indicator */}
      {(trend || changePercent !== undefined) && (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mt: 1.5 }}>
          {TrendIcon && (
            <TrendIcon
              sx={{
                fontSize: 18,
                color: variant === 'gradient' ? 'inherit' : trendColor,
              }}
            />
          )}
          {changePercent !== undefined && (
            <Typography
              variant="body2"
              sx={{
                color: variant === 'gradient' ? 'inherit' : trendColor,
                fontWeight: 'medium',
              }}
            >
              {changePercent > 0 ? '+' : ''}
              {changePercent.toFixed(1)}%
            </Typography>
          )}
          {description && (
            <Typography
              variant="body2"
              color={secondaryTextColor}
              sx={{ ml: 0.5 }}
            >
              {description}
            </Typography>
          )}
        </Box>
      )}

      {/* Sparkline */}
      {sparklineChartData && (
        <Box sx={{ mt: 2, height: 40 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={sparklineChartData}>
              <defs>
                <linearGradient id={`sparkline-gradient-${testId}`} x1="0" y1="0" x2="0" y2="1">
                  <stop
                    offset="5%"
                    stopColor={sparklineColor || (variant === 'gradient' ? '#fff' : theme.palette.primary.main)}
                    stopOpacity={0.4}
                  />
                  <stop
                    offset="95%"
                    stopColor={sparklineColor || (variant === 'gradient' ? '#fff' : theme.palette.primary.main)}
                    stopOpacity={0}
                  />
                </linearGradient>
              </defs>
              <Area
                type="monotone"
                dataKey="value"
                stroke={sparklineColor || (variant === 'gradient' ? '#fff' : theme.palette.primary.main)}
                strokeWidth={2}
                fill={`url(#sparkline-gradient-${testId})`}
              />
            </AreaChart>
          </ResponsiveContainer>
        </Box>
      )}
    </Paper>
  );
};

export default StatCard;
