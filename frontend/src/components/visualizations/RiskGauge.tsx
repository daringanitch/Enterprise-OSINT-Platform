/**
 * RiskGauge Component
 *
 * Circular gauge for displaying risk scores and other percentage-based metrics.
 */

import React, { useMemo } from 'react';
import { Box, Typography, useTheme } from '@mui/material';

export interface RiskGaugeProps {
  /** Current value (0-100) */
  value: number;
  /** Maximum value */
  max?: number;
  /** Gauge title */
  title?: string;
  /** Size in pixels */
  size?: number;
  /** Stroke width */
  strokeWidth?: number;
  /** Show value text */
  showValue?: boolean;
  /** Value suffix (e.g., '%') */
  valueSuffix?: string;
  /** Risk level thresholds */
  thresholds?: {
    low: number;
    medium: number;
    high: number;
  };
  /** Custom colors */
  colors?: {
    low: string;
    medium: string;
    high: string;
    critical: string;
    background: string;
  };
  /** Animate on mount */
  animated?: boolean;
  /** Risk level label */
  showLabel?: boolean;
  /** Test ID for testing */
  testId?: string;
}

const defaultThresholds = {
  low: 25,
  medium: 50,
  high: 75,
};

const defaultColors = {
  low: '#4caf50',
  medium: '#ff9800',
  high: '#f44336',
  critical: '#9c27b0',
  background: '#e0e0e0',
};

const getRiskLevel = (
  value: number,
  thresholds: { low: number; medium: number; high: number }
): 'low' | 'medium' | 'high' | 'critical' => {
  if (value <= thresholds.low) return 'low';
  if (value <= thresholds.medium) return 'medium';
  if (value <= thresholds.high) return 'high';
  return 'critical';
};

const getRiskLabel = (level: 'low' | 'medium' | 'high' | 'critical'): string => {
  const labels = {
    low: 'Low Risk',
    medium: 'Medium Risk',
    high: 'High Risk',
    critical: 'Critical Risk',
  };
  return labels[level];
};

export const RiskGauge: React.FC<RiskGaugeProps> = ({
  value,
  max = 100,
  title,
  size = 200,
  strokeWidth = 12,
  showValue = true,
  valueSuffix = '',
  thresholds = defaultThresholds,
  colors = defaultColors,
  animated = true,
  showLabel = true,
  testId,
}) => {
  const theme = useTheme();

  const normalizedValue = useMemo(
    () => Math.min(Math.max(value, 0), max),
    [value, max]
  );

  const percentage = useMemo(
    () => (normalizedValue / max) * 100,
    [normalizedValue, max]
  );

  const riskLevel = useMemo(
    () => getRiskLevel(percentage, thresholds),
    [percentage, thresholds]
  );

  const gaugeColor = colors[riskLevel];

  // SVG calculations
  const center = size / 2;
  const radius = (size - strokeWidth) / 2 - 10;
  const circumference = 2 * Math.PI * radius;
  const startAngle = 135; // Start from bottom left
  const endAngle = 405; // End at bottom right (270 degrees total)
  const totalAngle = endAngle - startAngle;
  const valueAngle = (percentage / 100) * totalAngle;

  // Arc path calculations
  const polarToCartesian = (
    cx: number,
    cy: number,
    r: number,
    angle: number
  ) => {
    const rad = ((angle - 90) * Math.PI) / 180;
    return {
      x: cx + r * Math.cos(rad),
      y: cy + r * Math.sin(rad),
    };
  };

  const describeArc = (
    x: number,
    y: number,
    r: number,
    startAng: number,
    endAng: number
  ) => {
    const start = polarToCartesian(x, y, r, endAng);
    const end = polarToCartesian(x, y, r, startAng);
    const largeArcFlag = endAng - startAng <= 180 ? 0 : 1;

    return [
      'M',
      start.x,
      start.y,
      'A',
      r,
      r,
      0,
      largeArcFlag,
      0,
      end.x,
      end.y,
    ].join(' ');
  };

  const backgroundArc = describeArc(center, center, radius, startAngle, endAngle);
  const valueArc = describeArc(
    center,
    center,
    radius,
    startAngle,
    startAngle + valueAngle
  );

  return (
    <Box
      data-testid={testId}
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        width: size,
      }}
    >
      {title && (
        <Typography
          variant="subtitle2"
          color="text.secondary"
          gutterBottom
          align="center"
        >
          {title}
        </Typography>
      )}
      <Box sx={{ position: 'relative', width: size, height: size * 0.75 }}>
        <svg
          width={size}
          height={size * 0.75}
          viewBox={`0 0 ${size} ${size * 0.75}`}
          style={{ overflow: 'visible' }}
        >
          {/* Background arc */}
          <path
            d={backgroundArc}
            fill="none"
            stroke={colors.background}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
          />
          {/* Value arc */}
          <path
            d={valueArc}
            fill="none"
            stroke={gaugeColor}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            style={
              animated
                ? {
                    transition: 'stroke-dashoffset 1s ease-out, stroke 0.3s ease',
                  }
                : undefined
            }
          />
          {/* Tick marks */}
          {[0, 25, 50, 75, 100].map((tick) => {
            const tickAngle = startAngle + (tick / 100) * totalAngle;
            const innerPoint = polarToCartesian(center, center, radius - 8, tickAngle);
            const outerPoint = polarToCartesian(center, center, radius + 8, tickAngle);
            return (
              <line
                key={tick}
                x1={innerPoint.x}
                y1={innerPoint.y}
                x2={outerPoint.x}
                y2={outerPoint.y}
                stroke={theme.palette.text.disabled}
                strokeWidth={2}
              />
            );
          })}
        </svg>
        {/* Center content */}
        <Box
          sx={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -20%)',
            textAlign: 'center',
          }}
        >
          {showValue && (
            <Typography
              variant="h4"
              fontWeight="bold"
              sx={{ color: gaugeColor }}
            >
              {Math.round(normalizedValue)}
              {valueSuffix && (
                <Typography
                  component="span"
                  variant="h6"
                  sx={{ color: gaugeColor }}
                >
                  {valueSuffix}
                </Typography>
              )}
            </Typography>
          )}
          {showLabel && (
            <Typography
              variant="caption"
              sx={{
                color: gaugeColor,
                fontWeight: 'medium',
                textTransform: 'uppercase',
                letterSpacing: 0.5,
              }}
            >
              {getRiskLabel(riskLevel)}
            </Typography>
          )}
        </Box>
      </Box>
    </Box>
  );
};

export default RiskGauge;
