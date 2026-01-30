/**
 * AreaChart Component
 *
 * Responsive area chart for visualizing trends and volumes over time.
 */

import React, { useMemo } from 'react';
import {
  AreaChart as RechartsAreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import { Box, Typography, useTheme, alpha } from '@mui/material';

export interface AreaChartDataPoint {
  [key: string]: string | number;
}

export interface AreaConfig {
  dataKey: string;
  name?: string;
  color?: string;
  fillOpacity?: number;
  stackId?: string;
  type?: 'monotone' | 'linear' | 'step';
}

export interface AreaChartProps {
  /** Chart data points */
  data: AreaChartDataPoint[];
  /** Configuration for each area */
  areas: AreaConfig[];
  /** Key for X-axis values */
  xAxisKey: string;
  /** Chart title */
  title?: string;
  /** Chart height in pixels */
  height?: number;
  /** Show grid lines */
  showGrid?: boolean;
  /** Show legend */
  showLegend?: boolean;
  /** Use gradient fill */
  gradient?: boolean;
  /** X-axis label */
  xAxisLabel?: string;
  /** Y-axis label */
  yAxisLabel?: string;
  /** Custom tooltip formatter */
  tooltipFormatter?: (value: number, name: string) => string;
  /** Test ID for testing */
  testId?: string;
}

const defaultColors = [
  '#1976d2', // blue
  '#2e7d32', // green
  '#ed6c02', // orange
  '#9c27b0', // purple
  '#d32f2f', // red
];

export const AreaChart: React.FC<AreaChartProps> = ({
  data,
  areas,
  xAxisKey,
  title,
  height = 300,
  showGrid = true,
  showLegend = true,
  gradient = true,
  xAxisLabel,
  yAxisLabel,
  tooltipFormatter,
  testId,
}) => {
  const theme = useTheme();

  const areasWithDefaults = useMemo(
    () =>
      areas.map((area, index) => ({
        ...area,
        color: area.color || defaultColors[index % defaultColors.length],
        fillOpacity: area.fillOpacity ?? 0.3,
        name: area.name || area.dataKey,
        type: area.type || 'monotone',
      })),
    [areas]
  );

  const customTooltip = ({ active, payload, label }: any) => {
    if (!active || !payload?.length) return null;

    return (
      <Box
        sx={{
          bgcolor: 'background.paper',
          border: 1,
          borderColor: 'divider',
          borderRadius: 1,
          p: 1.5,
          boxShadow: 2,
        }}
      >
        <Typography variant="body2" fontWeight="bold" gutterBottom>
          {label}
        </Typography>
        {payload.map((entry: any, index: number) => (
          <Typography key={index} variant="body2" sx={{ color: entry.color }}>
            {entry.name}:{' '}
            {tooltipFormatter
              ? tooltipFormatter(entry.value, entry.name)
              : entry.value}
          </Typography>
        ))}
      </Box>
    );
  };

  return (
    <Box data-testid={testId} sx={{ width: '100%' }}>
      {title && (
        <Typography variant="h6" gutterBottom align="center">
          {title}
        </Typography>
      )}
      <ResponsiveContainer width="100%" height={height}>
        <RechartsAreaChart
          data={data}
          margin={{ top: 5, right: 30, left: 20, bottom: 25 }}
        >
          {gradient && (
            <defs>
              {areasWithDefaults.map((area) => (
                <linearGradient
                  key={`gradient-${area.dataKey}`}
                  id={`gradient-${area.dataKey}`}
                  x1="0"
                  y1="0"
                  x2="0"
                  y2="1"
                >
                  <stop
                    offset="5%"
                    stopColor={area.color}
                    stopOpacity={0.8}
                  />
                  <stop
                    offset="95%"
                    stopColor={area.color}
                    stopOpacity={0.1}
                  />
                </linearGradient>
              ))}
            </defs>
          )}
          {showGrid && (
            <CartesianGrid
              strokeDasharray="3 3"
              stroke={theme.palette.divider}
            />
          )}
          <XAxis
            dataKey={xAxisKey}
            tick={{ fill: theme.palette.text.secondary, fontSize: 12 }}
            axisLine={{ stroke: theme.palette.divider }}
            label={
              xAxisLabel
                ? {
                    value: xAxisLabel,
                    position: 'bottom',
                    offset: 0,
                    fill: theme.palette.text.secondary,
                  }
                : undefined
            }
          />
          <YAxis
            tick={{ fill: theme.palette.text.secondary, fontSize: 12 }}
            axisLine={{ stroke: theme.palette.divider }}
            label={
              yAxisLabel
                ? {
                    value: yAxisLabel,
                    angle: -90,
                    position: 'insideLeft',
                    fill: theme.palette.text.secondary,
                  }
                : undefined
            }
          />
          <Tooltip content={customTooltip} />
          {showLegend && (
            <Legend
              formatter={(value) => (
                <span style={{ color: theme.palette.text.primary }}>
                  {value}
                </span>
              )}
            />
          )}
          {areasWithDefaults.map((area) => (
            <Area
              key={area.dataKey}
              type={area.type as any}
              dataKey={area.dataKey}
              name={area.name}
              stroke={area.color}
              fill={gradient ? `url(#gradient-${area.dataKey})` : area.color}
              fillOpacity={gradient ? 1 : area.fillOpacity}
              stackId={area.stackId}
              strokeWidth={2}
            />
          ))}
        </RechartsAreaChart>
      </ResponsiveContainer>
    </Box>
  );
};

export default AreaChart;
