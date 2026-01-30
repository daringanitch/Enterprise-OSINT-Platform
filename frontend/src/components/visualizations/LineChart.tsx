/**
 * LineChart Component
 *
 * Responsive line chart for time series data visualization.
 */

import React, { useMemo } from 'react';
import {
  LineChart as RechartsLineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';
import { Box, Typography, useTheme } from '@mui/material';

export interface LineChartDataPoint {
  [key: string]: string | number;
}

export interface LineConfig {
  dataKey: string;
  name?: string;
  color?: string;
  strokeWidth?: number;
  strokeDasharray?: string;
  dot?: boolean;
}

export interface LineChartProps {
  /** Chart data points */
  data: LineChartDataPoint[];
  /** Configuration for each line */
  lines: LineConfig[];
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
  /** X-axis label */
  xAxisLabel?: string;
  /** Y-axis label */
  yAxisLabel?: string;
  /** Reference line value */
  referenceLine?: { value: number; label?: string; color?: string };
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
  '#0288d1', // light blue
];

export const LineChart: React.FC<LineChartProps> = ({
  data,
  lines,
  xAxisKey,
  title,
  height = 300,
  showGrid = true,
  showLegend = true,
  xAxisLabel,
  yAxisLabel,
  referenceLine,
  tooltipFormatter,
  testId,
}) => {
  const theme = useTheme();

  const linesWithDefaults = useMemo(
    () =>
      lines.map((line, index) => ({
        ...line,
        color: line.color || defaultColors[index % defaultColors.length],
        strokeWidth: line.strokeWidth || 2,
        dot: line.dot !== false,
        name: line.name || line.dataKey,
      })),
    [lines]
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
          <Typography
            key={index}
            variant="body2"
            sx={{ color: entry.color }}
          >
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
        <RechartsLineChart
          data={data}
          margin={{ top: 5, right: 30, left: 20, bottom: 25 }}
        >
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
              wrapperStyle={{ paddingTop: 10 }}
              formatter={(value) => (
                <span style={{ color: theme.palette.text.primary }}>
                  {value}
                </span>
              )}
            />
          )}
          {referenceLine && (
            <ReferenceLine
              y={referenceLine.value}
              stroke={referenceLine.color || theme.palette.warning.main}
              strokeDasharray="5 5"
              label={referenceLine.label}
            />
          )}
          {linesWithDefaults.map((line) => (
            <Line
              key={line.dataKey}
              type="monotone"
              dataKey={line.dataKey}
              name={line.name}
              stroke={line.color}
              strokeWidth={line.strokeWidth}
              strokeDasharray={line.strokeDasharray}
              dot={line.dot}
              activeDot={{ r: 6 }}
            />
          ))}
        </RechartsLineChart>
      </ResponsiveContainer>
    </Box>
  );
};

export default LineChart;
