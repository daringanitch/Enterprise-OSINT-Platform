/**
 * BarChart Component
 *
 * Responsive bar chart for categorical data comparison.
 */

import React, { useMemo } from 'react';
import {
  BarChart as RechartsBarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Cell,
  LabelList,
} from 'recharts';
import { Box, Typography, useTheme } from '@mui/material';

export interface BarChartDataPoint {
  [key: string]: string | number;
}

export interface BarConfig {
  dataKey: string;
  name?: string;
  color?: string;
  stackId?: string;
  showLabel?: boolean;
}

export interface BarChartProps {
  /** Chart data points */
  data: BarChartDataPoint[];
  /** Configuration for each bar series */
  bars: BarConfig[];
  /** Key for X-axis (category) values */
  xAxisKey: string;
  /** Chart title */
  title?: string;
  /** Chart height in pixels */
  height?: number;
  /** Show grid lines */
  showGrid?: boolean;
  /** Show legend */
  showLegend?: boolean;
  /** Horizontal bar layout */
  horizontal?: boolean;
  /** Color bars by value using a gradient */
  colorByValue?: boolean;
  /** Min color for gradient (low values) */
  minColor?: string;
  /** Max color for gradient (high values) */
  maxColor?: string;
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
  '#0288d1', // light blue
];

const interpolateColor = (
  color1: string,
  color2: string,
  factor: number
): string => {
  const hex = (x: number) => {
    const h = Math.round(x).toString(16);
    return h.length === 1 ? '0' + h : h;
  };

  const r1 = parseInt(color1.slice(1, 3), 16);
  const g1 = parseInt(color1.slice(3, 5), 16);
  const b1 = parseInt(color1.slice(5, 7), 16);

  const r2 = parseInt(color2.slice(1, 3), 16);
  const g2 = parseInt(color2.slice(3, 5), 16);
  const b2 = parseInt(color2.slice(5, 7), 16);

  const r = r1 + factor * (r2 - r1);
  const g = g1 + factor * (g2 - g1);
  const b = b1 + factor * (b2 - b1);

  return `#${hex(r)}${hex(g)}${hex(b)}`;
};

export const BarChart: React.FC<BarChartProps> = ({
  data,
  bars,
  xAxisKey,
  title,
  height = 300,
  showGrid = true,
  showLegend = true,
  horizontal = false,
  colorByValue = false,
  minColor = '#4caf50',
  maxColor = '#f44336',
  xAxisLabel,
  yAxisLabel,
  tooltipFormatter,
  testId,
}) => {
  const theme = useTheme();

  const barsWithDefaults = useMemo(
    () =>
      bars.map((bar, index) => ({
        ...bar,
        color: bar.color || defaultColors[index % defaultColors.length],
        name: bar.name || bar.dataKey,
      })),
    [bars]
  );

  const getBarColors = useMemo(() => {
    if (!colorByValue || bars.length !== 1) return null;

    const dataKey = bars[0].dataKey;
    const values = data.map((d) => d[dataKey] as number);
    const min = Math.min(...values);
    const max = Math.max(...values);
    const range = max - min || 1;

    return data.map((d) => {
      const value = d[dataKey] as number;
      const factor = (value - min) / range;
      return interpolateColor(minColor, maxColor, factor);
    });
  }, [data, bars, colorByValue, minColor, maxColor]);

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

  const Chart = horizontal ? (
    <RechartsBarChart
      data={data}
      layout="vertical"
      margin={{ top: 5, right: 30, left: 60, bottom: 25 }}
    >
      {showGrid && (
        <CartesianGrid strokeDasharray="3 3" stroke={theme.palette.divider} />
      )}
      <XAxis
        type="number"
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
        type="category"
        dataKey={xAxisKey}
        tick={{ fill: theme.palette.text.secondary, fontSize: 12 }}
        axisLine={{ stroke: theme.palette.divider }}
        width={80}
      />
      <Tooltip content={customTooltip} />
      {showLegend && bars.length > 1 && (
        <Legend
          formatter={(value) => (
            <span style={{ color: theme.palette.text.primary }}>{value}</span>
          )}
        />
      )}
      {barsWithDefaults.map((bar) => (
        <Bar
          key={bar.dataKey}
          dataKey={bar.dataKey}
          name={bar.name}
          fill={bar.color}
          stackId={bar.stackId}
          radius={[0, 4, 4, 0]}
        >
          {colorByValue &&
            getBarColors?.map((color, index) => (
              <Cell key={`cell-${index}`} fill={color} />
            ))}
          {bar.showLabel && (
            <LabelList
              dataKey={bar.dataKey}
              position="right"
              fill={theme.palette.text.primary}
              fontSize={12}
            />
          )}
        </Bar>
      ))}
    </RechartsBarChart>
  ) : (
    <RechartsBarChart
      data={data}
      margin={{ top: 5, right: 30, left: 20, bottom: 25 }}
    >
      {showGrid && (
        <CartesianGrid strokeDasharray="3 3" stroke={theme.palette.divider} />
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
      {showLegend && bars.length > 1 && (
        <Legend
          formatter={(value) => (
            <span style={{ color: theme.palette.text.primary }}>{value}</span>
          )}
        />
      )}
      {barsWithDefaults.map((bar) => (
        <Bar
          key={bar.dataKey}
          dataKey={bar.dataKey}
          name={bar.name}
          fill={bar.color}
          stackId={bar.stackId}
          radius={[4, 4, 0, 0]}
        >
          {colorByValue &&
            getBarColors?.map((color, index) => (
              <Cell key={`cell-${index}`} fill={color} />
            ))}
          {bar.showLabel && (
            <LabelList
              dataKey={bar.dataKey}
              position="top"
              fill={theme.palette.text.primary}
              fontSize={12}
            />
          )}
        </Bar>
      ))}
    </RechartsBarChart>
  );

  return (
    <Box data-testid={testId} sx={{ width: '100%' }}>
      {title && (
        <Typography variant="h6" gutterBottom align="center">
          {title}
        </Typography>
      )}
      <ResponsiveContainer width="100%" height={height}>
        {Chart}
      </ResponsiveContainer>
    </Box>
  );
};

export default BarChart;
