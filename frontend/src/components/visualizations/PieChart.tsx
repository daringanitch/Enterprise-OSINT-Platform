/**
 * PieChart Component
 *
 * Responsive pie/donut chart for proportional data visualization.
 */

import React, { useState, useMemo } from 'react';
import {
  PieChart as RechartsPieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Sector,
} from 'recharts';
import { Box, Typography, useTheme } from '@mui/material';

export interface PieChartDataPoint {
  name: string;
  value: number;
  color?: string;
}

export interface PieChartProps {
  /** Chart data points */
  data: PieChartDataPoint[];
  /** Chart title */
  title?: string;
  /** Chart height in pixels */
  height?: number;
  /** Show as donut chart */
  donut?: boolean;
  /** Inner radius for donut (0-1 as percentage) */
  innerRadiusRatio?: number;
  /** Show legend */
  showLegend?: boolean;
  /** Show labels on slices */
  showLabels?: boolean;
  /** Show percentage in labels */
  showPercentage?: boolean;
  /** Enable active slice expansion on hover */
  activeOnHover?: boolean;
  /** Center label (for donut chart) */
  centerLabel?: string;
  /** Center value (for donut chart) */
  centerValue?: string | number;
  /** Custom color palette */
  colors?: string[];
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
  '#00695c', // teal
  '#c2185b', // pink
];

const renderActiveShape = (props: any) => {
  const {
    cx,
    cy,
    innerRadius,
    outerRadius,
    startAngle,
    endAngle,
    fill,
    payload,
    percent,
    value,
  } = props;

  return (
    <g>
      <Sector
        cx={cx}
        cy={cy}
        innerRadius={innerRadius}
        outerRadius={outerRadius + 8}
        startAngle={startAngle}
        endAngle={endAngle}
        fill={fill}
      />
      <Sector
        cx={cx}
        cy={cy}
        startAngle={startAngle}
        endAngle={endAngle}
        innerRadius={outerRadius + 10}
        outerRadius={outerRadius + 12}
        fill={fill}
      />
      <text
        x={cx}
        y={cy - 10}
        textAnchor="middle"
        fill="#333"
        fontSize={14}
        fontWeight="bold"
      >
        {payload.name}
      </text>
      <text x={cx} y={cy + 10} textAnchor="middle" fill="#666" fontSize={12}>
        {value} ({(percent * 100).toFixed(1)}%)
      </text>
    </g>
  );
};

export const PieChart: React.FC<PieChartProps> = ({
  data,
  title,
  height = 300,
  donut = false,
  innerRadiusRatio = 0.6,
  showLegend = true,
  showLabels = false,
  showPercentage = true,
  activeOnHover = true,
  centerLabel,
  centerValue,
  colors = defaultColors,
  testId,
}) => {
  const theme = useTheme();
  const [activeIndex, setActiveIndex] = useState<number | undefined>(undefined);

  const total = useMemo(
    () => data.reduce((sum, item) => sum + item.value, 0),
    [data]
  );

  const dataWithColors = useMemo(
    () =>
      data.map((item, index) => ({
        ...item,
        color: item.color || colors[index % colors.length],
      })),
    [data, colors]
  );

  const onPieEnter = (_: any, index: number) => {
    if (activeOnHover) {
      setActiveIndex(index);
    }
  };

  const onPieLeave = () => {
    setActiveIndex(undefined);
  };

  const customTooltip = ({ active, payload }: any) => {
    if (!active || !payload?.length) return null;

    const item = payload[0];
    const percentage = ((item.value / total) * 100).toFixed(1);

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
        <Typography variant="body2" fontWeight="bold" sx={{ color: item.payload.color }}>
          {item.name}
        </Typography>
        <Typography variant="body2">
          Value: {item.value}
        </Typography>
        {showPercentage && (
          <Typography variant="body2" color="text.secondary">
            {percentage}%
          </Typography>
        )}
      </Box>
    );
  };

  const renderCustomLabel = ({
    cx,
    cy,
    midAngle,
    innerRadius,
    outerRadius,
    percent,
    name,
  }: any) => {
    const RADIAN = Math.PI / 180;
    const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
    const x = cx + radius * Math.cos(-midAngle * RADIAN);
    const y = cy + radius * Math.sin(-midAngle * RADIAN);

    if (percent < 0.05) return null; // Don't show label for small slices

    return (
      <text
        x={x}
        y={y}
        fill="white"
        textAnchor="middle"
        dominantBaseline="central"
        fontSize={12}
        fontWeight="bold"
      >
        {showPercentage ? `${(percent * 100).toFixed(0)}%` : name}
      </text>
    );
  };

  const outerRadius = (height - 60) / 2 - 20;
  const innerRadius = donut ? outerRadius * innerRadiusRatio : 0;

  return (
    <Box data-testid={testId} sx={{ width: '100%' }}>
      {title && (
        <Typography variant="h6" gutterBottom align="center">
          {title}
        </Typography>
      )}
      <ResponsiveContainer width="100%" height={height}>
        <RechartsPieChart>
          <Pie
            data={dataWithColors}
            cx="50%"
            cy="50%"
            innerRadius={innerRadius}
            outerRadius={outerRadius}
            dataKey="value"
            nameKey="name"
            onMouseEnter={onPieEnter}
            onMouseLeave={onPieLeave}
            activeIndex={activeIndex}
            activeShape={activeOnHover ? renderActiveShape : undefined}
            label={showLabels && !activeOnHover ? renderCustomLabel : undefined}
            labelLine={false}
          >
            {dataWithColors.map((entry, index) => (
              <Cell
                key={`cell-${index}`}
                fill={entry.color}
                stroke={theme.palette.background.paper}
                strokeWidth={2}
              />
            ))}
          </Pie>
          <Tooltip content={customTooltip} />
          {showLegend && (
            <Legend
              layout="horizontal"
              verticalAlign="bottom"
              align="center"
              formatter={(value, entry: any) => (
                <span style={{ color: theme.palette.text.primary }}>
                  {value} ({entry.payload.value})
                </span>
              )}
            />
          )}
          {donut && (centerLabel || centerValue) && (
            <text
              x="50%"
              y="50%"
              textAnchor="middle"
              dominantBaseline="middle"
            >
              {centerValue && (
                <tspan
                  x="50%"
                  dy="-0.5em"
                  fontSize={24}
                  fontWeight="bold"
                  fill={theme.palette.text.primary}
                >
                  {centerValue}
                </tspan>
              )}
              {centerLabel && (
                <tspan
                  x="50%"
                  dy={centerValue ? '1.5em' : '0'}
                  fontSize={12}
                  fill={theme.palette.text.secondary}
                >
                  {centerLabel}
                </tspan>
              )}
            </text>
          )}
        </RechartsPieChart>
      </ResponsiveContainer>
    </Box>
  );
};

export default PieChart;
