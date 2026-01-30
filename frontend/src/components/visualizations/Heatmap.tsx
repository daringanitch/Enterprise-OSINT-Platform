/**
 * Heatmap Component
 *
 * Grid-based heatmap for visualizing matrix data with color intensity.
 */

import React, { useMemo } from 'react';
import { Box, Typography, useTheme, Tooltip as MuiTooltip, Paper } from '@mui/material';

export interface HeatmapCell {
  row: string;
  column: string;
  value: number;
  label?: string;
}

export interface HeatmapProps {
  /** Heatmap data cells */
  data: HeatmapCell[];
  /** Chart title */
  title?: string;
  /** Row labels (optional - auto-detected from data) */
  rows?: string[];
  /** Column labels (optional - auto-detected from data) */
  columns?: string[];
  /** Cell size in pixels */
  cellSize?: number;
  /** Minimum value for color scale */
  minValue?: number;
  /** Maximum value for color scale */
  maxValue?: number;
  /** Low value color */
  minColor?: string;
  /** High value color */
  maxColor?: string;
  /** Show value in cells */
  showValues?: boolean;
  /** Show legend */
  showLegend?: boolean;
  /** Cell click handler */
  onCellClick?: (cell: HeatmapCell) => void;
  /** Value formatter */
  formatValue?: (value: number) => string;
  /** Test ID for testing */
  testId?: string;
}

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

const getContrastColor = (hexColor: string): string => {
  const r = parseInt(hexColor.slice(1, 3), 16);
  const g = parseInt(hexColor.slice(3, 5), 16);
  const b = parseInt(hexColor.slice(5, 7), 16);
  const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
  return luminance > 0.5 ? '#000000' : '#ffffff';
};

export const Heatmap: React.FC<HeatmapProps> = ({
  data,
  title,
  rows: propRows,
  columns: propColumns,
  cellSize = 50,
  minValue: propMinValue,
  maxValue: propMaxValue,
  minColor = '#e3f2fd',
  maxColor = '#1565c0',
  showValues = true,
  showLegend = true,
  onCellClick,
  formatValue = (v) => v.toFixed(1),
  testId,
}) => {
  const theme = useTheme();

  // Extract unique rows and columns from data if not provided
  const rows = useMemo(() => {
    if (propRows) return propRows;
    const uniqueRows = new Set(data.map((d) => d.row));
    return Array.from(uniqueRows);
  }, [data, propRows]);

  const columns = useMemo(() => {
    if (propColumns) return propColumns;
    const uniqueCols = new Set(data.map((d) => d.column));
    return Array.from(uniqueCols);
  }, [data, propColumns]);

  // Build data matrix
  const matrix = useMemo(() => {
    const map = new Map<string, HeatmapCell>();
    data.forEach((cell) => {
      map.set(`${cell.row}-${cell.column}`, cell);
    });
    return map;
  }, [data]);

  // Calculate value range
  const { minValue, maxValue } = useMemo(() => {
    const values = data.map((d) => d.value);
    return {
      minValue: propMinValue ?? Math.min(...values),
      maxValue: propMaxValue ?? Math.max(...values),
    };
  }, [data, propMinValue, propMaxValue]);

  const valueRange = maxValue - minValue || 1;

  const getCellColor = (value: number): string => {
    const normalizedValue = (value - minValue) / valueRange;
    return interpolateColor(minColor, maxColor, Math.max(0, Math.min(1, normalizedValue)));
  };

  const labelWidth = 100;
  const legendWidth = showLegend ? 80 : 0;

  if (data.length === 0) {
    return (
      <Box data-testid={testId} sx={{ textAlign: 'center', py: 4 }}>
        <Typography color="text.secondary">No data to display</Typography>
      </Box>
    );
  }

  return (
    <Box data-testid={testId}>
      {title && (
        <Typography variant="h6" gutterBottom>
          {title}
        </Typography>
      )}
      <Box sx={{ display: 'flex', gap: 2 }}>
        <Box sx={{ overflow: 'auto' }}>
          {/* Column headers */}
          <Box sx={{ display: 'flex', ml: `${labelWidth}px` }}>
            {columns.map((col) => (
              <Box
                key={col}
                sx={{
                  width: cellSize,
                  height: 40,
                  display: 'flex',
                  alignItems: 'flex-end',
                  justifyContent: 'center',
                  px: 0.5,
                }}
              >
                <Typography
                  variant="caption"
                  sx={{
                    writingMode: 'vertical-rl',
                    transform: 'rotate(180deg)',
                    textAlign: 'left',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    maxHeight: 80,
                  }}
                >
                  {col}
                </Typography>
              </Box>
            ))}
          </Box>

          {/* Rows */}
          {rows.map((row) => (
            <Box key={row} sx={{ display: 'flex', alignItems: 'center' }}>
              {/* Row label */}
              <Box
                sx={{
                  width: labelWidth,
                  pr: 1,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'flex-end',
                }}
              >
                <Typography
                  variant="caption"
                  noWrap
                  sx={{ maxWidth: labelWidth - 8 }}
                >
                  {row}
                </Typography>
              </Box>

              {/* Cells */}
              {columns.map((col) => {
                const cell = matrix.get(`${row}-${col}`);
                const value = cell?.value ?? 0;
                const cellColor = getCellColor(value);
                const textColor = getContrastColor(cellColor);

                return (
                  <MuiTooltip
                    key={`${row}-${col}`}
                    title={
                      <Box>
                        <Typography variant="caption" display="block">
                          {row} × {col}
                        </Typography>
                        <Typography variant="body2" fontWeight="bold">
                          {cell?.label || formatValue(value)}
                        </Typography>
                      </Box>
                    }
                    arrow
                  >
                    <Box
                      onClick={() => cell && onCellClick?.(cell)}
                      sx={{
                        width: cellSize,
                        height: cellSize,
                        bgcolor: cellColor,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        border: 1,
                        borderColor: theme.palette.divider,
                        cursor: onCellClick ? 'pointer' : 'default',
                        transition: 'transform 0.1s, box-shadow 0.1s',
                        '&:hover': onCellClick
                          ? {
                              transform: 'scale(1.05)',
                              boxShadow: 2,
                              zIndex: 1,
                            }
                          : undefined,
                      }}
                    >
                      {showValues && (
                        <Typography
                          variant="caption"
                          sx={{
                            color: textColor,
                            fontWeight: 'medium',
                            fontSize: cellSize < 40 ? '0.65rem' : '0.75rem',
                          }}
                        >
                          {formatValue(value)}
                        </Typography>
                      )}
                    </Box>
                  </MuiTooltip>
                );
              })}
            </Box>
          ))}
        </Box>

        {/* Legend */}
        {showLegend && (
          <Box
            sx={{
              width: legendWidth,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              pt: 5,
            }}
          >
            <Typography variant="caption" gutterBottom>
              {formatValue(maxValue)}
            </Typography>
            <Box
              sx={{
                width: 20,
                height: 150,
                background: `linear-gradient(to bottom, ${maxColor}, ${minColor})`,
                borderRadius: 1,
                border: 1,
                borderColor: 'divider',
              }}
            />
            <Typography variant="caption" sx={{ mt: 1 }}>
              {formatValue(minValue)}
            </Typography>
          </Box>
        )}
      </Box>
    </Box>
  );
};

export default Heatmap;
