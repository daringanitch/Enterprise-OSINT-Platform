/**
 * Visually Hidden Component
 *
 * Hides content visually while keeping it accessible to screen readers.
 * Used for providing additional context for assistive technologies.
 */

import React from 'react';
import { Box, SxProps, Theme } from '@mui/material';

export interface VisuallyHiddenProps {
  /** Content to hide visually */
  children: React.ReactNode;
  /** HTML element to render as */
  as?: 'span' | 'div' | 'label' | 'h1' | 'h2' | 'h3' | 'h4' | 'h5' | 'h6' | 'p';
  /** Make visible when focused (for skip links) */
  focusable?: boolean;
  /** Test ID for testing */
  testId?: string;
}

const getHiddenStyles = (focusable: boolean): SxProps<Theme> => ({
  position: 'absolute',
  width: '1px',
  height: '1px',
  padding: 0,
  margin: '-1px',
  overflow: 'hidden',
  clip: 'rect(0, 0, 0, 0)',
  whiteSpace: 'nowrap',
  border: 0,
  ...(focusable && {
    '&:focus, &:active': {
      position: 'static',
      width: 'auto',
      height: 'auto',
      padding: 'inherit',
      margin: 'inherit',
      overflow: 'visible',
      clip: 'auto',
      whiteSpace: 'normal',
    },
  }),
});

export const VisuallyHidden: React.FC<VisuallyHiddenProps> = ({
  children,
  as: Component = 'span',
  focusable = false,
  testId,
}) => {
  return (
    <Box
      component={Component}
      sx={getHiddenStyles(focusable)}
      data-testid={testId}
    >
      {children}
    </Box>
  );
};

/**
 * Screen reader only text component (alias for VisuallyHidden)
 */
export const SrOnly = VisuallyHidden;

export default VisuallyHidden;
