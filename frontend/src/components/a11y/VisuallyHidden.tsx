/**
 * Visually Hidden Component
 *
 * Hides content visually while keeping it accessible to screen readers.
 * Used for providing additional context for assistive technologies.
 */

import React from 'react';
import { styled } from '@mui/material';

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

const HiddenElement = styled('span', {
  shouldForwardProp: (prop) => prop !== 'focusable',
})<{ focusable?: boolean }>(({ focusable }) => ({
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
}));

export const VisuallyHidden: React.FC<VisuallyHiddenProps> = ({
  children,
  as = 'span',
  focusable = false,
  testId,
}) => {
  return (
    <HiddenElement
      as={as}
      focusable={focusable}
      data-testid={testId}
    >
      {children}
    </HiddenElement>
  );
};

/**
 * Screen reader only text component (alias for VisuallyHidden)
 */
export const SrOnly = VisuallyHidden;

export default VisuallyHidden;
