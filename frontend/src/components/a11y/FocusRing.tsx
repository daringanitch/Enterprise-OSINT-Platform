/**
 * Focus Ring Component
 *
 * Provides consistent focus indicators for keyboard navigation.
 * Follows WCAG 2.1 Focus Visible requirements.
 */

import React, { useEffect, useState } from 'react';
import { styled, GlobalStyles } from '@mui/material';
import { designTokens } from '../../utils/theme';

/**
 * Global focus styles that apply :focus-visible patterns
 */
export const FocusStyles: React.FC = () => {
  return (
    <GlobalStyles
      styles={{
        // Remove default focus outline
        '*:focus': {
          outline: 'none',
        },
        // Apply focus ring only on keyboard navigation
        '*:focus-visible': {
          outline: `2px solid ${designTokens.colors.primary.main}`,
          outlineOffset: '2px',
        },
        // Specific overrides for certain elements
        'button:focus-visible, a:focus-visible': {
          outline: `2px solid ${designTokens.colors.primary.main}`,
          outlineOffset: '2px',
          borderRadius: designTokens.borderRadius.sm,
        },
        'input:focus-visible, textarea:focus-visible, select:focus-visible': {
          outline: 'none',
          boxShadow: `0 0 0 2px ${designTokens.colors.primary.main}`,
        },
        // High contrast mode support
        '@media (forced-colors: active)': {
          '*:focus-visible': {
            outline: '3px solid CanvasText',
            outlineOffset: '2px',
          },
        },
      }}
    />
  );
};

/**
 * Hook to detect keyboard vs mouse navigation
 */
export function useKeyboardNavigation(): boolean {
  const [isKeyboardNav, setIsKeyboardNav] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Tab') {
        setIsKeyboardNav(true);
      }
    };

    const handleMouseDown = () => {
      setIsKeyboardNav(false);
    };

    window.addEventListener('keydown', handleKeyDown);
    window.addEventListener('mousedown', handleMouseDown);

    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      window.removeEventListener('mousedown', handleMouseDown);
    };
  }, []);

  return isKeyboardNav;
}

/**
 * Focus ring wrapper component
 */
export interface FocusRingProps {
  children: React.ReactNode;
  /** Focus ring color */
  color?: string;
  /** Focus ring offset */
  offset?: number;
  /** Focus ring width */
  width?: number;
  /** Border radius */
  borderRadius?: string;
  /** Show ring even on mouse focus */
  alwaysShow?: boolean;
}

const FocusRingWrapper = styled('div', {
  shouldForwardProp: (prop) =>
    !['ringColor', 'ringOffset', 'ringWidth', 'ringBorderRadius', 'alwaysShow', 'isKeyboardNav'].includes(
      prop as string
    ),
})<{
  ringColor: string;
  ringOffset: number;
  ringWidth: number;
  ringBorderRadius: string;
  alwaysShow: boolean;
  isKeyboardNav: boolean;
}>(({ ringColor, ringOffset, ringWidth, ringBorderRadius, alwaysShow, isKeyboardNav }) => ({
  display: 'inline-block',
  position: 'relative',
  '&:focus-within': {
    ...(alwaysShow || isKeyboardNav
      ? {
          '&::after': {
            content: '""',
            position: 'absolute',
            top: -ringOffset - ringWidth,
            left: -ringOffset - ringWidth,
            right: -ringOffset - ringWidth,
            bottom: -ringOffset - ringWidth,
            border: `${ringWidth}px solid ${ringColor}`,
            borderRadius: ringBorderRadius,
            pointerEvents: 'none',
          },
        }
      : {}),
  },
}));

export const FocusRing: React.FC<FocusRingProps> = ({
  children,
  color = designTokens.colors.primary.main,
  offset = 2,
  width = 2,
  borderRadius = designTokens.borderRadius.md,
  alwaysShow = false,
}) => {
  const isKeyboardNav = useKeyboardNavigation();

  return (
    <FocusRingWrapper
      ringColor={color}
      ringOffset={offset}
      ringWidth={width}
      ringBorderRadius={borderRadius}
      alwaysShow={alwaysShow}
      isKeyboardNav={isKeyboardNav}
    >
      {children}
    </FocusRingWrapper>
  );
};

/**
 * Focus indicator dot (for complex components)
 */
export interface FocusIndicatorProps {
  /** Whether element is focused */
  isFocused: boolean;
  /** Position of indicator */
  position?: 'top-left' | 'top-right' | 'bottom-left' | 'bottom-right';
  /** Indicator color */
  color?: string;
  /** Size in pixels */
  size?: number;
}

const IndicatorDot = styled('div', {
  shouldForwardProp: (prop) =>
    !['position', 'indicatorColor', 'indicatorSize', 'isVisible'].includes(prop as string),
})<{
  position: string;
  indicatorColor: string;
  indicatorSize: number;
  isVisible: boolean;
}>(({ position, indicatorColor, indicatorSize, isVisible }) => {
  const positionStyles: Record<string, object> = {
    'top-left': { top: -indicatorSize / 2, left: -indicatorSize / 2 },
    'top-right': { top: -indicatorSize / 2, right: -indicatorSize / 2 },
    'bottom-left': { bottom: -indicatorSize / 2, left: -indicatorSize / 2 },
    'bottom-right': { bottom: -indicatorSize / 2, right: -indicatorSize / 2 },
  };

  return {
    position: 'absolute',
    width: indicatorSize,
    height: indicatorSize,
    borderRadius: '50%',
    backgroundColor: indicatorColor,
    opacity: isVisible ? 1 : 0,
    transition: 'opacity 0.15s ease',
    pointerEvents: 'none',
    boxShadow: `0 0 0 2px ${designTokens.colors.background.paper}`,
    ...positionStyles[position],
  };
});

export const FocusIndicator: React.FC<FocusIndicatorProps> = ({
  isFocused,
  position = 'top-right',
  color = designTokens.colors.primary.main,
  size = 8,
}) => {
  return (
    <IndicatorDot
      position={position}
      indicatorColor={color}
      indicatorSize={size}
      isVisible={isFocused}
      aria-hidden="true"
    />
  );
};

export default FocusRing;
