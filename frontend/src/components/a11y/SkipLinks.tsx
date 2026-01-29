/**
 * Skip Links Component
 *
 * Provides skip navigation links for keyboard users to bypass
 * repetitive content and jump directly to main sections.
 */

import React from 'react';
import { styled } from '@mui/material';
import { designTokens } from '../../utils/theme';

export interface SkipLink {
  /** Target element ID (without #) */
  targetId: string;
  /** Link text */
  label: string;
}

export interface SkipLinksProps {
  /** Array of skip links to render */
  links?: SkipLink[];
  /** Test ID for testing */
  testId?: string;
}

const defaultLinks: SkipLink[] = [
  { targetId: 'main-content', label: 'Skip to main content' },
  { targetId: 'main-navigation', label: 'Skip to navigation' },
];

const SkipLinksContainer = styled('nav')({
  position: 'absolute',
  top: 0,
  left: 0,
  zIndex: 9999,
});

const SkipLinkStyled = styled('a')({
  position: 'absolute',
  top: '-100px',
  left: '16px',
  padding: '12px 24px',
  backgroundColor: designTokens.colors.primary.main,
  color: '#ffffff',
  textDecoration: 'none',
  fontWeight: designTokens.typography.fontWeights.medium,
  fontSize: designTokens.typography.fontSizes.sm,
  borderRadius: designTokens.borderRadius.md,
  boxShadow: designTokens.shadows.lg,
  transition: 'top 0.2s ease',
  zIndex: 9999,

  '&:focus': {
    top: '16px',
    outline: `2px solid ${designTokens.colors.primary.light}`,
    outlineOffset: '2px',
  },

  '&:hover': {
    backgroundColor: designTokens.colors.primary.light,
  },
});

export const SkipLinks: React.FC<SkipLinksProps> = ({
  links = defaultLinks,
  testId,
}) => {
  const handleClick = (event: React.MouseEvent<HTMLAnchorElement>, targetId: string) => {
    event.preventDefault();
    const target = document.getElementById(targetId);

    if (target) {
      // Make target focusable if it isn't
      if (!target.hasAttribute('tabindex')) {
        target.setAttribute('tabindex', '-1');
      }
      target.focus();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  return (
    <SkipLinksContainer aria-label="Skip links" data-testid={testId}>
      {links.map((link, index) => (
        <SkipLinkStyled
          key={link.targetId}
          href={`#${link.targetId}`}
          onClick={(e) => handleClick(e, link.targetId)}
          style={{ left: `${16 + index * 200}px` }}
          data-testid={testId ? `${testId}-link-${index}` : undefined}
        >
          {link.label}
        </SkipLinkStyled>
      ))}
    </SkipLinksContainer>
  );
};

export default SkipLinks;
