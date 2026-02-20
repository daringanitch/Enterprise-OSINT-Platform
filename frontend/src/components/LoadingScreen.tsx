/**
 * Loading Screen Component
 *
 * Full-screen loading indicator with cyber aesthetic.
 */

import React from 'react';
import { Box, CircularProgress, Typography, styled, keyframes } from '@mui/material';
import { cyberColors, designTokens } from '../utils/theme';

const pulse = keyframes`
  0%, 100% {
    opacity: 1;
  }
  50% {
    opacity: 0.5;
  }
`;

const glow = keyframes`
  0%, 100% {
    box-shadow: 0 0 20px ${cyberColors.neon.cyan}40;
  }
  50% {
    box-shadow: 0 0 40px ${cyberColors.neon.cyan}80;
  }
`;

const LoadingContainer = styled(Box)({
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'center',
  justifyContent: 'center',
  minHeight: '100vh',
  backgroundColor: cyberColors.dark.charcoal,
  gap: 24,
});

const LogoText = styled(Typography)({
  fontFamily: designTokens.typography.fontFamily.display,
  fontSize: '2rem',
  fontWeight: 700,
  color: cyberColors.neon.cyan,
  textShadow: `0 0 20px ${cyberColors.neon.cyan}`,
  animation: `${pulse} 2s ease-in-out infinite`,
});

const SpinnerContainer = styled(Box)({
  position: 'relative',
  padding: 16,
  borderRadius: '50%',
  animation: `${glow} 2s ease-in-out infinite`,
});

const LoadingScreen: React.FC = () => {
  return (
    <LoadingContainer>
      <LogoText>OSINT PLATFORM</LogoText>
      <SpinnerContainer>
        <CircularProgress
          size={60}
          thickness={2}
          sx={{
            color: cyberColors.neon.cyan,
          }}
        />
      </SpinnerContainer>
      <Typography
        variant="body2"
        sx={{
          color: cyberColors.text.secondary,
          fontFamily: designTokens.typography.fontFamily.mono,
        }}
      >
        Initializing secure connection...
      </Typography>
    </LoadingContainer>
  );
};

export default LoadingScreen;
