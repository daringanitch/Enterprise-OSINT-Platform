/**
 * Login Page
 */

import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Box,
  Typography,
  TextField,
  Button,
  Alert,
  styled,
  keyframes,
} from '@mui/material';
import { motion } from 'framer-motion';
import { useAuth } from '../hooks/useAuth';
import { cyberColors, designTokens, glassmorphism } from '../utils/theme';

const pulse = keyframes`
  0%, 100% { opacity: 1; }
  50% { opacity: 0.7; }
`;

const PageContainer = styled(Box)({
  minHeight: '100vh',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  backgroundColor: cyberColors.dark.void,
  backgroundImage: `
    radial-gradient(circle at 20% 80%, ${cyberColors.neon.cyan}10 0%, transparent 50%),
    radial-gradient(circle at 80% 20%, ${cyberColors.neon.magenta}10 0%, transparent 50%)
  `,
});

const LoginCard = styled(motion.div)({
  ...glassmorphism.card,
  padding: 48,
  width: '100%',
  maxWidth: 420,
  borderRadius: designTokens.borderRadius.lg,
});

const Logo = styled(Typography)({
  fontFamily: designTokens.typography.fontFamily.display,
  fontSize: '1.75rem',
  fontWeight: 700,
  color: cyberColors.neon.cyan,
  textShadow: `0 0 20px ${cyberColors.neon.cyan}`,
  textAlign: 'center',
  marginBottom: 8,
  animation: `${pulse} 3s ease-in-out infinite`,
});

const Subtitle = styled(Typography)({
  color: cyberColors.text.secondary,
  textAlign: 'center',
  marginBottom: 32,
  fontSize: '0.875rem',
});

const StyledTextField = styled(TextField)({
  marginBottom: 16,
  '& .MuiOutlinedInput-root': {
    color: cyberColors.text.primary,
    backgroundColor: cyberColors.dark.slate,
    '& fieldset': {
      borderColor: cyberColors.border.subtle,
    },
    '&:hover fieldset': {
      borderColor: cyberColors.neon.cyan,
    },
    '&.Mui-focused fieldset': {
      borderColor: cyberColors.neon.cyan,
      boxShadow: `0 0 10px ${cyberColors.neon.cyan}40`,
    },
  },
  '& .MuiInputLabel-root': {
    color: cyberColors.text.secondary,
    '&.Mui-focused': {
      color: cyberColors.neon.cyan,
    },
  },
});

const LoginButton = styled(Button)({
  marginTop: 16,
  padding: '12px 24px',
  fontFamily: designTokens.typography.fontFamily.display,
  fontWeight: 600,
  backgroundColor: cyberColors.neon.cyan,
  color: cyberColors.dark.void,
  '&:hover': {
    backgroundColor: cyberColors.neon.electricBlue,
    boxShadow: `0 0 20px ${cyberColors.neon.cyan}60`,
  },
  '&:disabled': {
    backgroundColor: cyberColors.dark.ash,
    color: cyberColors.text.muted,
  },
});

const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { login, error, isLoading } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const from = (location.state as { from?: { pathname: string } })?.from?.pathname || '/dashboard';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const success = await login(email, password);
    if (success) {
      navigate(from, { replace: true });
    }
  };

  return (
    <PageContainer>
      <LoginCard
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <Logo>OSINT PLATFORM</Logo>
        <Subtitle>Enterprise Intelligence Analysis</Subtitle>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <form onSubmit={handleSubmit}>
          <StyledTextField
            fullWidth
            label="Username"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="username"
            autoFocus
          />
          <StyledTextField
            fullWidth
            label="Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
          <LoginButton
            type="submit"
            fullWidth
            variant="contained"
            disabled={isLoading || !email || !password}
          >
            {isLoading ? 'Authenticating...' : 'Access System'}
          </LoginButton>
        </form>

        <Typography
          variant="caption"
          sx={{
            display: 'block',
            textAlign: 'center',
            mt: 3,
            color: cyberColors.text.muted,
            fontFamily: designTokens.typography.fontFamily.mono,
          }}
        >
          Demo: admin / admin123
        </Typography>
      </LoginCard>
    </PageContainer>
  );
};

export default LoginPage;
