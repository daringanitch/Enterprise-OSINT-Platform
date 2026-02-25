/**
 * Credential Intelligence Page
 *
 * Allows analysts to check email, domain, and password exposure
 * across HIBP, Dehashed, Hudson Rock, and paste sites.
 */

import React, { useState, useCallback, useEffect } from 'react';
import {
  Box,
  Card,
  Typography,
  Chip,
  TextField,
  Button,
  Alert,
  LinearProgress,
  Tabs,
  Tab,
  Paper,
  Grid,
  Divider,
  Tooltip,
  IconButton,
  CircularProgress,
} from '@mui/material';
import {
  Search as SearchIcon,
  Email as EmailIcon,
  Language as DomainIcon,
  Lock as LockIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Security as SecurityIcon,
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon,
  Shield as ShieldIcon,
} from '@mui/icons-material';
import { motion } from 'framer-motion';
import { cyberColors, designTokens, glassmorphism } from '../utils/theme';
import { pageVariants } from '../utils/animations';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface EmailResult {
  risk_level: 'critical' | 'high' | 'medium' | 'low' | 'none';
  risk_score: number;
  hibp_breaches: number;
  hibp_pastes: number;
  hudson_rock: number;
  dehashed: number;
  paste: number;
  summary: string;
}

interface DomainResult {
  risk_level: 'critical' | 'high' | 'medium' | 'low' | 'none';
  risk_score: number;
  hibp_domain: number;
  hudson_rock_domain: number;
  dehashed_domain: number;
  paste_domain: number;
  summary: string;
}

interface PasswordResult {
  is_pwned: boolean;
  pwned_count: number;
}

interface SourceStatus {
  hibp: boolean;
  dehashed: boolean;
  hudson_rock: boolean;
  paste: boolean;
}

interface LoadingState {
  email: boolean;
  domain: boolean;
  password: boolean;
}

// ---------------------------------------------------------------------------
// Styled Components
// ---------------------------------------------------------------------------

const StyledCard = motion(Card);

const RiskBadge: React.FC<{ level: string }> = ({ level }) => {
  const colorMap: Record<string, string> = {
    critical: cyberColors.neon.red,
    high: cyberColors.neon.orange,
    medium: cyberColors.neon.magenta,
    low: cyberColors.neon.cyan,
    none: cyberColors.neon.green,
  };

  return (
    <Chip
      label={level.toUpperCase()}
      size="small"
      sx={{
        backgroundColor: `${colorMap[level]}20`,
        color: colorMap[level],
        borderColor: colorMap[level],
        border: '1px solid',
        fontWeight: 'bold',
        fontSize: '0.75rem',
      }}
    />
  );
};

// ---------------------------------------------------------------------------
// Tab Panel Component
// ---------------------------------------------------------------------------

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = (props) => {
  const { children, value, index } = props;
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`credential-tabpanel-${index}`}
      aria-labelledby={`credential-tab-${index}`}
    >
      {value === index && <Box sx={{ pt: 3 }}>{children}</Box>}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

const CredentialIntelligencePage: React.FC = () => {
  // State management
  const [tabValue, setTabValue] = useState(0);
  const [emailInput, setEmailInput] = useState('');
  const [domainInput, setDomainInput] = useState('');
  const [passwordInput, setPasswordInput] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState<LoadingState>({
    email: false,
    domain: false,
    password: false,
  });
  const [emailResult, setEmailResult] = useState<EmailResult | null>(null);
  const [domainResult, setDomainResult] = useState<DomainResult | null>(null);
  const [passwordResult, setPasswordResult] = useState<PasswordResult | null>(null);
  const [sourceStatus, setSourceStatus] = useState<SourceStatus>({
    hibp: false,
    dehashed: false,
    hudson_rock: false,
    paste: false,
  });
  const [error, setError] = useState('');

  // Get auth token
  const getAuthToken = useCallback((): string | null => {
    return localStorage.getItem('auth_token');
  }, []);

  // Fetch source status on mount
  useEffect(() => {
    const fetchSourceStatus = async () => {
      const token = getAuthToken();
      if (!token) return;

      try {
        const response = await fetch('/api/credentials/status', {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (response.ok) {
          const data = await response.json();
          setSourceStatus(data.sources || {});
        }
      } catch (err) {
        console.error('Failed to fetch source status:', err);
      }
    };

    fetchSourceStatus();
  }, [getAuthToken]);

  // Handle email check
  const handleCheckEmail = useCallback(async () => {
    if (!emailInput.trim()) {
      setError('Please enter an email address');
      return;
    }

    const token = getAuthToken();
    if (!token) {
      setError('Authentication required');
      return;
    }

    setLoading((prev) => ({ ...prev, email: true }));
    setError('');

    try {
      const response = await fetch('/api/credentials/check/email', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ email: emailInput.trim() }),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data: EmailResult = await response.json();
      setEmailResult(data);
    } catch (err) {
      setError(`Failed to check email: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setLoading((prev) => ({ ...prev, email: false }));
    }
  }, [emailInput, getAuthToken]);

  // Handle domain check
  const handleCheckDomain = useCallback(async () => {
    if (!domainInput.trim()) {
      setError('Please enter a domain');
      return;
    }

    const token = getAuthToken();
    if (!token) {
      setError('Authentication required');
      return;
    }

    setLoading((prev) => ({ ...prev, domain: true }));
    setError('');

    try {
      const response = await fetch('/api/credentials/check/domain', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ domain: domainInput.trim() }),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data: DomainResult = await response.json();
      setDomainResult(data);
    } catch (err) {
      setError(`Failed to check domain: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setLoading((prev) => ({ ...prev, domain: false }));
    }
  }, [domainInput, getAuthToken]);

  // Handle password check
  const handleCheckPassword = useCallback(async () => {
    if (!passwordInput.trim()) {
      setError('Please enter a password');
      return;
    }

    const token = getAuthToken();
    if (!token) {
      setError('Authentication required');
      return;
    }

    setLoading((prev) => ({ ...prev, password: true }));
    setError('');

    try {
      const response = await fetch('/api/credentials/check/password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ password: passwordInput }),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data: PasswordResult = await response.json();
      setPasswordResult(data);
    } catch (err) {
      setError(`Failed to check password: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setLoading((prev) => ({ ...prev, password: false }));
    }
  }, [passwordInput, getAuthToken]);

  return (
    <motion.div
      initial="initial"
      animate="animate"
      exit="exit"
      variants={pageVariants}
      style={{ width: '100%' }}
    >
      <Box
        sx={{
          p: 3,
          background: `linear-gradient(135deg, ${cyberColors.dark.charcoal} 0%, ${cyberColors.dark.slate} 100%)`,
          minHeight: '100vh',
        }}
      >
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Typography
            variant="h4"
            sx={{
              fontWeight: 'bold',
              color: cyberColors.text.primary,
              mb: 1,
              textShadow: `0 0 20px ${cyberColors.glow.cyan}`,
            }}
          >
            Credential Intelligence
          </Typography>
          <Typography
            variant="body2"
            sx={{
              color: cyberColors.text.secondary,
            }}
          >
            Monitor email, domain, and password exposure across HIBP, Dehashed, Hudson Rock, and
            paste sites
          </Typography>
        </Box>

        {/* Error Alert */}
        {error && (
          <Alert
            severity="error"
            onClose={() => setError('')}
            sx={{
              mb: 3,
              backgroundColor: `${cyberColors.neon.red}20`,
              borderColor: cyberColors.neon.red,
              color: cyberColors.neon.red,
            }}
          >
            {error}
          </Alert>
        )}

        <Grid container spacing={3}>
          {/* Search Panels */}
          <Grid item xs={12} lg={8}>
            <StyledCard
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
              sx={{
                ...glassmorphism.card,
                p: 3,
              }}
            >
              {/* Tabs */}
              <Paper
                square
                sx={{
                  backgroundColor: 'transparent',
                  borderBottom: `1px solid ${designTokens.colors.border.light}`,
                }}
              >
                <Tabs
                  value={tabValue}
                  onChange={(_, newValue) => setTabValue(newValue)}
                  aria-label="credential checks"
                  sx={{
                    '& .MuiTabs-indicator': {
                      backgroundColor: cyberColors.neon.cyan,
                    },
                  }}
                >
                  <Tab
                    icon={<EmailIcon />}
                    label="Email"
                    id="credential-tab-0"
                    aria-controls="credential-tabpanel-0"
                    sx={{
                      color: cyberColors.text.secondary,
                      '&.Mui-selected': {
                        color: cyberColors.neon.cyan,
                      },
                    }}
                  />
                  <Tab
                    icon={<DomainIcon />}
                    label="Domain"
                    id="credential-tab-1"
                    aria-controls="credential-tabpanel-1"
                    sx={{
                      color: cyberColors.text.secondary,
                      '&.Mui-selected': {
                        color: cyberColors.neon.cyan,
                      },
                    }}
                  />
                  <Tab
                    icon={<LockIcon />}
                    label="Password"
                    id="credential-tab-2"
                    aria-controls="credential-tabpanel-2"
                    sx={{
                      color: cyberColors.text.secondary,
                      '&.Mui-selected': {
                        color: cyberColors.neon.cyan,
                      },
                    }}
                  />
                </Tabs>
              </Paper>

              {/* Email Tab */}
              <TabPanel value={tabValue} index={0}>
                <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
                  <TextField
                    fullWidth
                    placeholder="Enter email address"
                    value={emailInput}
                    onChange={(e) => setEmailInput(e.target.value)}
                    onKeyPress={(e) => {
                      if (e.key === 'Enter') handleCheckEmail();
                    }}
                    disabled={loading.email}
                    sx={{
                      '& .MuiOutlinedInput-root': {
                        color: cyberColors.text.primary,
                        '& fieldset': {
                          borderColor: designTokens.colors.border.main,
                        },
                        '&:hover fieldset': {
                          borderColor: designTokens.colors.border.light,
                        },
                      },
                      '& .MuiOutlinedInput-input::placeholder': {
                        color: cyberColors.text.muted,
                        opacity: 1,
                      },
                    }}
                  />
                  <Button
                    variant="contained"
                    onClick={handleCheckEmail}
                    disabled={loading.email}
                    startIcon={loading.email ? <CircularProgress size={20} /> : <SearchIcon />}
                    sx={{
                      backgroundColor: cyberColors.neon.cyan,
                      color: '#000',
                      fontWeight: 'bold',
                      '&:hover': {
                        backgroundColor: cyberColors.neon.electricBlue,
                      },
                    }}
                  >
                    Search
                  </Button>
                </Box>

                {emailResult && (
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                      <RiskBadge level={emailResult.risk_level} />
                      <Typography variant="body2" sx={{ color: cyberColors.text.secondary }}>
                        Risk Score: {emailResult.risk_score}%
                      </Typography>
                    </Box>
                    <LinearProgress
                      variant="determinate"
                      value={emailResult.risk_score}
                      sx={{
                        backgroundColor: `${cyberColors.neon.cyan}20`,
                        '& .MuiLinearProgress-bar': {
                          backgroundColor:
                            emailResult.risk_score > 70
                              ? cyberColors.neon.red
                              : emailResult.risk_score > 40
                                ? cyberColors.neon.orange
                                : cyberColors.neon.green,
                        },
                      }}
                    />
                    <Divider sx={{ borderColor: designTokens.colors.border.main }} />
                    <Grid container spacing={2}>
                      <Grid item xs={6} sm={3}>
                        <Box
                          sx={{
                            p: 2,
                            background: `${cyberColors.neon.cyan}10`,
                            borderRadius: 1,
                            border: `1px solid ${designTokens.colors.border.light}`,
                          }}
                        >
                          <Typography
                            variant="body2"
                            sx={{ color: cyberColors.text.muted, mb: 1 }}
                          >
                            HIBP Breaches
                          </Typography>
                          <Typography
                            variant="h6"
                            sx={{ color: cyberColors.neon.cyan, fontWeight: 'bold' }}
                          >
                            {emailResult.hibp_breaches}
                          </Typography>
                        </Box>
                      </Grid>
                      <Grid item xs={6} sm={3}>
                        <Box
                          sx={{
                            p: 2,
                            background: `${cyberColors.neon.magenta}10`,
                            borderRadius: 1,
                            border: `1px solid ${designTokens.colors.border.light}`,
                          }}
                        >
                          <Typography
                            variant="body2"
                            sx={{ color: cyberColors.text.muted, mb: 1 }}
                          >
                            Pastes
                          </Typography>
                          <Typography
                            variant="h6"
                            sx={{ color: cyberColors.neon.magenta, fontWeight: 'bold' }}
                          >
                            {emailResult.hibp_pastes}
                          </Typography>
                        </Box>
                      </Grid>
                      <Grid item xs={6} sm={3}>
                        <Box
                          sx={{
                            p: 2,
                            background: `${cyberColors.neon.orange}10`,
                            borderRadius: 1,
                            border: `1px solid ${designTokens.colors.border.light}`,
                          }}
                        >
                          <Typography
                            variant="body2"
                            sx={{ color: cyberColors.text.muted, mb: 1 }}
                          >
                            Hudson Rock
                          </Typography>
                          <Typography
                            variant="h6"
                            sx={{ color: cyberColors.neon.orange, fontWeight: 'bold' }}
                          >
                            {emailResult.hudson_rock}
                          </Typography>
                        </Box>
                      </Grid>
                      <Grid item xs={6} sm={3}>
                        <Box
                          sx={{
                            p: 2,
                            background: `${cyberColors.neon.red}10`,
                            borderRadius: 1,
                            border: `1px solid ${designTokens.colors.border.light}`,
                          }}
                        >
                          <Typography
                            variant="body2"
                            sx={{ color: cyberColors.text.muted, mb: 1 }}
                          >
                            Dehashed
                          </Typography>
                          <Typography
                            variant="h6"
                            sx={{ color: cyberColors.neon.red, fontWeight: 'bold' }}
                          >
                            {emailResult.dehashed}
                          </Typography>
                        </Box>
                      </Grid>
                    </Grid>
                    <Box
                      sx={{
                        p: 2,
                        background: `${cyberColors.neon.green}10`,
                        borderRadius: 1,
                        border: `1px solid ${designTokens.colors.border.light}`,
                      }}
                    >
                      <Typography variant="body2" sx={{ color: cyberColors.text.secondary }}>
                        {emailResult.summary}
                      </Typography>
                    </Box>
                  </Box>
                )}
              </TabPanel>

              {/* Domain Tab */}
              <TabPanel value={tabValue} index={1}>
                <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
                  <TextField
                    fullWidth
                    placeholder="Enter domain (e.g., example.com)"
                    value={domainInput}
                    onChange={(e) => setDomainInput(e.target.value)}
                    onKeyPress={(e) => {
                      if (e.key === 'Enter') handleCheckDomain();
                    }}
                    disabled={loading.domain}
                    sx={{
                      '& .MuiOutlinedInput-root': {
                        color: cyberColors.text.primary,
                        '& fieldset': {
                          borderColor: designTokens.colors.border.main,
                        },
                        '&:hover fieldset': {
                          borderColor: designTokens.colors.border.light,
                        },
                      },
                      '& .MuiOutlinedInput-input::placeholder': {
                        color: cyberColors.text.muted,
                        opacity: 1,
                      },
                    }}
                  />
                  <Button
                    variant="contained"
                    onClick={handleCheckDomain}
                    disabled={loading.domain}
                    startIcon={loading.domain ? <CircularProgress size={20} /> : <SearchIcon />}
                    sx={{
                      backgroundColor: cyberColors.neon.cyan,
                      color: '#000',
                      fontWeight: 'bold',
                      '&:hover': {
                        backgroundColor: cyberColors.neon.electricBlue,
                      },
                    }}
                  >
                    Search
                  </Button>
                </Box>

                {domainResult && (
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                      <RiskBadge level={domainResult.risk_level} />
                      <Typography variant="body2" sx={{ color: cyberColors.text.secondary }}>
                        Risk Score: {domainResult.risk_score}%
                      </Typography>
                    </Box>
                    <LinearProgress
                      variant="determinate"
                      value={domainResult.risk_score}
                      sx={{
                        backgroundColor: `${cyberColors.neon.cyan}20`,
                        '& .MuiLinearProgress-bar': {
                          backgroundColor:
                            domainResult.risk_score > 70
                              ? cyberColors.neon.red
                              : domainResult.risk_score > 40
                                ? cyberColors.neon.orange
                                : cyberColors.neon.green,
                        },
                      }}
                    />
                    <Divider sx={{ borderColor: designTokens.colors.border.main }} />
                    <Grid container spacing={2}>
                      <Grid item xs={6} sm={3}>
                        <Box
                          sx={{
                            p: 2,
                            background: `${cyberColors.neon.cyan}10`,
                            borderRadius: 1,
                            border: `1px solid ${designTokens.colors.border.light}`,
                          }}
                        >
                          <Typography
                            variant="body2"
                            sx={{ color: cyberColors.text.muted, mb: 1 }}
                          >
                            HIBP
                          </Typography>
                          <Typography
                            variant="h6"
                            sx={{ color: cyberColors.neon.cyan, fontWeight: 'bold' }}
                          >
                            {domainResult.hibp_domain}
                          </Typography>
                        </Box>
                      </Grid>
                      <Grid item xs={6} sm={3}>
                        <Box
                          sx={{
                            p: 2,
                            background: `${cyberColors.neon.orange}10`,
                            borderRadius: 1,
                            border: `1px solid ${designTokens.colors.border.light}`,
                          }}
                        >
                          <Typography
                            variant="body2"
                            sx={{ color: cyberColors.text.muted, mb: 1 }}
                          >
                            Hudson Rock
                          </Typography>
                          <Typography
                            variant="h6"
                            sx={{ color: cyberColors.neon.orange, fontWeight: 'bold' }}
                          >
                            {domainResult.hudson_rock_domain}
                          </Typography>
                        </Box>
                      </Grid>
                      <Grid item xs={6} sm={3}>
                        <Box
                          sx={{
                            p: 2,
                            background: `${cyberColors.neon.red}10`,
                            borderRadius: 1,
                            border: `1px solid ${designTokens.colors.border.light}`,
                          }}
                        >
                          <Typography
                            variant="body2"
                            sx={{ color: cyberColors.text.muted, mb: 1 }}
                          >
                            Dehashed
                          </Typography>
                          <Typography
                            variant="h6"
                            sx={{ color: cyberColors.neon.red, fontWeight: 'bold' }}
                          >
                            {domainResult.dehashed_domain}
                          </Typography>
                        </Box>
                      </Grid>
                      <Grid item xs={6} sm={3}>
                        <Box
                          sx={{
                            p: 2,
                            background: `${cyberColors.neon.magenta}10`,
                            borderRadius: 1,
                            border: `1px solid ${designTokens.colors.border.light}`,
                          }}
                        >
                          <Typography
                            variant="body2"
                            sx={{ color: cyberColors.text.muted, mb: 1 }}
                          >
                            Paste Sites
                          </Typography>
                          <Typography
                            variant="h6"
                            sx={{ color: cyberColors.neon.magenta, fontWeight: 'bold' }}
                          >
                            {domainResult.paste_domain}
                          </Typography>
                        </Box>
                      </Grid>
                    </Grid>
                    <Box
                      sx={{
                        p: 2,
                        background: `${cyberColors.neon.green}10`,
                        borderRadius: 1,
                        border: `1px solid ${designTokens.colors.border.light}`,
                      }}
                    >
                      <Typography variant="body2" sx={{ color: cyberColors.text.secondary }}>
                        {domainResult.summary}
                      </Typography>
                    </Box>
                  </Box>
                )}
              </TabPanel>

              {/* Password Tab */}
              <TabPanel value={tabValue} index={2}>
                <Alert
                  severity="info"
                  icon={<ShieldIcon />}
                  sx={{
                    mb: 3,
                    backgroundColor: `${cyberColors.neon.electricBlue}20`,
                    borderColor: cyberColors.neon.electricBlue,
                    color: cyberColors.neon.electricBlue,
                  }}
                >
                  <Typography variant="body2">
                    <strong>Privacy Protected:</strong> This check uses k-anonymity. Only the
                    first 5 characters of your password's SHA-1 hash are sent to the server. Your
                    full password never leaves your device.
                  </Typography>
                </Alert>

                <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
                  <TextField
                    fullWidth
                    type={showPassword ? 'text' : 'password'}
                    placeholder="Enter password"
                    value={passwordInput}
                    onChange={(e) => setPasswordInput(e.target.value)}
                    onKeyPress={(e) => {
                      if (e.key === 'Enter') handleCheckPassword();
                    }}
                    disabled={loading.password}
                    InputProps={{
                      endAdornment: (
                        <IconButton
                          onClick={() => setShowPassword(!showPassword)}
                          edge="end"
                          disabled={loading.password}
                          sx={{ color: cyberColors.text.secondary }}
                        >
                          {showPassword ? <VisibilityOffIcon /> : <VisibilityIcon />}
                        </IconButton>
                      ),
                    }}
                    sx={{
                      '& .MuiOutlinedInput-root': {
                        color: cyberColors.text.primary,
                        '& fieldset': {
                          borderColor: designTokens.colors.border.main,
                        },
                        '&:hover fieldset': {
                          borderColor: designTokens.colors.border.light,
                        },
                      },
                      '& .MuiOutlinedInput-input::placeholder': {
                        color: cyberColors.text.muted,
                        opacity: 1,
                      },
                    }}
                  />
                  <Button
                    variant="contained"
                    onClick={handleCheckPassword}
                    disabled={loading.password}
                    startIcon={loading.password ? <CircularProgress size={20} /> : <LockIcon />}
                    sx={{
                      backgroundColor: cyberColors.neon.cyan,
                      color: '#000',
                      fontWeight: 'bold',
                      '&:hover': {
                        backgroundColor: cyberColors.neon.electricBlue,
                      },
                    }}
                  >
                    Check
                  </Button>
                </Box>

                {passwordResult && (
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    <Box
                      sx={{
                        p: 3,
                        background:
                          passwordResult.is_pwned
                            ? `${cyberColors.neon.red}10`
                            : `${cyberColors.neon.green}10`,
                        borderRadius: 1,
                        border: `1px solid ${passwordResult.is_pwned ? cyberColors.neon.red : cyberColors.neon.green}`,
                        display: 'flex',
                        alignItems: 'center',
                        gap: 2,
                      }}
                    >
                      {passwordResult.is_pwned ? (
                        <WarningIcon
                          sx={{
                            color: cyberColors.neon.red,
                            fontSize: '2rem',
                          }}
                        />
                      ) : (
                        <CheckCircleIcon
                          sx={{
                            color: cyberColors.neon.green,
                            fontSize: '2rem',
                          }}
                        />
                      )}
                      <Box>
                        <Typography
                          variant="h6"
                          sx={{
                            color: passwordResult.is_pwned
                              ? cyberColors.neon.red
                              : cyberColors.neon.green,
                            fontWeight: 'bold',
                          }}
                        >
                          {passwordResult.is_pwned ? 'Password Compromised' : 'Password Safe'}
                        </Typography>
                        <Typography variant="body2" sx={{ color: cyberColors.text.secondary }}>
                          {passwordResult.is_pwned
                            ? `Found in ${passwordResult.pwned_count} breach${passwordResult.pwned_count !== 1 ? 'es' : ''}`
                            : 'Not found in any known breaches'}
                        </Typography>
                      </Box>
                    </Box>
                  </Box>
                )}
              </TabPanel>
            </StyledCard>
          </Grid>

          {/* Source Status Panel */}
          <Grid item xs={12} lg={4}>
            <StyledCard
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.1 }}
              sx={{
                ...glassmorphism.card,
                p: 3,
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
                <SecurityIcon sx={{ color: cyberColors.neon.cyan }} />
                <Typography
                  variant="h6"
                  sx={{
                    color: cyberColors.text.primary,
                    fontWeight: 'bold',
                  }}
                >
                  Source Status
                </Typography>
              </Box>

              <Divider sx={{ borderColor: designTokens.colors.border.main, mb: 3 }} />

              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  <Box
                    sx={{
                      width: 12,
                      height: 12,
                      borderRadius: '50%',
                      backgroundColor: sourceStatus.hibp
                        ? cyberColors.neon.green
                        : cyberColors.text.muted,
                      boxShadow: sourceStatus.hibp
                        ? `0 0 10px ${cyberColors.neon.green}`
                        : 'none',
                    }}
                  />
                  <Box>
                    <Typography
                      variant="body2"
                      sx={{
                        color: cyberColors.text.primary,
                        fontWeight: 'bold',
                      }}
                    >
                      HIBP (Have I Been Pwned)
                    </Typography>
                    <Typography
                      variant="caption"
                      sx={{ color: cyberColors.text.muted }}
                    >
                      Breach & paste monitoring
                    </Typography>
                  </Box>
                </Box>

                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  <Box
                    sx={{
                      width: 12,
                      height: 12,
                      borderRadius: '50%',
                      backgroundColor: sourceStatus.dehashed
                        ? cyberColors.neon.orange
                        : cyberColors.text.muted,
                      boxShadow: sourceStatus.dehashed
                        ? `0 0 10px ${cyberColors.neon.orange}`
                        : 'none',
                    }}
                  />
                  <Box>
                    <Typography
                      variant="body2"
                      sx={{
                        color: cyberColors.text.primary,
                        fontWeight: 'bold',
                      }}
                    >
                      Dehashed
                    </Typography>
                    <Typography
                      variant="caption"
                      sx={{ color: cyberColors.text.muted }}
                    >
                      Hashed credential database
                    </Typography>
                  </Box>
                </Box>

                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  <Box
                    sx={{
                      width: 12,
                      height: 12,
                      borderRadius: '50%',
                      backgroundColor: sourceStatus.hudson_rock
                        ? cyberColors.neon.cyan
                        : cyberColors.text.muted,
                      boxShadow: sourceStatus.hudson_rock
                        ? `0 0 10px ${cyberColors.neon.cyan}`
                        : 'none',
                    }}
                  />
                  <Box>
                    <Typography
                      variant="body2"
                      sx={{
                        color: cyberColors.text.primary,
                        fontWeight: 'bold',
                      }}
                    >
                      Hudson Rock
                    </Typography>
                    <Typography
                      variant="caption"
                      sx={{ color: cyberColors.text.muted }}
                    >
                      Infostealer monitoring
                    </Typography>
                  </Box>
                </Box>

                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  <Box
                    sx={{
                      width: 12,
                      height: 12,
                      borderRadius: '50%',
                      backgroundColor: sourceStatus.paste
                        ? cyberColors.neon.magenta
                        : cyberColors.text.muted,
                      boxShadow: sourceStatus.paste
                        ? `0 0 10px ${cyberColors.neon.magenta}`
                        : 'none',
                    }}
                  />
                  <Box>
                    <Typography
                      variant="body2"
                      sx={{
                        color: cyberColors.text.primary,
                        fontWeight: 'bold',
                      }}
                    >
                      Paste Sites
                    </Typography>
                    <Typography
                      variant="caption"
                      sx={{ color: cyberColors.text.muted }}
                    >
                      Public paste aggregation
                    </Typography>
                  </Box>
                </Box>
              </Box>
            </StyledCard>
          </Grid>
        </Grid>
      </Box>
    </motion.div>
  );
};

export default CredentialIntelligencePage;
