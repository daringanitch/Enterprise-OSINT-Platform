/**
 * Username Search Page
 *
 * Searches 400+ social-media sites for a username via the Sherlock tool
 * (social-media-enhanced MCP) and lists the claimed accounts.
 */

import React, { useState, useCallback } from 'react';
import {
  Box,
  Card,
  Typography,
  Chip,
  TextField,
  Button,
  Alert,
  LinearProgress,
  Grid,
  Link,
  Tooltip,
  IconButton,
} from '@mui/material';
import {
  Search as SearchIcon,
  Person as PersonIcon,
  OpenInNew as OpenInNewIcon,
  CheckCircle as CheckCircleIcon,
  PublicOff as PublicOffIcon,
} from '@mui/icons-material';
import { motion } from 'framer-motion';
import { cyberColors, designTokens, glassmorphism } from '../utils/theme';
import { pageVariants } from '../utils/animations';
import api from '../utils/api';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Account {
  site: string;
  url: string;
}

interface UsernameSearchResult {
  username: string;
  count: number;
  accounts: Account[];
  scan_duration_seconds: number | null;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

const UsernameSearchPage: React.FC = () => {
  const [username, setUsername] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<UsernameSearchResult | null>(null);

  const handleSearch = useCallback(async () => {
    const trimmed = username.trim();
    if (!trimmed) {
      setError("Enter a username to search.");
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await api.post<UsernameSearchResult>(
        '/social/username-search',
        { username: trimmed }
      );
      setResult(response.data);
    } catch (err: any) {
      setError(
        err?.response?.data?.error ||
          'Search failed. The scan can take up to two minutes — please try again.'
      );
    } finally {
      setLoading(false);
    }
  }, [username]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !loading) {
      handleSearch();
    }
  };

  return (
    <motion.div
      variants={pageVariants}
      initial="initial"
      animate="animate"
      exit="exit"
    >
      <Box sx={{ p: { xs: 2, md: 3 } }}>
        {/* Header */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
          <PersonIcon sx={{ fontSize: 32, color: cyberColors.neon.cyan }} />
          <Typography variant="h4" fontWeight={700}>
            Username Search
          </Typography>
        </Box>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Search 400+ social-media sites for a username and surface the claimed
          accounts. Powered by Sherlock.
        </Typography>

        {/* Search input */}
        <Card sx={{ ...glassmorphism.card, p: 3, mb: 3 }}>
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'flex-start', flexWrap: 'wrap' }}>
            <TextField
              fullWidth
              label="Username"
              placeholder="e.g. john_doe"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              onKeyDown={handleKeyDown}
              disabled={loading}
              autoFocus
              sx={{ flex: 1, minWidth: 240 }}
              inputProps={{ 'aria-label': 'Username to search' }}
            />
            <Button
              variant="contained"
              size="large"
              startIcon={<SearchIcon />}
              onClick={handleSearch}
              disabled={loading || !username.trim()}
              sx={{ height: 56, px: 4 }}
            >
              {loading ? 'Searching…' : 'Search'}
            </Button>
          </Box>
          {loading && (
            <Box sx={{ mt: 2 }}>
              <LinearProgress />
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                Scanning up to 400 sites — this can take up to two minutes.
              </Typography>
            </Box>
          )}
        </Card>

        {/* Error */}
        {error && (
          <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError('')}>
            {error}
          </Alert>
        )}

        {/* Results */}
        {result && (
          <Card sx={{ ...glassmorphism.card, p: 3 }}>
            <Box
              sx={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                mb: 2,
                flexWrap: 'wrap',
                gap: 1,
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <CheckCircleIcon sx={{ color: cyberColors.neon.green }} />
                <Typography variant="h6" fontWeight={600}>
                  {result.count} account{result.count === 1 ? '' : 's'} found for{' '}
                  <Box component="span" sx={{ color: cyberColors.neon.cyan }}>
                    {result.username}
                  </Box>
                </Typography>
              </Box>
              {result.scan_duration_seconds != null && (
                <Chip
                  size="small"
                  label={`${result.scan_duration_seconds}s`}
                  sx={{ fontFamily: designTokens.typography.fontFamily.mono }}
                />
              )}
            </Box>

            {result.count === 0 ? (
              <Box sx={{ textAlign: 'center', py: 4, color: 'text.secondary' }}>
                <PublicOffIcon sx={{ fontSize: 40, mb: 1, opacity: 0.6 }} />
                <Typography>No claimed accounts found for this username.</Typography>
              </Box>
            ) : (
              <Grid container spacing={1.5}>
                {result.accounts.map((account) => (
                  <Grid item xs={12} sm={6} md={4} key={`${account.site}-${account.url}`}>
                    <Box
                      sx={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        p: 1.5,
                        borderRadius: 1,
                        border: `1px solid ${cyberColors.border.default}`,
                        transition: 'border-color 0.2s',
                        '&:hover': { borderColor: cyberColors.neon.cyan },
                      }}
                    >
                      <Typography variant="body2" fontWeight={500} noWrap sx={{ mr: 1 }}>
                        {account.site}
                      </Typography>
                      <Tooltip title={account.url}>
                        <IconButton
                          component={Link}
                          href={account.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          size="small"
                          aria-label={`Open ${account.site} profile in a new tab`}
                        >
                          <OpenInNewIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            )}
          </Card>
        )}
      </Box>
    </motion.div>
  );
};

export default UsernameSearchPage;
