import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Container,
  Paper,
  Tabs,
  Tab,
  Button,
  Card,
  CardContent,
  CardActions,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  FormGroup,
  FormControlLabel,
  Checkbox,
  Chip,
  Badge,
  IconButton,
  Grid,
  Typography,
  Divider,
  CircularProgress,
  Alert,
  Tooltip,
  Stack,
  Switch,
} from '@mui/material';
import { alpha } from '@mui/material/styles';
import {
  MonitorHeart,
  Notifications,
  Public,
  Storage,
  Email,
  Search,
  Shield,
  Language,
  Router,
  Warning,
  CheckCircle,
  Cancel,
  Delete as DeleteIcon,
  Refresh,
  Close,
  ExpandMore,
  ExpandLess,
  Add,
  AccessTime as Clock,
  TrendingUp,
} from '@mui/icons-material';
import { motion } from 'framer-motion';
import { cyberColors, designTokens, glassmorphism } from '../utils/theme';
import { pageVariants } from '../utils/animations';

interface WatchlistEntry {
  id: string;
  name: string;
  entry_type:
    | 'domain'
    | 'ip'
    | 'email'
    | 'keyword'
    | 'registrant'
    | 'certificate_subject'
    | 'threat_actor'
    | 'cidr'
    | 'asn';
  value: string;
  enabled: boolean;
  check_interval_hours: number;
  last_checked_at?: string;
  next_check_at?: string;
  alert_on: string[];
  tags: string[];
  notes?: string;
  total_checks: number;
  total_alerts: number;
  last_alert_at?: string;
  new_alert_count: number;
}

interface MonitorAlert {
  id: string;
  watchlist_id: string;
  watchlist_name: string;
  alert_type: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  details?: Record<string, unknown>;
  old_value?: string;
  new_value?: string;
  diff_summary?: string;
  status: 'new' | 'acknowledged' | 'in_progress' | 'resolved' | 'dismissed';
  triggered_at: string;
  false_positive?: boolean;
}

interface MonitorSummary {
  store: {
    watchlist_entries: number;
    new_alerts: number;
    by_severity: Record<string, number>;
  };
  scheduler: {
    running: boolean;
  };
}

type TabValue = 0 | 1;
type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low' | 'info';
type StatusFilter = 'all' | 'new';

const getSeverityColor = (severity: string): string => {
  switch (severity) {
    case 'critical':
      return cyberColors.neon.magenta;
    case 'high':
      return cyberColors.neon.red;
    case 'medium':
      return cyberColors.neon.orange;
    case 'low':
      return cyberColors.neon.cyan;
    case 'info':
      return cyberColors.neon.green;
    default:
      return cyberColors.neon.cyan;
  }
};

const getEntryTypeIcon = (entryType: string): React.ReactNode => {
  const iconProps = { fontSize: 'small' as const };
  switch (entryType) {
    case 'domain':
      return <Language {...iconProps} />;
    case 'ip':
      return <Storage {...iconProps} />;
    case 'cidr':
    case 'asn':
      return <Router {...iconProps} />;
    case 'email':
      return <Email {...iconProps} />;
    case 'keyword':
      return <Search {...iconProps} />;
    case 'certificate_subject':
      return <Shield {...iconProps} />;
    case 'registrant':
    case 'threat_actor':
      return <Public {...iconProps} />;
    default:
      return <MonitorHeart {...iconProps} />;
  }
};

const getAlertTypeIcon = (alertType: string): React.ReactNode => {
  const iconProps = { fontSize: 'small' as const };
  if (alertType.includes('dns')) return <Language {...iconProps} />;
  if (alertType.includes('cert')) return <Shield {...iconProps} />;
  if (alertType.includes('port')) return <Router {...iconProps} />;
  if (alertType.includes('keyword')) return <Search {...iconProps} />;
  return <TrendingUp {...iconProps} />;
};

const formatRelativeTime = (dateString: string): string => {
  const now = new Date();
  const then = new Date(dateString);
  const diffMs = now.getTime() - then.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffMins < 1) return 'just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return then.toLocaleDateString();
};

const Monitoring: React.FC = () => {
  const [tabValue, setTabValue] = useState<TabValue>(0);
  const [watchlistEntries, setWatchlistEntries] = useState<WatchlistEntry[]>([]);
  const [alerts, setAlerts] = useState<MonitorAlert[]>([]);
  const [summary, setSummary] = useState<MonitorSummary | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [expandedEntryId, setExpandedEntryId] = useState<string | null>(null);
  const [checkingId, setCheckingId] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');

  const [formData, setFormData] = useState({
    name: '',
    entry_type: 'domain',
    value: '',
    check_interval_hours: '24',
    notes: '',
    alert_on: [] as string[],
  });

  const token = localStorage.getItem('token');

  const apiCall = useCallback(
    async (
      method: string,
      endpoint: string,
      body?: Record<string, unknown>
    ) => {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };
      if (token) {
        headers.Authorization = `Bearer ${token}`;
      }

      const response = await fetch(`/api/monitoring${endpoint}`, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
      });

      if (!response.ok) {
        if (response.status === 401) {
          localStorage.removeItem('token');
          window.location.href = '/login';
        }
        throw new Error(`HTTP ${response.status}`);
      }

      return response.json();
    },
    [token]
  );

  const fetchWatchlist = useCallback(async () => {
    try {
      const data = await apiCall('GET', '/watchlist');
      setWatchlistEntries(data.entries || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch watchlist');
    }
  }, [apiCall]);

  const fetchAlerts = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      if (statusFilter === 'new') params.append('status', 'new');
      params.append('limit', '100');
      const data = await apiCall('GET', `/alerts?${params.toString()}`);
      setAlerts(data.alerts || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch alerts');
    }
  }, [apiCall, statusFilter]);

  const fetchSummary = useCallback(async () => {
    try {
      const data = await apiCall('GET', '/summary');
      setSummary(data);
    } catch (err) {
      // Silent fail for summary
    }
  }, [apiCall]);

  useEffect(() => {
    const interval = setInterval(() => {
      if (tabValue === 0) {
        fetchWatchlist();
      } else {
        fetchAlerts();
      }
      fetchSummary();
    }, 30000);

    return () => clearInterval(interval);
  }, [tabValue, fetchWatchlist, fetchAlerts, fetchSummary]);

  useEffect(() => {
    setLoading(true);
    Promise.all([fetchWatchlist(), fetchAlerts(), fetchSummary()]).finally(
      () => setLoading(false)
    );
  }, [fetchWatchlist, fetchAlerts, fetchSummary]);

  const handleAddWatchlistEntry = async () => {
    try {
      await apiCall('POST', '/watchlist', {
        name: formData.name || formData.value,
        entry_type: formData.entry_type,
        value: formData.value,
        check_interval_hours: parseInt(formData.check_interval_hours),
        notes: formData.notes,
        alert_on: formData.alert_on,
      });
      setDialogOpen(false);
      setFormData({
        name: '',
        entry_type: 'domain',
        value: '',
        check_interval_hours: '24',
        notes: '',
        alert_on: [],
      });
      await fetchWatchlist();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add entry');
    }
  };

  const handleDeleteWatchlistEntry = async (id: string) => {
    try {
      await apiCall('DELETE', `/watchlist/${id}`);
      await fetchWatchlist();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete entry');
    }
  };

  const handleCheckNow = async (id: string) => {
    setCheckingId(id);
    try {
      await apiCall('POST', `/watchlist/${id}/check`);
      await fetchWatchlist();
      await fetchAlerts();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Check failed');
    } finally {
      setCheckingId(null);
    }
  };

  const handleToggleEntry = async (id: string, enabled: boolean) => {
    try {
      await apiCall('POST', `/watchlist/${id}/enable`, { enabled });
      await fetchWatchlist();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to toggle entry');
    }
  };

  const handleAlertAction = async (
    alertId: string,
    action: 'acknowledge' | 'resolve' | 'dismiss'
  ) => {
    try {
      await apiCall('POST', `/alerts/${alertId}/${action}`);
      await fetchAlerts();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update alert');
    }
  };

  const getFilteredAlerts = (): MonitorAlert[] => {
    return alerts.filter((alert) => {
      if (
        severityFilter !== 'all' &&
        alert.severity !== severityFilter
      ) {
        return false;
      }
      if (statusFilter === 'new' && alert.status !== 'new') {
        return false;
      }
      return true;
    });
  };

  const filteredAlerts = getFilteredAlerts();
  const entryAlerts = (entryId: string): MonitorAlert[] =>
    alerts.filter((a) => a.watchlist_id === entryId);

  return (
    <motion.div initial="initial" animate="animate" variants={pageVariants}>
      <Container maxWidth="xl" sx={{ py: 4 }}>
        <Box sx={{ mb: 4 }}>
          <Typography
            variant="h3"
            sx={{
              fontFamily: designTokens.typography.fontFamily.display,
              color: cyberColors.neon.cyan,
              mb: 1,
              fontWeight: 600,
            }}
          >
            Monitoring & Alerts
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Real-time threat monitoring and alert management
          </Typography>
        </Box>

        {error && (
          <Alert
            severity="error"
            onClose={() => setError(null)}
            sx={{ mb: 3 }}
          >
            {error}
          </Alert>
        )}

        <Paper
          sx={{
            ...glassmorphism.card,
            mb: 3,
          }}
        >
          <Tabs
            value={tabValue}
            onChange={(_, newValue) => setTabValue(newValue as TabValue)}
            sx={{
              borderBottom: `1px solid ${alpha(cyberColors.neon.cyan, 0.2)}`,
            }}
          >
            <Tab
              label="Watchlist"
              icon={<MonitorHeart />}
              iconPosition="start"
            />
            <Tab
              label="Alerts"
              icon={
                <Badge
                  badgeContent={summary?.store.new_alerts || 0}
                  color="error"
                >
                  <Notifications />
                </Badge>
              }
              iconPosition="start"
            />
          </Tabs>
        </Paper>

        {tabValue === 0 && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3 }}
          >
            <Paper
              sx={{
                ...glassmorphism.card,
                mb: 3,
                p: 2,
              }}
            >
              <Box
                sx={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  mb: 2,
                }}
              >
                <Stack direction="row" spacing={3}>
                  <Box>
                    <Typography
                      variant="caption"
                      color="text.secondary"
                      sx={{ display: 'block', mb: 0.5 }}
                    >
                      MONITORED ASSETS
                    </Typography>
                    <Typography
                      variant="h5"
                      sx={{ color: cyberColors.neon.cyan, fontWeight: 600 }}
                    >
                      {summary?.store.watchlist_entries || 0}
                    </Typography>
                  </Box>
                  <Box>
                    <Typography
                      variant="caption"
                      color="text.secondary"
                      sx={{ display: 'block', mb: 0.5 }}
                    >
                      NEW ALERTS
                    </Typography>
                    <Typography
                      variant="h5"
                      sx={{
                        color:
                          (summary?.store.new_alerts || 0) > 0
                            ? cyberColors.neon.red
                            : cyberColors.neon.green,
                        fontWeight: 600,
                      }}
                    >
                      {summary?.store.new_alerts || 0}
                    </Typography>
                  </Box>
                  <Box>
                    <Typography
                      variant="caption"
                      color="text.secondary"
                      sx={{ display: 'block', mb: 0.5 }}
                    >
                      SCHEDULER
                    </Typography>
                    <Chip
                      label={
                        summary?.scheduler.running ? 'Running' : 'Stopped'
                      }
                      size="small"
                      color={
                        summary?.scheduler.running ? 'success' : 'error'
                      }
                      variant="outlined"
                    />
                  </Box>
                </Stack>
                <Button
                  variant="contained"
                  startIcon={<Add />}
                  onClick={() => setDialogOpen(true)}
                  sx={{
                    background: `linear-gradient(135deg, ${cyberColors.neon.cyan}, ${cyberColors.neon.green})`,
                    color: '#000',
                    fontWeight: 600,
                    '&:hover': {
                      background: `linear-gradient(135deg, ${alpha(
                        cyberColors.neon.cyan,
                        0.9
                      )}, ${alpha(cyberColors.neon.green, 0.9)})`,
                    },
                  }}
                >
                  Add to Watchlist
                </Button>
              </Box>
            </Paper>

            {loading ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', py: 6 }}>
                <CircularProgress sx={{ color: cyberColors.neon.cyan }} />
              </Box>
            ) : (
              <Grid container spacing={2}>
                {watchlistEntries.map((entry) => (
                  <Grid item xs={12} md={6} key={entry.id}>
                    <motion.div
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.3 }}
                    >
                      <Card
                        sx={{
                          ...glassmorphism.card,
                          height: '100%',
                          display: 'flex',
                          flexDirection: 'column',
                        }}
                      >
                        <CardContent sx={{ flex: 1 }}>
                          <Box
                            sx={{
                              display: 'flex',
                              justifyContent: 'space-between',
                              alignItems: 'flex-start',
                              mb: 2,
                            }}
                          >
                            <Box sx={{ display: 'flex', gap: 1, flex: 1 }}>
                              <Box
                                sx={{
                                  color: cyberColors.neon.cyan,
                                  display: 'flex',
                                  alignItems: 'center',
                                }}
                              >
                                {getEntryTypeIcon(entry.entry_type)}
                              </Box>
                              <Box>
                                <Typography
                                  variant="h6"
                                  sx={{
                                    fontFamily:
                                      designTokens.typography.fontFamily
                                        .display,
                                    color: cyberColors.neon.cyan,
                                  }}
                                >
                                  {entry.name}
                                </Typography>
                                <Typography
                                  variant="caption"
                                  color="text.secondary"
                                  sx={{
                                    fontFamily: 'monospace',
                                    display: 'block',
                                    mb: 1,
                                  }}
                                >
                                  {entry.value}
                                </Typography>
                                <Box
                                  sx={{
                                    display: 'flex',
                                    gap: 1,
                                    flexWrap: 'wrap',
                                  }}
                                >
                                  <Chip
                                    label={entry.entry_type}
                                    size="small"
                                    variant="outlined"
                                    sx={{
                                      borderColor: cyberColors.neon.cyan,
                                      color: cyberColors.neon.cyan,
                                    }}
                                  />
                                </Box>
                              </Box>
                            </Box>
                            <Badge
                              badgeContent={entry.new_alert_count}
                              color="error"
                            >
                              <Box
                                sx={{
                                  width: 24,
                                  height: 24,
                                }}
                              />
                            </Badge>
                          </Box>

                          <Divider
                            sx={{
                              my: 1.5,
                              borderColor: alpha(cyberColors.neon.cyan, 0.1),
                            }}
                          />

                          <Stack spacing={1} sx={{ mb: 2 }}>
                            <Box
                              sx={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                alignItems: 'center',
                              }}
                            >
                              <Typography variant="caption" color="text.secondary">
                                Status
                              </Typography>
                              <Switch
                                size="small"
                                checked={entry.enabled}
                                onChange={(e) =>
                                  handleToggleEntry(entry.id, e.target.checked)
                                }
                                sx={{
                                  '& .MuiSwitch-switchBase.Mui-checked': {
                                    color: cyberColors.neon.green,
                                  },
                                }}
                              />
                            </Box>
                            <Typography
                              variant="caption"
                              color="text.secondary"
                            >
                              {entry.total_checks} checks • {entry.total_alerts}{' '}
                              alerts
                              {entry.last_checked_at &&
                                ` • Last: ${formatRelativeTime(
                                  entry.last_checked_at
                                )}`}
                            </Typography>
                            {entry.notes && (
                              <Typography
                                variant="caption"
                                sx={{
                                  color: alpha(cyberColors.neon.cyan, 0.7),
                                  fontStyle: 'italic',
                                }}
                              >
                                {entry.notes}
                              </Typography>
                            )}
                          </Stack>

                          {expandedEntryId === entry.id &&
                            entryAlerts(entry.id).length > 0 && (
                              <Box
                                sx={{
                                  mt: 2,
                                  pt: 2,
                                  borderTop: `1px solid ${alpha(
                                    cyberColors.neon.cyan,
                                    0.1
                                  )}`,
                                }}
                              >
                                <Typography
                                  variant="caption"
                                  color="text.secondary"
                                  sx={{ display: 'block', mb: 1 }}
                                >
                                  RECENT ALERTS
                                </Typography>
                                <Stack spacing={1}>
                                  {entryAlerts(entry.id)
                                    .slice(0, 3)
                                    .map((alert) => (
                                      <Box
                                        key={alert.id}
                                        sx={{
                                          p: 1,
                                          bgcolor: alpha(
                                            getSeverityColor(alert.severity),
                                            0.1
                                          ),
                                          borderLeft: `3px solid ${getSeverityColor(
                                            alert.severity
                                          )}`,
                                          borderRadius: 1,
                                        }}
                                      >
                                        <Typography
                                          variant="caption"
                                          sx={{
                                            color: getSeverityColor(
                                              alert.severity
                                            ),
                                            fontWeight: 600,
                                          }}
                                        >
                                          {alert.alert_type}
                                        </Typography>
                                        <Typography
                                          variant="caption"
                                          display="block"
                                          color="text.secondary"
                                        >
                                          {alert.title}
                                        </Typography>
                                      </Box>
                                    ))}
                                </Stack>
                              </Box>
                            )}
                        </CardContent>
                        <CardActions
                          sx={{
                            display: 'flex',
                            gap: 1,
                            pt: 1,
                            borderTop: `1px solid ${alpha(cyberColors.neon.cyan, 0.1)}`,
                          }}
                        >
                          <Button
                            size="small"
                            onClick={() =>
                              setExpandedEntryId(
                                expandedEntryId === entry.id ? null : entry.id
                              )
                            }
                            startIcon={
                              expandedEntryId === entry.id ? (
                                <ExpandLess />
                              ) : (
                                <ExpandMore />
                              )
                            }
                          >
                            {expandedEntryId === entry.id
                              ? 'Hide Alerts'
                              : 'Show Alerts'}
                          </Button>
                          <Button
                            size="small"
                            onClick={() => handleCheckNow(entry.id)}
                            disabled={checkingId === entry.id}
                            startIcon={
                              checkingId === entry.id ? (
                                <CircularProgress size={16} />
                              ) : (
                                <Refresh />
                              )
                            }
                          >
                            {checkingId === entry.id ? 'Checking...' : 'Check Now'}
                          </Button>
                          <Box sx={{ flex: 1 }} />
                          <Tooltip title="Delete">
                            <IconButton
                              size="small"
                              onClick={() =>
                                handleDeleteWatchlistEntry(entry.id)
                              }
                              sx={{
                                color: cyberColors.neon.red,
                                '&:hover': {
                                  bgcolor: alpha(cyberColors.neon.red, 0.1),
                                },
                              }}
                            >
                              <DeleteIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </CardActions>
                      </Card>
                    </motion.div>
                  </Grid>
                ))}
              </Grid>
            )}

            <Dialog
              open={dialogOpen}
              onClose={() => setDialogOpen(false)}
              maxWidth="sm"
              fullWidth
              PaperProps={{
                sx: {
                  ...glassmorphism.card,
                },
              }}
            >
              <DialogTitle
                sx={{
                  fontFamily: designTokens.typography.fontFamily.display,
                  color: cyberColors.neon.cyan,
                }}
              >
                Add to Watchlist
              </DialogTitle>
              <DialogContent sx={{ pt: 3 }}>
                <Stack spacing={3}>
                  <TextField
                    label="Name (optional)"
                    fullWidth
                    value={formData.name}
                    onChange={(e) =>
                      setFormData({ ...formData, name: e.target.value })
                    }
                    size="small"
                    placeholder="Leave empty to use value"
                  />
                  <FormControl fullWidth size="small">
                    <InputLabel>Entry Type</InputLabel>
                    <Select
                      value={formData.entry_type}
                      label="Entry Type"
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          entry_type: e.target.value,
                        })
                      }
                    >
                      <MenuItem value="domain">Domain</MenuItem>
                      <MenuItem value="ip">IP Address</MenuItem>
                      <MenuItem value="cidr">CIDR Block</MenuItem>
                      <MenuItem value="asn">ASN</MenuItem>
                      <MenuItem value="email">Email Address</MenuItem>
                      <MenuItem value="keyword">Keyword</MenuItem>
                      <MenuItem value="certificate_subject">
                        Certificate Subject
                      </MenuItem>
                      <MenuItem value="registrant">Registrant</MenuItem>
                      <MenuItem value="threat_actor">Threat Actor</MenuItem>
                    </Select>
                  </FormControl>
                  <TextField
                    label="Value"
                    fullWidth
                    value={formData.value}
                    onChange={(e) =>
                      setFormData({ ...formData, value: e.target.value })
                    }
                    size="small"
                    required
                  />
                  <FormControl fullWidth size="small">
                    <InputLabel>Check Interval (hours)</InputLabel>
                    <Select
                      value={formData.check_interval_hours}
                      label="Check Interval (hours)"
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          check_interval_hours: e.target.value,
                        })
                      }
                    >
                      <MenuItem value="1">1 hour</MenuItem>
                      <MenuItem value="6">6 hours</MenuItem>
                      <MenuItem value="12">12 hours</MenuItem>
                      <MenuItem value="24">24 hours</MenuItem>
                      <MenuItem value="72">3 days</MenuItem>
                      <MenuItem value="168">1 week</MenuItem>
                    </Select>
                  </FormControl>
                  <TextField
                    label="Notes"
                    fullWidth
                    value={formData.notes}
                    onChange={(e) =>
                      setFormData({ ...formData, notes: e.target.value })
                    }
                    multiline
                    rows={3}
                    size="small"
                  />
                  <FormControl component="fieldset">
                    <Typography variant="caption" color="text.secondary" sx={{ mb: 1 }}>
                      Alert On
                    </Typography>
                    <FormGroup>
                      {[
                        'dns_change',
                        'cert_change',
                        'port_change',
                        'keyword_match',
                        'threat_score_change',
                      ].map((alertType) => (
                        <FormControlLabel
                          key={alertType}
                          control={
                            <Checkbox
                              size="small"
                              checked={formData.alert_on.includes(
                                alertType
                              )}
                              onChange={(e) => {
                                const newAlertOn = e.target.checked
                                  ? [...formData.alert_on, alertType]
                                  : formData.alert_on.filter(
                                      (a) => a !== alertType
                                    );
                                setFormData({
                                  ...formData,
                                  alert_on: newAlertOn,
                                });
                              }}
                            />
                          }
                          label={alertType.replace(/_/g, ' ')}
                        />
                      ))}
                    </FormGroup>
                  </FormControl>
                </Stack>
              </DialogContent>
              <DialogActions>
                <Button
                  onClick={() => setDialogOpen(false)}
                  sx={{ color: cyberColors.neon.cyan }}
                >
                  Cancel
                </Button>
                <Button
                  onClick={handleAddWatchlistEntry}
                  variant="contained"
                  sx={{
                    background: `linear-gradient(135deg, ${cyberColors.neon.cyan}, ${cyberColors.neon.green})`,
                    color: '#000',
                    fontWeight: 600,
                  }}
                >
                  Add Entry
                </Button>
              </DialogActions>
            </Dialog>
          </motion.div>
        )}

        {tabValue === 1 && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3 }}
          >
            <Paper
              sx={{
                ...glassmorphism.card,
                mb: 3,
                p: 2,
              }}
            >
              <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap' }}>
                {(
                  ['all', 'critical', 'high', 'medium', 'low', 'info'] as const
                ).map((severity) => (
                  <Chip
                    key={severity}
                    label={
                      severity.charAt(0).toUpperCase() + severity.slice(1)
                    }
                    onClick={() => setSeverityFilter(severity)}
                    color={
                      severityFilter === severity ? 'primary' : 'default'
                    }
                    variant={
                      severityFilter === severity ? 'filled' : 'outlined'
                    }
                    sx={{
                      borderColor:
                        severity === 'all'
                          ? cyberColors.neon.cyan
                          : getSeverityColor(severity),
                      color:
                        severity === 'all'
                          ? cyberColors.neon.cyan
                          : getSeverityColor(severity),
                      ...(severityFilter === severity && {
                        bgcolor:
                          severity === 'all'
                            ? cyberColors.neon.cyan
                            : getSeverityColor(severity),
                        color: '#000',
                      }),
                    }}
                  />
                ))}
                <Divider orientation="vertical" flexItem sx={{ my: 1 }} />
                {(['all', 'new'] as const).map((status) => (
                  <Chip
                    key={status}
                    label={status.charAt(0).toUpperCase() + status.slice(1)}
                    onClick={() => setStatusFilter(status)}
                    color={statusFilter === status ? 'primary' : 'default'}
                    variant={
                      statusFilter === status ? 'filled' : 'outlined'
                    }
                    sx={{
                      borderColor: cyberColors.neon.cyan,
                      color: cyberColors.neon.cyan,
                      ...(statusFilter === status && {
                        bgcolor: cyberColors.neon.cyan,
                        color: '#000',
                      }),
                    }}
                  />
                ))}
              </Stack>
            </Paper>

            {loading ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', py: 6 }}>
                <CircularProgress sx={{ color: cyberColors.neon.cyan }} />
              </Box>
            ) : (
              <Stack spacing={2}>
                {filteredAlerts.length === 0 ? (
                  <Paper
                    sx={{
                      ...glassmorphism.card,
                      p: 4,
                      textAlign: 'center',
                    }}
                  >
                    <CheckCircle
                      sx={{
                        fontSize: 48,
                        color: cyberColors.neon.green,
                        mb: 2,
                      }}
                    />
                    <Typography color="text.secondary">
                      No alerts matching your filters
                    </Typography>
                  </Paper>
                ) : (
                  filteredAlerts.map((alert) => (
                    <motion.div
                      key={alert.id}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.3 }}
                    >
                      <Card sx={{ ...glassmorphism.card }}>
                        <CardContent>
                          <Box
                            sx={{
                              display: 'flex',
                              justifyContent: 'space-between',
                              alignItems: 'flex-start',
                              mb: 2,
                            }}
                          >
                            <Box sx={{ display: 'flex', gap: 2, flex: 1 }}>
                              <Box
                                sx={{
                                  width: 4,
                                  bgcolor: getSeverityColor(alert.severity),
                                  borderRadius: 1,
                                  flexShrink: 0,
                                }}
                              />
                              <Box sx={{ flex: 1 }}>
                                <Box
                                  sx={{
                                    display: 'flex',
                                    gap: 1,
                                    alignItems: 'center',
                                    mb: 0.5,
                                  }}
                                >
                                  <Chip
                                    label={alert.severity.toUpperCase()}
                                    size="small"
                                    sx={{
                                      bgcolor: alpha(
                                        getSeverityColor(alert.severity),
                                        0.2
                                      ),
                                      color: getSeverityColor(alert.severity),
                                      fontWeight: 600,
                                    }}
                                    icon={getAlertTypeIcon(alert.alert_type) as React.ReactElement}
                                  />
                                  <Typography
                                    variant="caption"
                                    color="text.secondary"
                                  >
                                    {alert.alert_type}
                                  </Typography>
                                </Box>
                                <Typography
                                  variant="h6"
                                  sx={{
                                    fontFamily:
                                      designTokens.typography.fontFamily
                                        .display,
                                    color: cyberColors.neon.cyan,
                                    mb: 1,
                                  }}
                                >
                                  {alert.title}
                                </Typography>
                                <Typography
                                  variant="body2"
                                  color="text.secondary"
                                  sx={{ mb: 1 }}
                                >
                                  {alert.description}
                                </Typography>
                                {alert.diff_summary && (
                                  <Box
                                    sx={{
                                      p: 1,
                                      bgcolor: alpha(
                                        cyberColors.neon.cyan,
                                        0.05
                                      ),
                                      borderRadius: 1,
                                      fontFamily: 'monospace',
                                      fontSize: '0.75rem',
                                      color: cyberColors.neon.green,
                                      mb: 1,
                                      overflow: 'auto',
                                    }}
                                  >
                                    {alert.diff_summary}
                                  </Box>
                                )}
                                <Box
                                  sx={{
                                    display: 'flex',
                                    justifyContent: 'space-between',
                                    alignItems: 'center',
                                    mt: 2,
                                  }}
                                >
                                  <Box>
                                    <Typography
                                      variant="caption"
                                      color="text.secondary"
                                    >
                                      {alert.watchlist_name} •{' '}
                                      {formatRelativeTime(alert.triggered_at)}
                                    </Typography>
                                  </Box>
                                  <Chip
                                    label={alert.status}
                                    size="small"
                                    variant="outlined"
                                    sx={{
                                      borderColor:
                                        alert.status === 'new'
                                          ? cyberColors.neon.red
                                          : cyberColors.neon.cyan,
                                      color:
                                        alert.status === 'new'
                                          ? cyberColors.neon.red
                                          : cyberColors.neon.cyan,
                                    }}
                                  />
                                </Box>
                              </Box>
                            </Box>
                          </Box>
                        </CardContent>
                        <CardActions
                          sx={{
                            display: 'flex',
                            gap: 1,
                            pt: 0,
                            borderTop: `1px solid ${alpha(cyberColors.neon.cyan, 0.1)}`,
                          }}
                        >
                          {alert.status === 'new' && (
                            <Button
                              size="small"
                              onClick={() =>
                                handleAlertAction(alert.id, 'acknowledge')
                              }
                              sx={{ color: cyberColors.neon.cyan }}
                            >
                              Acknowledge
                            </Button>
                          )}
                          {alert.status !== 'resolved' && (
                            <Button
                              size="small"
                              onClick={() =>
                                handleAlertAction(alert.id, 'resolve')
                              }
                              sx={{ color: cyberColors.neon.green }}
                            >
                              Resolve
                            </Button>
                          )}
                          {alert.status !== 'dismissed' && (
                            <Button
                              size="small"
                              onClick={() =>
                                handleAlertAction(alert.id, 'dismiss')
                              }
                              sx={{ color: cyberColors.neon.orange }}
                            >
                              Dismiss
                            </Button>
                          )}
                        </CardActions>
                      </Card>
                    </motion.div>
                  ))
                )}
              </Stack>
            )}
          </motion.div>
        )}
      </Container>
    </motion.div>
  );
};

export default Monitoring;
