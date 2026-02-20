/**
 * InvestigationTimeline Component
 *
 * Chronological visualization of investigation events with
 * animated appearance, severity coding, and expandable details.
 *
 * Features:
 * - Animated event appearance on load
 * - Event type icons (infrastructure, social, threat, credential)
 * - Severity color coding
 * - Source attribution
 * - Expandable event details
 * - Time range zoom controls
 */

import React, { useState, useMemo, useRef, useCallback } from 'react';
import {
  Box,
  Typography,
  Chip,
  IconButton,
  Tooltip,
  Collapse,
  Paper,
  Slider,
  alpha,
  styled,
} from '@mui/material';
import { motion, AnimatePresence } from 'framer-motion';
import TimelineIcon from '@mui/icons-material/Timeline';
import StorageIcon from '@mui/icons-material/Storage';
import PersonIcon from '@mui/icons-material/Person';
import BugReportIcon from '@mui/icons-material/BugReport';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import PublicIcon from '@mui/icons-material/Public';
import EmailIcon from '@mui/icons-material/Email';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import ZoomInIcon from '@mui/icons-material/ZoomIn';
import ZoomOutIcon from '@mui/icons-material/ZoomOut';
import FilterListIcon from '@mui/icons-material/FilterList';
import { cyberColors, designTokens, glassmorphism } from '../../utils/theme';
import { staggerContainer, staggerItem } from '../../utils/animations';

// =============================================================================
// Types
// =============================================================================

export type EventType =
  | 'infrastructure'
  | 'social'
  | 'threat'
  | 'credential'
  | 'network'
  | 'email'
  | 'discovery'
  | 'correlation';

export type EventSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface TimelineEvent {
  id: string;
  timestamp: string; // ISO date string
  title: string;
  description: string;
  type: EventType;
  severity: EventSeverity;
  source: string; // MCP server or data source name
  entities?: string[]; // Related entity IDs
  details?: Record<string, any>;
  linkedEvents?: string[]; // IDs of related events
}

export interface InvestigationTimelineProps {
  /** Timeline events */
  events: TimelineEvent[];
  /** Title */
  title?: string;
  /** Height */
  height?: number;
  /** Loading state */
  loading?: boolean;
  /** Event click handler */
  onEventClick?: (event: TimelineEvent) => void;
  /** Filter by event types */
  typeFilter?: EventType[];
  /** Filter by severity */
  severityFilter?: EventSeverity[];
  /** Test ID */
  testId?: string;
}

// =============================================================================
// Event Type Configuration
// =============================================================================

const eventTypeConfig: Record<EventType, { icon: React.ReactNode; color: string; label: string }> = {
  infrastructure: {
    icon: <StorageIcon fontSize="small" />,
    color: cyberColors.neon.cyan,
    label: 'Infrastructure',
  },
  social: {
    icon: <PersonIcon fontSize="small" />,
    color: cyberColors.neon.purple,
    label: 'Social',
  },
  threat: {
    icon: <BugReportIcon fontSize="small" />,
    color: cyberColors.neon.red,
    label: 'Threat',
  },
  credential: {
    icon: <VpnKeyIcon fontSize="small" />,
    color: cyberColors.neon.orange,
    label: 'Credential',
  },
  network: {
    icon: <PublicIcon fontSize="small" />,
    color: cyberColors.neon.electricBlue,
    label: 'Network',
  },
  email: {
    icon: <EmailIcon fontSize="small" />,
    color: cyberColors.neon.magenta,
    label: 'Email',
  },
  discovery: {
    icon: <TimelineIcon fontSize="small" />,
    color: cyberColors.neon.green,
    label: 'Discovery',
  },
  correlation: {
    icon: <TimelineIcon fontSize="small" />,
    color: cyberColors.neon.yellow,
    label: 'Correlation',
  },
};

const severityConfig: Record<EventSeverity, { color: string; label: string }> = {
  critical: { color: cyberColors.neon.magenta, label: 'CRITICAL' },
  high: { color: cyberColors.neon.red, label: 'HIGH' },
  medium: { color: cyberColors.neon.orange, label: 'MEDIUM' },
  low: { color: cyberColors.neon.yellow, label: 'LOW' },
  info: { color: cyberColors.neon.cyan, label: 'INFO' },
};

// =============================================================================
// Styled Components
// =============================================================================

const TimelineContainer = styled(Paper)(({ theme }) => ({
  ...glassmorphism.card,
  borderRadius: designTokens.borderRadius.lg,
  overflow: 'hidden',
}));

const HeaderSection = styled(Box)(({ theme }) => ({
  padding: '16px 20px',
  borderBottom: `1px solid ${alpha(cyberColors.neon.cyan, 0.1)}`,
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
}));

const TimelineTrack = styled(Box)(({ theme }) => ({
  position: 'relative',
  padding: '20px 20px 20px 60px',
  '&::before': {
    content: '""',
    position: 'absolute',
    left: 40,
    top: 0,
    bottom: 0,
    width: 2,
    background: `linear-gradient(180deg,
      ${alpha(cyberColors.neon.cyan, 0.5)} 0%,
      ${alpha(cyberColors.neon.magenta, 0.5)} 50%,
      ${alpha(cyberColors.neon.cyan, 0.5)} 100%
    )`,
    boxShadow: `0 0 10px ${alpha(cyberColors.neon.cyan, 0.3)}`,
  },
}));

const EventCard = styled(motion.div)<{ severityColor: string }>(({ severityColor }) => ({
  ...glassmorphism.interactive,
  borderRadius: designTokens.borderRadius.md,
  marginBottom: 12,
  position: 'relative',
  cursor: 'pointer',
  borderLeft: `3px solid ${severityColor}`,
  '&::before': {
    content: '""',
    position: 'absolute',
    left: -26,
    top: 16,
    width: 12,
    height: 12,
    borderRadius: '50%',
    background: severityColor,
    boxShadow: `0 0 10px ${severityColor}`,
    zIndex: 1,
  },
}));

const EventHeader = styled(Box)(({ theme }) => ({
  padding: 12,
  display: 'flex',
  alignItems: 'flex-start',
  justifyContent: 'space-between',
}));

const EventDetails = styled(Box)(({ theme }) => ({
  padding: '0 12px 12px',
  borderTop: `1px solid ${alpha(cyberColors.neon.cyan, 0.1)}`,
}));

const TimeMarker = styled(Typography)(({ theme }) => ({
  position: 'absolute',
  left: -48,
  top: 12,
  fontSize: '0.6rem',
  color: cyberColors.text.muted,
  fontFamily: designTokens.typography.fontFamily.mono,
  writingMode: 'vertical-rl',
  textOrientation: 'mixed',
  transform: 'rotate(180deg)',
}));

const FilterBar = styled(Box)(({ theme }) => ({
  display: 'flex',
  gap: 4,
  flexWrap: 'wrap',
  padding: '8px 20px',
  borderBottom: `1px solid ${alpha(cyberColors.neon.cyan, 0.1)}`,
  background: alpha(cyberColors.dark.steel, 0.3),
}));

// =============================================================================
// Component
// =============================================================================

export const InvestigationTimeline: React.FC<InvestigationTimelineProps> = ({
  events,
  title = 'Investigation Timeline',
  height = 500,
  loading = false,
  onEventClick,
  typeFilter,
  severityFilter,
  testId,
}) => {
  const [expandedEvents, setExpandedEvents] = useState<Set<string>>(new Set());
  const [activeTypeFilters, setActiveTypeFilters] = useState<Set<EventType>>(
    new Set(typeFilter || Object.keys(eventTypeConfig) as EventType[])
  );
  const [activeSeverityFilters, setActiveSeverityFilters] = useState<Set<EventSeverity>>(
    new Set(severityFilter || Object.keys(severityConfig) as EventSeverity[])
  );
  const [showFilters, setShowFilters] = useState(false);

  // Filter and sort events
  const filteredEvents = useMemo(() => {
    return events
      .filter((event) =>
        activeTypeFilters.has(event.type) && activeSeverityFilters.has(event.severity)
      )
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }, [events, activeTypeFilters, activeSeverityFilters]);

  const toggleEventExpanded = (eventId: string) => {
    setExpandedEvents((prev) => {
      const next = new Set(prev);
      if (next.has(eventId)) {
        next.delete(eventId);
      } else {
        next.add(eventId);
      }
      return next;
    });
  };

  const toggleTypeFilter = (type: EventType) => {
    setActiveTypeFilters((prev) => {
      const next = new Set(prev);
      if (next.has(type)) {
        if (next.size > 1) next.delete(type);
      } else {
        next.add(type);
      }
      return next;
    });
  };

  const toggleSeverityFilter = (severity: EventSeverity) => {
    setActiveSeverityFilters((prev) => {
      const next = new Set(prev);
      if (next.has(severity)) {
        if (next.size > 1) next.delete(severity);
      } else {
        next.add(severity);
      }
      return next;
    });
  };

  const formatTime = (timestamp: string): string => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  const formatDate = (timestamp: string): string => {
    const date = new Date(timestamp);
    return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
  };

  // Group events by date
  const groupedEvents = useMemo(() => {
    const groups: { date: string; events: TimelineEvent[] }[] = [];
    let currentDate = '';

    filteredEvents.forEach((event) => {
      const eventDate = formatDate(event.timestamp);
      if (eventDate !== currentDate) {
        currentDate = eventDate;
        groups.push({ date: eventDate, events: [event] });
      } else {
        groups[groups.length - 1].events.push(event);
      }
    });

    return groups;
  }, [filteredEvents]);

  return (
    <TimelineContainer data-testid={testId}>
      {/* Header */}
      <HeaderSection>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <TimelineIcon sx={{ color: cyberColors.neon.cyan }} />
          <Box>
            <Typography
              variant="h6"
              sx={{
                fontFamily: designTokens.typography.fontFamily.display,
                color: cyberColors.text.primary,
                fontSize: '1rem',
              }}
            >
              {title}
            </Typography>
            <Typography variant="caption" sx={{ color: cyberColors.text.secondary }}>
              {filteredEvents.length} events | {events.length} total
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Tooltip title="Toggle Filters">
            <IconButton
              size="small"
              onClick={() => setShowFilters(!showFilters)}
              sx={{ color: showFilters ? cyberColors.neon.cyan : undefined }}
            >
              <FilterListIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
      </HeaderSection>

      {/* Filter Bar */}
      <Collapse in={showFilters}>
        <FilterBar>
          <Typography variant="caption" sx={{ color: cyberColors.text.muted, mr: 1 }}>
            Types:
          </Typography>
          {(Object.keys(eventTypeConfig) as EventType[]).map((type) => {
            const config = eventTypeConfig[type];
            const isActive = activeTypeFilters.has(type);
            return (
              <Chip
                key={type}
                label={config.label}
                icon={<Box sx={{ color: 'inherit', display: 'flex' }}>{config.icon}</Box>}
                size="small"
                onClick={() => toggleTypeFilter(type)}
                sx={{
                  height: 22,
                  fontSize: '0.65rem',
                  bgcolor: isActive ? alpha(config.color, 0.2) : 'transparent',
                  color: isActive ? config.color : cyberColors.text.muted,
                  border: `1px solid ${isActive ? config.color : alpha(cyberColors.text.muted, 0.3)}`,
                  cursor: 'pointer',
                }}
              />
            );
          })}
          <Box sx={{ width: '100%', mt: 0.5 }} />
          <Typography variant="caption" sx={{ color: cyberColors.text.muted, mr: 1 }}>
            Severity:
          </Typography>
          {(Object.keys(severityConfig) as EventSeverity[]).map((severity) => {
            const config = severityConfig[severity];
            const isActive = activeSeverityFilters.has(severity);
            return (
              <Chip
                key={severity}
                label={config.label}
                size="small"
                onClick={() => toggleSeverityFilter(severity)}
                sx={{
                  height: 20,
                  fontSize: '0.6rem',
                  bgcolor: isActive ? alpha(config.color, 0.2) : 'transparent',
                  color: isActive ? config.color : cyberColors.text.muted,
                  border: `1px solid ${isActive ? config.color : alpha(cyberColors.text.muted, 0.3)}`,
                  cursor: 'pointer',
                }}
              />
            );
          })}
        </FilterBar>
      </Collapse>

      {/* Timeline Track */}
      <Box sx={{ height, overflowY: 'auto' }}>
        {loading ? (
          <Box sx={{ p: 4, textAlign: 'center' }}>
            <Typography color="text.secondary">Loading timeline events...</Typography>
          </Box>
        ) : filteredEvents.length === 0 ? (
          <Box sx={{ p: 4, textAlign: 'center' }}>
            <Typography color="text.secondary">No events to display</Typography>
          </Box>
        ) : (
          <motion.div
            variants={staggerContainer}
            initial="initial"
            animate="enter"
          >
            {groupedEvents.map((group, groupIndex) => (
              <Box key={group.date}>
                {/* Date Header */}
                <Box
                  sx={{
                    px: 2,
                    py: 1,
                    bgcolor: alpha(cyberColors.dark.steel, 0.5),
                    position: 'sticky',
                    top: 0,
                    zIndex: 5,
                  }}
                >
                  <Typography
                    variant="caption"
                    sx={{
                      color: cyberColors.neon.cyan,
                      fontWeight: 600,
                      fontFamily: designTokens.typography.fontFamily.mono,
                    }}
                  >
                    {group.date}
                  </Typography>
                </Box>

                <TimelineTrack>
                  <AnimatePresence>
                    {group.events.map((event, eventIndex) => {
                      const typeConfig = eventTypeConfig[event.type];
                      const sevConfig = severityConfig[event.severity];
                      const isExpanded = expandedEvents.has(event.id);

                      return (
                        <EventCard
                          key={event.id}
                          severityColor={sevConfig.color}
                          variants={staggerItem}
                          onClick={() => {
                            toggleEventExpanded(event.id);
                            onEventClick?.(event);
                          }}
                          whileHover={{ x: 4 }}
                        >
                          {/* Time marker */}
                          <Typography
                            sx={{
                              position: 'absolute',
                              left: -45,
                              top: 20,
                              fontSize: '0.55rem',
                              color: cyberColors.text.muted,
                              fontFamily: designTokens.typography.fontFamily.mono,
                            }}
                          >
                            {formatTime(event.timestamp)}
                          </Typography>

                          <EventHeader>
                            <Box sx={{ flex: 1, minWidth: 0 }}>
                              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                                <Box sx={{ color: typeConfig.color, display: 'flex' }}>
                                  {typeConfig.icon}
                                </Box>
                                <Typography
                                  variant="subtitle2"
                                  sx={{
                                    fontWeight: 600,
                                    color: cyberColors.text.primary,
                                    overflow: 'hidden',
                                    textOverflow: 'ellipsis',
                                    whiteSpace: 'nowrap',
                                  }}
                                >
                                  {event.title}
                                </Typography>
                              </Box>
                              <Typography
                                variant="caption"
                                sx={{
                                  color: cyberColors.text.secondary,
                                  display: 'block',
                                  overflow: 'hidden',
                                  textOverflow: 'ellipsis',
                                  whiteSpace: isExpanded ? 'normal' : 'nowrap',
                                }}
                              >
                                {event.description}
                              </Typography>
                            </Box>
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, ml: 1 }}>
                              <Chip
                                label={sevConfig.label}
                                size="small"
                                sx={{
                                  height: 18,
                                  fontSize: '0.55rem',
                                  fontWeight: 700,
                                  bgcolor: alpha(sevConfig.color, 0.2),
                                  color: sevConfig.color,
                                }}
                              />
                              <IconButton size="small">
                                {isExpanded ? (
                                  <ExpandLessIcon fontSize="small" />
                                ) : (
                                  <ExpandMoreIcon fontSize="small" />
                                )}
                              </IconButton>
                            </Box>
                          </EventHeader>

                          {/* Expanded Details */}
                          <Collapse in={isExpanded}>
                            <EventDetails>
                              <Box sx={{ pt: 1 }}>
                                <Typography
                                  variant="caption"
                                  sx={{
                                    color: cyberColors.text.muted,
                                    fontFamily: designTokens.typography.fontFamily.mono,
                                    display: 'block',
                                    mb: 1,
                                  }}
                                >
                                  Source: <span style={{ color: cyberColors.neon.cyan }}>{event.source}</span>
                                </Typography>

                                {event.entities && event.entities.length > 0 && (
                                  <Box sx={{ mb: 1 }}>
                                    <Typography
                                      variant="caption"
                                      sx={{ color: cyberColors.text.muted, display: 'block', mb: 0.5 }}
                                    >
                                      Related Entities:
                                    </Typography>
                                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                                      {event.entities.slice(0, 5).map((entity) => (
                                        <Chip
                                          key={entity}
                                          label={entity}
                                          size="small"
                                          sx={{
                                            height: 18,
                                            fontSize: '0.6rem',
                                            bgcolor: alpha(cyberColors.neon.cyan, 0.15),
                                          }}
                                        />
                                      ))}
                                      {event.entities.length > 5 && (
                                        <Chip
                                          label={`+${event.entities.length - 5}`}
                                          size="small"
                                          sx={{
                                            height: 18,
                                            fontSize: '0.6rem',
                                            bgcolor: alpha(cyberColors.text.muted, 0.2),
                                          }}
                                        />
                                      )}
                                    </Box>
                                  </Box>
                                )}

                                {event.details && (
                                  <Box>
                                    {Object.entries(event.details).slice(0, 4).map(([key, value]) => (
                                      <Typography
                                        key={key}
                                        variant="caption"
                                        sx={{
                                          display: 'block',
                                          fontFamily: designTokens.typography.fontFamily.mono,
                                          color: cyberColors.text.secondary,
                                          fontSize: '0.65rem',
                                        }}
                                      >
                                        <span style={{ color: cyberColors.neon.cyan }}>{key}:</span>{' '}
                                        {String(value).substring(0, 60)}
                                      </Typography>
                                    ))}
                                  </Box>
                                )}
                              </Box>
                            </EventDetails>
                          </Collapse>
                        </EventCard>
                      );
                    })}
                  </AnimatePresence>
                </TimelineTrack>
              </Box>
            ))}
          </motion.div>
        )}
      </Box>
    </TimelineContainer>
  );
};

export default InvestigationTimeline;
