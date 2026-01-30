/**
 * TimelineChart Component
 *
 * Vertical timeline for displaying chronological events and investigation history.
 */

import React, { useMemo } from 'react';
import {
  Box,
  Typography,
  Paper,
  useTheme,
  Chip,
  Collapse,
  IconButton,
} from '@mui/material';
import {
  Timeline,
  TimelineItem,
  TimelineSeparator,
  TimelineConnector,
  TimelineContent,
  TimelineDot,
  TimelineOppositeContent,
} from '@mui/lab';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';

export interface TimelineEvent {
  id: string;
  timestamp: string | Date;
  title: string;
  description?: string;
  type?: 'info' | 'success' | 'warning' | 'error' | 'primary';
  icon?: React.ReactNode;
  tags?: string[];
  details?: Record<string, any>;
  source?: string;
}

export interface TimelineChartProps {
  /** Timeline events */
  events: TimelineEvent[];
  /** Chart title */
  title?: string;
  /** Show timestamps on opposite side */
  showTimestamps?: boolean;
  /** Date format function */
  formatDate?: (date: Date) => string;
  /** Time format function */
  formatTime?: (date: Date) => string;
  /** Allow expanding event details */
  expandable?: boolean;
  /** Maximum height with scroll */
  maxHeight?: number;
  /** Group events by date */
  groupByDate?: boolean;
  /** Test ID for testing */
  testId?: string;
}

const defaultFormatDate = (date: Date): string => {
  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
};

const defaultFormatTime = (date: Date): string => {
  return date.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
  });
};

const typeColors: Record<string, 'primary' | 'secondary' | 'success' | 'warning' | 'error' | 'info'> = {
  info: 'info',
  success: 'success',
  warning: 'warning',
  error: 'error',
  primary: 'primary',
};

interface TimelineEventItemProps {
  event: TimelineEvent;
  showTimestamp: boolean;
  formatDate: (date: Date) => string;
  formatTime: (date: Date) => string;
  expandable: boolean;
  isLast: boolean;
}

const TimelineEventItem: React.FC<TimelineEventItemProps> = ({
  event,
  showTimestamp,
  formatDate,
  formatTime,
  expandable,
  isLast,
}) => {
  const theme = useTheme();
  const [expanded, setExpanded] = React.useState(false);

  const eventDate = useMemo(
    () => (typeof event.timestamp === 'string' ? new Date(event.timestamp) : event.timestamp),
    [event.timestamp]
  );

  const dotColor = typeColors[event.type || 'info'];

  const hasDetails = event.details && Object.keys(event.details).length > 0;

  return (
    <TimelineItem>
      {showTimestamp && (
        <TimelineOppositeContent
          sx={{ flex: 0.3, py: 1.5 }}
          color="text.secondary"
        >
          <Typography variant="caption" display="block">
            {formatDate(eventDate)}
          </Typography>
          <Typography variant="caption" display="block" color="text.disabled">
            {formatTime(eventDate)}
          </Typography>
        </TimelineOppositeContent>
      )}
      <TimelineSeparator>
        <TimelineDot color={dotColor} variant={event.icon ? 'outlined' : 'filled'}>
          {event.icon}
        </TimelineDot>
        {!isLast && <TimelineConnector />}
      </TimelineSeparator>
      <TimelineContent sx={{ py: 1.5, px: 2 }}>
        <Paper
          elevation={1}
          sx={{
            p: 2,
            bgcolor: theme.palette.mode === 'dark' ? 'grey.900' : 'grey.50',
            '&:hover': {
              bgcolor: theme.palette.mode === 'dark' ? 'grey.800' : 'grey.100',
            },
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
            <Box sx={{ flex: 1 }}>
              <Typography variant="subtitle2" fontWeight="bold">
                {event.title}
              </Typography>
              {!showTimestamp && (
                <Typography variant="caption" color="text.secondary">
                  {formatDate(eventDate)} {formatTime(eventDate)}
                </Typography>
              )}
            </Box>
            {expandable && hasDetails && (
              <IconButton
                size="small"
                onClick={() => setExpanded(!expanded)}
                aria-label={expanded ? 'Collapse details' : 'Expand details'}
              >
                {expanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
              </IconButton>
            )}
          </Box>

          {event.description && (
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              {event.description}
            </Typography>
          )}

          {event.tags && event.tags.length > 0 && (
            <Box sx={{ mt: 1, display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
              {event.tags.map((tag, index) => (
                <Chip
                  key={index}
                  label={tag}
                  size="small"
                  variant="outlined"
                  sx={{ fontSize: '0.7rem', height: 20 }}
                />
              ))}
            </Box>
          )}

          {event.source && (
            <Typography
              variant="caption"
              color="text.disabled"
              sx={{ display: 'block', mt: 1 }}
            >
              Source: {event.source}
            </Typography>
          )}

          <Collapse in={expanded}>
            {hasDetails && (
              <Box
                sx={{
                  mt: 2,
                  pt: 2,
                  borderTop: 1,
                  borderColor: 'divider',
                }}
              >
                <Typography variant="caption" fontWeight="bold" gutterBottom>
                  Details
                </Typography>
                <Box
                  component="pre"
                  sx={{
                    mt: 1,
                    p: 1,
                    bgcolor: 'background.default',
                    borderRadius: 1,
                    fontSize: '0.75rem',
                    overflow: 'auto',
                    maxHeight: 200,
                  }}
                >
                  {JSON.stringify(event.details, null, 2)}
                </Box>
              </Box>
            )}
          </Collapse>
        </Paper>
      </TimelineContent>
    </TimelineItem>
  );
};

export const TimelineChart: React.FC<TimelineChartProps> = ({
  events,
  title,
  showTimestamps = true,
  formatDate = defaultFormatDate,
  formatTime = defaultFormatTime,
  expandable = true,
  maxHeight,
  groupByDate = false,
  testId,
}) => {
  const sortedEvents = useMemo(
    () =>
      [...events].sort((a, b) => {
        const dateA = typeof a.timestamp === 'string' ? new Date(a.timestamp) : a.timestamp;
        const dateB = typeof b.timestamp === 'string' ? new Date(b.timestamp) : b.timestamp;
        return dateB.getTime() - dateA.getTime(); // Newest first
      }),
    [events]
  );

  const groupedEvents = useMemo(() => {
    if (!groupByDate) return null;

    const groups: Record<string, TimelineEvent[]> = {};
    sortedEvents.forEach((event) => {
      const date = typeof event.timestamp === 'string' ? new Date(event.timestamp) : event.timestamp;
      const dateKey = formatDate(date);
      if (!groups[dateKey]) {
        groups[dateKey] = [];
      }
      groups[dateKey].push(event);
    });
    return groups;
  }, [sortedEvents, groupByDate, formatDate]);

  if (events.length === 0) {
    return (
      <Box data-testid={testId} sx={{ textAlign: 'center', py: 4 }}>
        <Typography color="text.secondary">No events to display</Typography>
      </Box>
    );
  }

  return (
    <Box data-testid={testId}>
      {title && (
        <Typography variant="h6" gutterBottom>
          {title}
        </Typography>
      )}
      <Box
        sx={{
          maxHeight: maxHeight,
          overflow: maxHeight ? 'auto' : 'visible',
        }}
      >
        {groupByDate && groupedEvents ? (
          Object.entries(groupedEvents).map(([date, dateEvents]) => (
            <Box key={date} sx={{ mb: 3 }}>
              <Typography
                variant="subtitle2"
                color="text.secondary"
                sx={{
                  mb: 1,
                  pl: 2,
                  borderLeft: 3,
                  borderColor: 'primary.main',
                }}
              >
                {date}
              </Typography>
              <Timeline position={showTimestamps ? 'right' : 'right'}>
                {dateEvents.map((event, index) => (
                  <TimelineEventItem
                    key={event.id}
                    event={event}
                    showTimestamp={false} // Already shown in group header
                    formatDate={formatDate}
                    formatTime={formatTime}
                    expandable={expandable}
                    isLast={index === dateEvents.length - 1}
                  />
                ))}
              </Timeline>
            </Box>
          ))
        ) : (
          <Timeline position={showTimestamps ? 'alternate' : 'right'}>
            {sortedEvents.map((event, index) => (
              <TimelineEventItem
                key={event.id}
                event={event}
                showTimestamp={showTimestamps}
                formatDate={formatDate}
                formatTime={formatTime}
                expandable={expandable}
                isLast={index === sortedEvents.length - 1}
              />
            ))}
          </Timeline>
        )}
      </Box>
    </Box>
  );
};

export default TimelineChart;
