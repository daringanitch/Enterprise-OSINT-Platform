/**
 * AnnotationPanel
 *
 * Collapsible side-panel for live investigation annotations.
 * Analysts can write timestamped notes, tag specific entities (IOCs),
 * and see each other's comments in real time.
 *
 * Usage:
 *   <AnnotationPanel
 *     annotations={annotations}
 *     onAdd={addAnnotation}
 *     onDelete={deleteAnnotation}
 *     currentAnalystId="analyst-123"
 *   />
 */

import React, { useState, useRef, useCallback, useEffect } from 'react';
import {
  Box,
  Typography,
  TextField,
  Button,
  IconButton,
  Tooltip,
  Collapse,
  styled,
  Avatar,
  Divider,
} from '@mui/material';
import SendIcon from '@mui/icons-material/Send';
import DeleteOutlineIcon from '@mui/icons-material/DeleteOutline';
import CommentIcon from '@mui/icons-material/Comment';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import TagIcon from '@mui/icons-material/Tag';
import { cyberColors, designTokens, glassmorphism } from '../../utils/theme';
import { Annotation } from '../../hooks/useCollaboration';

// ─── Styled ───────────────────────────────────────────────────────────────────

const Panel = styled(Box)({
  ...glassmorphism.card,
  borderRadius: 12,
  overflow: 'hidden',
  display: 'flex',
  flexDirection: 'column',
});

const PanelHeader = styled(Box)({
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  padding: '12px 16px',
  borderBottom: `1px solid ${cyberColors.dark.steel}60`,
  cursor: 'pointer',
  '&:hover': { backgroundColor: `${cyberColors.neon.cyan}05` },
});

const AnnotationList = styled(Box)({
  flex: 1,
  overflowY: 'auto',
  maxHeight: 360,
  scrollbarWidth: 'thin',
  scrollbarColor: `${cyberColors.dark.steel} transparent`,
  '&::-webkit-scrollbar': { width: 3 },
  '&::-webkit-scrollbar-thumb': { backgroundColor: cyberColors.dark.steel, borderRadius: 2 },
});

const AnnotationItem = styled(Box)<{ ismine?: string }>(({ ismine }) => ({
  padding: '10px 16px',
  borderLeft: `2px solid transparent`,
  transition: 'background 0.15s',
  '&:hover': {
    backgroundColor: `${cyberColors.dark.steel}15`,
    '& .delete-btn': { opacity: 1 },
  },
  ...(ismine === 'true' && {
    borderLeftColor: `${cyberColors.neon.cyan}50`,
  }),
}));

const EntityTag = styled(Box)({
  display: 'inline-flex',
  alignItems: 'center',
  gap: 4,
  padding: '1px 8px',
  borderRadius: 12,
  fontSize: '0.7rem',
  fontFamily: designTokens.typography.fontFamily.mono,
  backgroundColor: `${cyberColors.neon.orange}15`,
  color: cyberColors.neon.orange,
  border: `1px solid ${cyberColors.neon.orange}30`,
  marginBottom: 4,
});

const ComposeDivider = styled(Box)({
  borderTop: `1px solid ${cyberColors.dark.steel}60`,
  padding: '12px 16px',
  display: 'flex',
  flexDirection: 'column',
  gap: 8,
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatTime(isoDate: string): string {
  const d = new Date(isoDate);
  const now = new Date();
  const diff = (now.getTime() - d.getTime()) / 1000;
  if (diff < 60) return 'just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return d.toLocaleDateString();
}

function initials(name: string): string {
  return name.split(/\s+/).slice(0, 2).map((n) => n[0]?.toUpperCase() || '').join('');
}

// ─── Types ────────────────────────────────────────────────────────────────────

export interface AnnotationPanelProps {
  annotations: Annotation[];
  onAdd: (text: string, entity?: { value: string; type: string }) => Promise<Annotation | null>;
  onDelete: (id: string) => Promise<void>;
  currentAnalystId: string;
  /** Pre-fill entity when opening from a right-click context menu */
  prefillEntity?: { value: string; type: string } | null;
  defaultOpen?: boolean;
}

// ─── Component ────────────────────────────────────────────────────────────────

export const AnnotationPanel: React.FC<AnnotationPanelProps> = ({
  annotations,
  onAdd,
  onDelete,
  currentAnalystId,
  prefillEntity = null,
  defaultOpen = true,
}) => {
  const [open, setOpen] = useState(defaultOpen);
  const [text, setText] = useState('');
  const [entity, setEntity] = useState<{ value: string; type: string } | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to newest annotation
  useEffect(() => {
    if (listRef.current && annotations.length > 0) {
      listRef.current.scrollTop = 0; // newest first
    }
  }, [annotations.length]);

  // Pre-fill entity from context
  useEffect(() => {
    if (prefillEntity) {
      setEntity(prefillEntity);
      setOpen(true);
    }
  }, [prefillEntity]);

  const handleSubmit = useCallback(async () => {
    const trimmed = text.trim();
    if (!trimmed || submitting) return;
    setSubmitting(true);
    try {
      await onAdd(trimmed, entity || undefined);
      setText('');
      setEntity(null);
    } finally {
      setSubmitting(false);
    }
  }, [text, entity, submitting, onAdd]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault();
      handleSubmit();
    }
  };

  return (
    <Panel>
      {/* Header */}
      <PanelHeader onClick={() => setOpen((v) => !v)}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <CommentIcon sx={{ fontSize: '1rem', color: cyberColors.neon.purple }} />
          <Typography sx={{ fontSize: '0.85rem', fontWeight: 600, color: cyberColors.text.primary }}>
            Annotations
          </Typography>
          {annotations.length > 0 && (
            <Box
              sx={{
                minWidth: 18, height: 18, borderRadius: 9, px: 0.5,
                backgroundColor: `${cyberColors.neon.purple}25`,
                color: cyberColors.neon.purple,
                fontSize: '0.65rem', fontWeight: 700,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}
            >
              {annotations.length}
            </Box>
          )}
        </Box>
        <IconButton size="small" sx={{ color: cyberColors.text.muted, p: 0.25 }}>
          {open ? <ExpandLessIcon fontSize="small" /> : <ExpandMoreIcon fontSize="small" />}
        </IconButton>
      </PanelHeader>

      <Collapse in={open}>
        {/* Annotation list */}
        <AnnotationList ref={listRef}>
          {annotations.length === 0 ? (
            <Box sx={{ p: '20px 16px', textAlign: 'center' }}>
              <Typography sx={{ fontSize: '0.78rem', color: cyberColors.text.muted, fontStyle: 'italic' }}>
                No annotations yet. Add a note below.
              </Typography>
            </Box>
          ) : (
            annotations.map((ann, i) => {
              const isMine = ann.analyst_id === currentAnalystId;
              return (
                <React.Fragment key={ann.id}>
                  <AnnotationItem ismine={isMine.toString()}>
                    <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1 }}>
                      <Avatar
                        sx={{
                          width: 26, height: 26,
                          fontSize: '0.65rem', fontWeight: 700,
                          backgroundColor: `${ann.color}20`,
                          color: ann.color,
                          border: `1px solid ${ann.color}50`,
                          flexShrink: 0, mt: 0.25,
                        }}
                      >
                        {initials(ann.analyst_name)}
                      </Avatar>
                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.25 }}>
                          <Typography sx={{ fontSize: '0.75rem', fontWeight: 600, color: ann.color }}>
                            {ann.analyst_name}
                          </Typography>
                          <Typography sx={{ fontSize: '0.65rem', color: cyberColors.text.muted }}>
                            {formatTime(ann.created_at)}
                          </Typography>
                        </Box>
                        {ann.entity && (
                          <EntityTag>
                            <TagIcon sx={{ fontSize: '0.7rem' }} />
                            {ann.entity.type}: {ann.entity.value}
                          </EntityTag>
                        )}
                        <Typography sx={{ fontSize: '0.82rem', color: cyberColors.text.secondary, lineHeight: 1.5 }}>
                          {ann.text}
                        </Typography>
                      </Box>
                      {isMine && (
                        <Tooltip title="Delete annotation">
                          <IconButton
                            className="delete-btn"
                            size="small"
                            onClick={() => onDelete(ann.id)}
                            sx={{
                              opacity: 0,
                              transition: 'opacity 0.15s',
                              color: cyberColors.text.muted,
                              p: 0.25,
                              '&:hover': { color: cyberColors.neon.red },
                            }}
                          >
                            <DeleteOutlineIcon sx={{ fontSize: '0.9rem' }} />
                          </IconButton>
                        </Tooltip>
                      )}
                    </Box>
                  </AnnotationItem>
                  {i < annotations.length - 1 && (
                    <Divider sx={{ borderColor: `${cyberColors.dark.steel}30`, mx: 2 }} />
                  )}
                </React.Fragment>
              );
            })
          )}
        </AnnotationList>

        {/* Compose */}
        <ComposeDivider>
          {entity && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <EntityTag>
                <TagIcon sx={{ fontSize: '0.7rem' }} />
                {entity.type}: {entity.value}
              </EntityTag>
              <IconButton
                size="small"
                onClick={() => setEntity(null)}
                sx={{ color: cyberColors.text.muted, p: 0.25, fontSize: '0.7rem' }}
              >
                ✕
              </IconButton>
            </Box>
          )}
          <Box sx={{ display: 'flex', gap: 1 }}>
            <TextField
              value={text}
              onChange={(e) => setText(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Add a note… (⌘↵ to submit)"
              multiline
              maxRows={4}
              size="small"
              fullWidth
              sx={{
                '& .MuiOutlinedInput-root': {
                  '& fieldset': { borderColor: `${cyberColors.dark.steel}60` },
                  '&:hover fieldset': { borderColor: cyberColors.neon.purple },
                  '&.Mui-focused fieldset': { borderColor: cyberColors.neon.purple },
                  color: cyberColors.text.primary,
                  fontSize: '0.82rem',
                },
              }}
            />
            <Button
              variant="contained"
              onClick={handleSubmit}
              disabled={!text.trim() || submitting}
              sx={{
                minWidth: 40, width: 40, height: 40, p: 0, flexShrink: 0, alignSelf: 'flex-end',
                backgroundColor: cyberColors.neon.purple,
                '&:hover': { backgroundColor: '#7C3AED' },
                '&.Mui-disabled': { backgroundColor: `${cyberColors.neon.purple}30` },
              }}
            >
              <SendIcon sx={{ fontSize: '1rem' }} />
            </Button>
          </Box>
        </ComposeDivider>
      </Collapse>
    </Panel>
  );
};

export default AnnotationPanel;
