/**
 * SearchBar
 *
 * Full-featured filter bar for the Investigations page.
 *
 * Features:
 *  - Free-text search across target / type fields (live client-side filtering)
 *  - Dropdown filters: Status, Priority, Risk Level
 *  - Saved searches panel: save current query, re-apply saved queries, delete them
 *  - "Save Search" button opens an inline modal (name + description)
 *  - Clear all resets every filter
 *
 * Usage:
 *   <SearchBar
 *     params={searchParams}
 *     onChange={setSearchParams}
 *     savedSearches={savedSearches}
 *     onSaveSearch={handleSave}
 *     onDeleteSearch={handleDelete}
 *     onSelectSavedSearch={handleSelect}
 *   />
 */

import React, { useState, useCallback, useRef } from 'react';
import {
  Box,
  TextField,
  InputAdornment,
  IconButton,
  Button,
  Chip,
  Menu,
  MenuItem,
  Divider,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Typography,
  Tooltip,
  styled,
  Collapse,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import ClearIcon from '@mui/icons-material/Clear';
import BookmarkAddIcon from '@mui/icons-material/BookmarkAdd';
import BookmarkIcon from '@mui/icons-material/Bookmark';
import BookmarkBorderIcon from '@mui/icons-material/BookmarkBorder';
import DeleteOutlineIcon from '@mui/icons-material/DeleteOutline';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import FilterListIcon from '@mui/icons-material/FilterList';
import { cyberColors, designTokens } from '../../utils/theme';
import { SearchParams, SavedSearch } from '../../hooks/useSavedSearches';

// ─── Constants ────────────────────────────────────────────────────────────────

const STATUS_OPTIONS = [
  { value: 'pending', label: 'Pending' },
  { value: 'queued', label: 'Queued' },
  { value: 'planning', label: 'Planning' },
  { value: 'profiling', label: 'Profiling' },
  { value: 'collecting', label: 'Collecting' },
  { value: 'analyzing', label: 'Analyzing' },
  { value: 'assessing_risk', label: 'Assessing Risk' },
  { value: 'verifying', label: 'Verifying' },
  { value: 'generating_report', label: 'Generating Report' },
  { value: 'completed', label: 'Completed' },
  { value: 'failed', label: 'Failed' },
  { value: 'cancelled', label: 'Cancelled' },
];

const PRIORITY_OPTIONS = [
  { value: 'critical', label: 'Critical' },
  { value: 'urgent', label: 'Urgent' },
  { value: 'high', label: 'High' },
  { value: 'normal', label: 'Normal' },
  { value: 'low', label: 'Low' },
];

const RISK_OPTIONS = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' },
];

// ─── Styled components ────────────────────────────────────────────────────────

const SearchRoot = styled(Box)({
  display: 'flex',
  flexDirection: 'column',
  gap: 12,
  marginBottom: 20,
});

const FilterRow = styled(Box)({
  display: 'flex',
  alignItems: 'center',
  gap: 8,
  flexWrap: 'wrap',
});

const StyledTextField = styled(TextField)({
  flex: 1,
  minWidth: 220,
  '& .MuiOutlinedInput-root': {
    backgroundColor: `${cyberColors.dark.steel}20`,
    borderRadius: 8,
    '& fieldset': { borderColor: `${cyberColors.dark.steel}60` },
    '&:hover fieldset': { borderColor: `${cyberColors.neon.cyan}40` },
    '&.Mui-focused fieldset': { borderColor: cyberColors.neon.cyan },
    '& input': {
      color: cyberColors.text.primary,
      fontSize: '0.88rem',
      fontFamily: designTokens.typography.fontFamily.mono,
      padding: '8px 12px',
    },
  },
});

const FilterChipButton = styled(Button)<{ active?: string }>(({ active }) => ({
  height: 32,
  fontSize: '0.75rem',
  fontWeight: 600,
  textTransform: 'none',
  borderRadius: 16,
  padding: '0 12px',
  border: `1px solid ${active === 'true' ? cyberColors.neon.cyan : `${cyberColors.dark.steel}60`}`,
  color: active === 'true' ? cyberColors.neon.cyan : cyberColors.text.secondary,
  backgroundColor: active === 'true' ? `${cyberColors.neon.cyan}15` : 'transparent',
  '&:hover': {
    backgroundColor: `${cyberColors.neon.cyan}10`,
    borderColor: `${cyberColors.neon.cyan}60`,
  },
}));

const SavedSearchChip = styled(Chip)({
  height: 28,
  fontSize: '0.75rem',
  backgroundColor: `${cyberColors.neon.purple}15`,
  color: cyberColors.neon.purple,
  border: `1px solid ${cyberColors.neon.purple}35`,
  cursor: 'pointer',
  '&:hover': {
    backgroundColor: `${cyberColors.neon.purple}25`,
  },
  '& .MuiChip-deleteIcon': {
    color: `${cyberColors.neon.purple}80`,
    '&:hover': { color: cyberColors.neon.red },
  },
});

const SaveModal = styled(Dialog)({
  '& .MuiDialog-paper': {
    backgroundColor: cyberColors.dark.void,
    border: `1px solid ${cyberColors.dark.steel}`,
    borderRadius: 12,
    minWidth: 360,
  },
});

// ─── Types ────────────────────────────────────────────────────────────────────

export interface SearchBarProps {
  params: SearchParams;
  onChange: (params: SearchParams) => void;
  savedSearches: SavedSearch[];
  onSaveSearch: (name: string, description: string, params: SearchParams) => Promise<void>;
  onDeleteSearch: (id: string) => Promise<void>;
  onSelectSavedSearch: (params: SearchParams) => void;
  saving?: boolean;
}

// ─── Filter dropdown ──────────────────────────────────────────────────────────

interface FilterDropdownProps {
  label: string;
  value: string | undefined;
  options: { value: string; label: string }[];
  onSelect: (value: string | undefined) => void;
}

function FilterDropdown({ label, value, options, onSelect }: FilterDropdownProps) {
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const open = Boolean(anchorEl);

  return (
    <>
      <FilterChipButton
        active={value ? 'true' : 'false'}
        onClick={(e) => setAnchorEl(e.currentTarget)}
        endIcon={open ? <ExpandLessIcon sx={{ fontSize: '0.9rem !important' }} /> : <ExpandMoreIcon sx={{ fontSize: '0.9rem !important' }} />}
        startIcon={<FilterListIcon sx={{ fontSize: '0.85rem !important' }} />}
      >
        {value ? options.find((o) => o.value === value)?.label || label : label}
      </FilterChipButton>
      <Menu
        anchorEl={anchorEl}
        open={open}
        onClose={() => setAnchorEl(null)}
        PaperProps={{
          sx: {
            backgroundColor: cyberColors.dark.void,
            border: `1px solid ${cyberColors.dark.steel}`,
            borderRadius: 2,
            minWidth: 160,
          },
        }}
      >
        {value && (
          <>
            <MenuItem
              onClick={() => { onSelect(undefined); setAnchorEl(null); }}
              sx={{ fontSize: '0.8rem', color: cyberColors.text.muted, fontStyle: 'italic' }}
            >
              Clear filter
            </MenuItem>
            <Divider sx={{ borderColor: `${cyberColors.dark.steel}60` }} />
          </>
        )}
        {options.map((opt) => (
          <MenuItem
            key={opt.value}
            onClick={() => { onSelect(opt.value); setAnchorEl(null); }}
            selected={value === opt.value}
            sx={{
              fontSize: '0.82rem',
              color: value === opt.value ? cyberColors.neon.cyan : cyberColors.text.primary,
              backgroundColor: value === opt.value ? `${cyberColors.neon.cyan}10` : 'transparent',
              '&:hover': { backgroundColor: `${cyberColors.neon.cyan}08` },
            }}
          >
            {opt.label}
          </MenuItem>
        ))}
      </Menu>
    </>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export const SearchBar: React.FC<SearchBarProps> = ({
  params,
  onChange,
  savedSearches,
  onSaveSearch,
  onDeleteSearch,
  onSelectSavedSearch,
  saving = false,
}) => {
  const [saveModalOpen, setSaveModalOpen] = useState(false);
  const [saveName, setSaveName] = useState('');
  const [saveDesc, setSaveDesc] = useState('');
  const [saveError, setSaveError] = useState('');
  const [showSaved, setShowSaved] = useState(false);
  const nameRef = useRef<HTMLInputElement>(null);

  const hasActiveFilters = Boolean(
    params.q || params.status || params.priority || params.risk_level,
  );

  const handleClear = useCallback(() => {
    onChange({});
  }, [onChange]);

  const handleQ = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => onChange({ ...params, q: e.target.value || undefined }),
    [params, onChange],
  );

  const handleSaveSubmit = useCallback(async () => {
    if (!saveName.trim()) {
      setSaveError('Name is required');
      nameRef.current?.focus();
      return;
    }
    setSaveError('');
    try {
      await onSaveSearch(saveName.trim(), saveDesc.trim(), params);
      setSaveModalOpen(false);
      setSaveName('');
      setSaveDesc('');
      setShowSaved(true);
    } catch {
      setSaveError('Failed to save search. Please try again.');
    }
  }, [saveName, saveDesc, params, onSaveSearch]);

  return (
    <SearchRoot>
      {/* Main filter row */}
      <FilterRow>
        {/* Text search */}
        <StyledTextField
          placeholder="Search by target, type, or keyword…"
          value={params.q || ''}
          onChange={handleQ}
          size="small"
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon sx={{ fontSize: '1rem', color: cyberColors.text.muted }} />
              </InputAdornment>
            ),
            endAdornment: params.q ? (
              <InputAdornment position="end">
                <IconButton
                  size="small"
                  onClick={() => onChange({ ...params, q: undefined })}
                  sx={{ color: cyberColors.text.muted }}
                >
                  <ClearIcon sx={{ fontSize: '0.9rem' }} />
                </IconButton>
              </InputAdornment>
            ) : null,
          }}
        />

        {/* Filter dropdowns */}
        <FilterDropdown
          label="Status"
          value={params.status}
          options={STATUS_OPTIONS}
          onSelect={(v) => onChange({ ...params, status: v })}
        />
        <FilterDropdown
          label="Priority"
          value={params.priority}
          options={PRIORITY_OPTIONS}
          onSelect={(v) => onChange({ ...params, priority: v })}
        />
        <FilterDropdown
          label="Risk Level"
          value={params.risk_level}
          options={RISK_OPTIONS}
          onSelect={(v) => onChange({ ...params, risk_level: v })}
        />

        {/* Divider */}
        <Box sx={{ flex: 1 }} />

        {/* Saved searches toggle */}
        <Tooltip title={showSaved ? 'Hide saved searches' : 'Show saved searches'}>
          <Button
            size="small"
            startIcon={savedSearches.length > 0 ? <BookmarkIcon /> : <BookmarkBorderIcon />}
            endIcon={showSaved ? <ExpandLessIcon /> : <ExpandMoreIcon />}
            onClick={() => setShowSaved((s) => !s)}
            sx={{
              height: 32,
              fontSize: '0.75rem',
              fontWeight: 600,
              textTransform: 'none',
              color: savedSearches.length > 0 ? cyberColors.neon.purple : cyberColors.text.secondary,
              border: `1px solid ${savedSearches.length > 0 ? `${cyberColors.neon.purple}50` : `${cyberColors.dark.steel}60`}`,
              borderRadius: 16,
              px: 1.5,
              '&:hover': {
                backgroundColor: `${cyberColors.neon.purple}10`,
              },
            }}
          >
            Saved ({savedSearches.length})
          </Button>
        </Tooltip>

        {/* Save current search */}
        <Tooltip title={hasActiveFilters ? 'Save this search' : 'Add filters to save a search'}>
          <span>
            <Button
              size="small"
              startIcon={<BookmarkAddIcon />}
              disabled={!hasActiveFilters || saving}
              onClick={() => setSaveModalOpen(true)}
              sx={{
                height: 32,
                fontSize: '0.75rem',
                fontWeight: 600,
                textTransform: 'none',
                color: cyberColors.neon.cyan,
                border: `1px solid ${cyberColors.neon.cyan}40`,
                borderRadius: 16,
                px: 1.5,
                '&:hover': { backgroundColor: `${cyberColors.neon.cyan}10` },
                '&.Mui-disabled': {
                  color: cyberColors.text.muted,
                  borderColor: `${cyberColors.dark.steel}40`,
                },
              }}
            >
              Save Search
            </Button>
          </span>
        </Tooltip>

        {/* Clear all */}
        {hasActiveFilters && (
          <Tooltip title="Clear all filters">
            <IconButton
              size="small"
              onClick={handleClear}
              sx={{
                color: cyberColors.text.muted,
                border: `1px solid ${cyberColors.dark.steel}60`,
                borderRadius: 8,
                p: '5px',
                '&:hover': { color: cyberColors.neon.red, borderColor: `${cyberColors.neon.red}50` },
              }}
            >
              <ClearIcon sx={{ fontSize: '0.9rem' }} />
            </IconButton>
          </Tooltip>
        )}
      </FilterRow>

      {/* Active filter tags */}
      {hasActiveFilters && (
        <FilterRow>
          <Typography sx={{ fontSize: '0.72rem', color: cyberColors.text.muted, mr: 0.5 }}>
            Filters:
          </Typography>
          {params.status && (
            <Chip
              label={`Status: ${STATUS_OPTIONS.find((o) => o.value === params.status)?.label}`}
              size="small"
              onDelete={() => onChange({ ...params, status: undefined })}
              sx={{
                height: 22, fontSize: '0.7rem',
                backgroundColor: `${cyberColors.neon.cyan}15`,
                color: cyberColors.neon.cyan,
                border: `1px solid ${cyberColors.neon.cyan}30`,
                '& .MuiChip-deleteIcon': { color: `${cyberColors.neon.cyan}70`, fontSize: '0.85rem' },
              }}
            />
          )}
          {params.priority && (
            <Chip
              label={`Priority: ${PRIORITY_OPTIONS.find((o) => o.value === params.priority)?.label}`}
              size="small"
              onDelete={() => onChange({ ...params, priority: undefined })}
              sx={{
                height: 22, fontSize: '0.7rem',
                backgroundColor: `${cyberColors.neon.orange}15`,
                color: cyberColors.neon.orange,
                border: `1px solid ${cyberColors.neon.orange}30`,
                '& .MuiChip-deleteIcon': { color: `${cyberColors.neon.orange}70`, fontSize: '0.85rem' },
              }}
            />
          )}
          {params.risk_level && (
            <Chip
              label={`Risk: ${RISK_OPTIONS.find((o) => o.value === params.risk_level)?.label}`}
              size="small"
              onDelete={() => onChange({ ...params, risk_level: undefined })}
              sx={{
                height: 22, fontSize: '0.7rem',
                backgroundColor: `${cyberColors.neon.red}15`,
                color: cyberColors.neon.red,
                border: `1px solid ${cyberColors.neon.red}30`,
                '& .MuiChip-deleteIcon': { color: `${cyberColors.neon.red}70`, fontSize: '0.85rem' },
              }}
            />
          )}
        </FilterRow>
      )}

      {/* Saved searches panel */}
      <Collapse in={showSaved}>
        <Box
          sx={{
            backgroundColor: `${cyberColors.dark.steel}10`,
            border: `1px solid ${cyberColors.dark.steel}40`,
            borderRadius: 2,
            p: 1.5,
          }}
        >
          {savedSearches.length === 0 ? (
            <Typography sx={{ fontSize: '0.78rem', color: cyberColors.text.muted, fontStyle: 'italic' }}>
              No saved searches yet. Apply filters and click "Save Search" to create one.
            </Typography>
          ) : (
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, alignItems: 'center' }}>
              <Typography sx={{ fontSize: '0.72rem', color: cyberColors.text.muted, mr: 0.5 }}>
                Saved:
              </Typography>
              {savedSearches.map((s) => (
                <SavedSearchChip
                  key={s.id}
                  icon={<BookmarkIcon sx={{ fontSize: '0.8rem !important' }} />}
                  label={s.name}
                  onClick={() => {
                    onSelectSavedSearch(s.query_params);
                    setShowSaved(false);
                  }}
                  onDelete={() => onDeleteSearch(s.id)}
                  deleteIcon={
                    <Tooltip title={`Delete "${s.name}"`}>
                      <DeleteOutlineIcon />
                    </Tooltip>
                  }
                  title={s.description || s.name}
                />
              ))}
            </Box>
          )}
        </Box>
      </Collapse>

      {/* Save search modal */}
      <SaveModal open={saveModalOpen} onClose={() => { setSaveModalOpen(false); setSaveError(''); }}>
        <DialogTitle
          sx={{
            fontFamily: designTokens.typography.fontFamily.display,
            fontSize: '1rem',
            color: cyberColors.text.primary,
            borderBottom: `1px solid ${cyberColors.dark.steel}60`,
            pb: 1.5,
          }}
        >
          Save Search
        </DialogTitle>
        <DialogContent sx={{ pt: '16px !important', display: 'flex', flexDirection: 'column', gap: 2 }}>
          <TextField
            inputRef={nameRef}
            label="Name"
            value={saveName}
            onChange={(e) => { setSaveName(e.target.value); setSaveError(''); }}
            error={!!saveError}
            helperText={saveError}
            size="small"
            autoFocus
            fullWidth
            placeholder="e.g. APT C2 Domains"
            sx={{
              '& .MuiOutlinedInput-root': {
                '& fieldset': { borderColor: `${cyberColors.dark.steel}80` },
                '&:hover fieldset': { borderColor: cyberColors.neon.cyan },
                '&.Mui-focused fieldset': { borderColor: cyberColors.neon.cyan },
                color: cyberColors.text.primary,
              },
              '& .MuiInputLabel-root': { color: cyberColors.text.secondary },
              '& .MuiInputLabel-root.Mui-focused': { color: cyberColors.neon.cyan },
            }}
          />
          <TextField
            label="Description (optional)"
            value={saveDesc}
            onChange={(e) => setSaveDesc(e.target.value)}
            size="small"
            fullWidth
            multiline
            rows={2}
            placeholder="What does this search track?"
            sx={{
              '& .MuiOutlinedInput-root': {
                '& fieldset': { borderColor: `${cyberColors.dark.steel}80` },
                '&:hover fieldset': { borderColor: cyberColors.neon.cyan },
                '&.Mui-focused fieldset': { borderColor: cyberColors.neon.cyan },
                color: cyberColors.text.primary,
              },
              '& .MuiInputLabel-root': { color: cyberColors.text.secondary },
              '& .MuiInputLabel-root.Mui-focused': { color: cyberColors.neon.cyan },
            }}
          />

          {/* Filter summary */}
          <Box sx={{ backgroundColor: `${cyberColors.dark.steel}15`, borderRadius: 1, p: 1 }}>
            <Typography sx={{ fontSize: '0.7rem', color: cyberColors.text.muted, mb: 0.5 }}>
              Current filters:
            </Typography>
            {params.q && (
              <Typography sx={{ fontSize: '0.75rem', color: cyberColors.text.secondary }}>
                Query: <span style={{ color: cyberColors.neon.cyan }}>"{params.q}"</span>
              </Typography>
            )}
            {params.status && (
              <Typography sx={{ fontSize: '0.75rem', color: cyberColors.text.secondary }}>
                Status: <span style={{ color: cyberColors.neon.cyan }}>{params.status}</span>
              </Typography>
            )}
            {params.priority && (
              <Typography sx={{ fontSize: '0.75rem', color: cyberColors.text.secondary }}>
                Priority: <span style={{ color: cyberColors.neon.cyan }}>{params.priority}</span>
              </Typography>
            )}
            {params.risk_level && (
              <Typography sx={{ fontSize: '0.75rem', color: cyberColors.text.secondary }}>
                Risk: <span style={{ color: cyberColors.neon.cyan }}>{params.risk_level}</span>
              </Typography>
            )}
          </Box>
        </DialogContent>
        <DialogActions sx={{ borderTop: `1px solid ${cyberColors.dark.steel}60`, px: 3, py: 1.5, gap: 1 }}>
          <Button
            onClick={() => { setSaveModalOpen(false); setSaveError(''); }}
            sx={{ color: cyberColors.text.secondary, textTransform: 'none' }}
          >
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={handleSaveSubmit}
            disabled={saving || !saveName.trim()}
            sx={{
              backgroundColor: cyberColors.neon.cyan,
              color: cyberColors.dark.void,
              fontWeight: 600,
              textTransform: 'none',
              '&:hover': { backgroundColor: cyberColors.neon.electricBlue },
              '&.Mui-disabled': { backgroundColor: `${cyberColors.neon.cyan}40` },
            }}
          >
            {saving ? 'Saving…' : 'Save Search'}
          </Button>
        </DialogActions>
      </SaveModal>
    </SearchRoot>
  );
};

export default SearchBar;
