/**
 * DataTable Component
 *
 * Enhanced data table with sorting, filtering, pagination, and export capabilities.
 */

import React, { useState, useMemo, useCallback } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  InputAdornment,
  IconButton,
  Tooltip,
  Chip,
  Menu,
  MenuItem,
  Checkbox,
  FormControlLabel,
  useTheme,
} from '@mui/material';
import {
  DataGrid,
  GridColDef,
  GridRowParams,
  GridSortModel,
  GridFilterModel,
  GridToolbarContainer,
  GridToolbarColumnsButton,
  GridToolbarFilterButton,
  GridToolbarDensitySelector,
  GridToolbarExport,
  GridPaginationModel,
  GridRowSelectionModel,
} from '@mui/x-data-grid';
import SearchIcon from '@mui/icons-material/Search';
import DownloadIcon from '@mui/icons-material/Download';
import FilterListIcon from '@mui/icons-material/FilterList';
import ViewColumnIcon from '@mui/icons-material/ViewColumn';

export interface DataTableColumn {
  field: string;
  headerName: string;
  width?: number;
  minWidth?: number;
  flex?: number;
  type?: 'string' | 'number' | 'date' | 'boolean' | 'actions';
  sortable?: boolean;
  filterable?: boolean;
  hideable?: boolean;
  renderCell?: (params: any) => React.ReactNode;
  valueFormatter?: (params: any) => string;
  align?: 'left' | 'center' | 'right';
}

export interface DataTableProps<T extends { id: string | number }> {
  /** Table data rows */
  rows: T[];
  /** Column definitions */
  columns: DataTableColumn[];
  /** Table title */
  title?: string;
  /** Enable row selection */
  selectable?: boolean;
  /** Enable multi-row selection */
  multiSelect?: boolean;
  /** Selected row IDs */
  selectedIds?: (string | number)[];
  /** Selection change handler */
  onSelectionChange?: (ids: (string | number)[]) => void;
  /** Row click handler */
  onRowClick?: (row: T) => void;
  /** Enable pagination */
  paginated?: boolean;
  /** Page size options */
  pageSizeOptions?: number[];
  /** Default page size */
  defaultPageSize?: number;
  /** Enable search */
  searchable?: boolean;
  /** Search placeholder */
  searchPlaceholder?: string;
  /** Enable column visibility toggle */
  columnToggle?: boolean;
  /** Enable export */
  exportable?: boolean;
  /** Export filename */
  exportFilename?: string;
  /** Loading state */
  loading?: boolean;
  /** Auto height (fit content) */
  autoHeight?: boolean;
  /** Fixed height */
  height?: number;
  /** Dense mode */
  dense?: boolean;
  /** Show toolbar */
  showToolbar?: boolean;
  /** Custom toolbar actions */
  toolbarActions?: React.ReactNode;
  /** No rows message */
  noRowsMessage?: string;
  /** Test ID for testing */
  testId?: string;
}

function CustomToolbar({
  title,
  searchValue,
  onSearchChange,
  searchable,
  searchPlaceholder,
  toolbarActions,
}: {
  title?: string;
  searchValue: string;
  onSearchChange: (value: string) => void;
  searchable: boolean;
  searchPlaceholder: string;
  toolbarActions?: React.ReactNode;
}) {
  return (
    <GridToolbarContainer sx={{ p: 1.5, gap: 2, flexWrap: 'wrap' }}>
      {title && (
        <Typography variant="h6" sx={{ flex: '1 1 auto' }}>
          {title}
        </Typography>
      )}

      {searchable && (
        <TextField
          size="small"
          placeholder={searchPlaceholder}
          value={searchValue}
          onChange={(e) => onSearchChange(e.target.value)}
          sx={{ width: 250 }}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon fontSize="small" color="action" />
              </InputAdornment>
            ),
          }}
        />
      )}

      <Box sx={{ display: 'flex', gap: 1 }}>
        <GridToolbarColumnsButton />
        <GridToolbarFilterButton />
        <GridToolbarDensitySelector />
        <GridToolbarExport />
        {toolbarActions}
      </Box>
    </GridToolbarContainer>
  );
}

export function DataTable<T extends { id: string | number }>({
  rows,
  columns,
  title,
  selectable = false,
  multiSelect = true,
  selectedIds = [],
  onSelectionChange,
  onRowClick,
  paginated = true,
  pageSizeOptions = [10, 25, 50, 100],
  defaultPageSize = 25,
  searchable = true,
  searchPlaceholder = 'Search...',
  columnToggle = true,
  exportable = true,
  exportFilename = 'data-export',
  loading = false,
  autoHeight = false,
  height = 500,
  dense = false,
  showToolbar = true,
  toolbarActions,
  noRowsMessage = 'No data available',
  testId,
}: DataTableProps<T>) {
  const theme = useTheme();
  const [searchValue, setSearchValue] = useState('');
  const [paginationModel, setPaginationModel] = useState<GridPaginationModel>({
    page: 0,
    pageSize: defaultPageSize,
  });
  const [sortModel, setSortModel] = useState<GridSortModel>([]);
  const [filterModel, setFilterModel] = useState<GridFilterModel>({ items: [] });
  const [selectionModel, setSelectionModel] = useState<GridRowSelectionModel>(selectedIds);

  // Convert columns to DataGrid format
  const gridColumns: GridColDef[] = useMemo(
    () =>
      columns.map((col) => ({
        field: col.field,
        headerName: col.headerName,
        width: col.width,
        minWidth: col.minWidth || 100,
        flex: col.flex,
        type: col.type === 'actions' ? 'actions' : col.type,
        sortable: col.sortable !== false,
        filterable: col.filterable !== false,
        hideable: col.hideable !== false,
        renderCell: col.renderCell,
        valueFormatter: col.valueFormatter,
        align: col.align,
        headerAlign: col.align,
      })),
    [columns]
  );

  // Filter rows based on search
  const filteredRows = useMemo(() => {
    if (!searchValue.trim()) return rows;

    const searchLower = searchValue.toLowerCase();
    return rows.filter((row) =>
      Object.values(row).some((value) =>
        String(value).toLowerCase().includes(searchLower)
      )
    );
  }, [rows, searchValue]);

  const handleRowClick = useCallback(
    (params: GridRowParams) => {
      if (onRowClick) {
        onRowClick(params.row as T);
      }
    },
    [onRowClick]
  );

  const handleSelectionChange = useCallback(
    (newSelection: GridRowSelectionModel) => {
      setSelectionModel(newSelection);
      onSelectionChange?.(newSelection as (string | number)[]);
    },
    [onSelectionChange]
  );

  return (
    <Box data-testid={testId} sx={{ width: '100%' }}>
      <Paper
        elevation={1}
        sx={{
          height: autoHeight ? 'auto' : height,
          width: '100%',
        }}
      >
        <DataGrid
          rows={filteredRows}
          columns={gridColumns}
          loading={loading}
          autoHeight={autoHeight}
          density={dense ? 'compact' : 'standard'}
          // Pagination
          pagination={paginated ? true : undefined}
          paginationModel={paginationModel}
          onPaginationModelChange={setPaginationModel}
          pageSizeOptions={pageSizeOptions}
          // Sorting
          sortModel={sortModel}
          onSortModelChange={setSortModel}
          // Filtering
          filterModel={filterModel}
          onFilterModelChange={setFilterModel}
          // Selection
          checkboxSelection={selectable && multiSelect}
          rowSelectionModel={selectionModel}
          onRowSelectionModelChange={handleSelectionChange}
          disableRowSelectionOnClick={!multiSelect}
          // Row click
          onRowClick={handleRowClick}
          // Toolbar
          slots={{
            toolbar: showToolbar ? CustomToolbar : undefined,
            noRowsOverlay: () => (
              <Box
                sx={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  height: '100%',
                }}
              >
                <Typography color="text.secondary">{noRowsMessage}</Typography>
              </Box>
            ),
          }}
          slotProps={{
            toolbar: {
              title,
              searchValue,
              onSearchChange: setSearchValue,
              searchable,
              searchPlaceholder,
              toolbarActions,
            },
          }}
          // Styling
          sx={{
            border: 'none',
            '& .MuiDataGrid-cell': {
              borderBottom: `1px solid ${theme.palette.divider}`,
            },
            '& .MuiDataGrid-columnHeaders': {
              bgcolor: theme.palette.mode === 'dark' ? 'grey.900' : 'grey.100',
              borderBottom: `2px solid ${theme.palette.divider}`,
            },
            '& .MuiDataGrid-row': {
              '&:hover': {
                bgcolor: theme.palette.action.hover,
              },
              '&.Mui-selected': {
                bgcolor: theme.palette.action.selected,
                '&:hover': {
                  bgcolor: theme.palette.action.selected,
                },
              },
            },
            '& .MuiDataGrid-footerContainer': {
              borderTop: `2px solid ${theme.palette.divider}`,
            },
          }}
          // Localization
          localeText={{
            noRowsLabel: noRowsMessage,
            toolbarColumns: 'Columns',
            toolbarFilters: 'Filters',
            toolbarDensity: 'Density',
            toolbarExport: 'Export',
          }}
          // Export
          {...(exportable && {
            csvOptions: { fileName: exportFilename },
            printOptions: { fileName: exportFilename },
          })}
        />
      </Paper>
    </Box>
  );
}

export default DataTable;
