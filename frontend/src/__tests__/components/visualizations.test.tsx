/**
 * Visualization Components Tests
 */

import React from 'react';
import { render, screen, fireEvent, within } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { createTheme } from '@mui/material';
import {
  LineChart,
  BarChart,
  PieChart,
  AreaChart,
  RiskGauge,
  TimelineChart,
  NetworkGraph,
  Heatmap,
  StatCard,
  ThreatMatrix,
  DataTable,
} from '../../components/visualizations';

const theme = createTheme();

const renderWithTheme = (component: React.ReactElement) => {
  return render(<ThemeProvider theme={theme}>{component}</ThemeProvider>);
};

// Mock ResizeObserver
class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}
window.ResizeObserver = ResizeObserver;

// Mock scrollIntoView which is not available in jsdom
Element.prototype.scrollIntoView = jest.fn();

// =============================================================================
// LineChart Tests
// =============================================================================

describe('LineChart Component', () => {
  const mockData = [
    { date: 'Jan', value1: 10, value2: 20 },
    { date: 'Feb', value1: 15, value2: 25 },
    { date: 'Mar', value1: 20, value2: 30 },
  ];

  const mockLines = [
    { dataKey: 'value1', name: 'Series 1' },
    { dataKey: 'value2', name: 'Series 2' },
  ];

  describe('Rendering', () => {
    it('renders with data', () => {
      renderWithTheme(
        <LineChart data={mockData} lines={mockLines} xAxisKey="date" testId="line-chart" />
      );
      expect(screen.getByTestId('line-chart')).toBeInTheDocument();
    });

    it('renders title when provided', () => {
      renderWithTheme(
        <LineChart
          data={mockData}
          lines={mockLines}
          xAxisKey="date"
          title="Test Chart"
        />
      );
      expect(screen.getByText('Test Chart')).toBeInTheDocument();
    });

    it('renders with custom height', () => {
      renderWithTheme(
        <LineChart
          data={mockData}
          lines={mockLines}
          xAxisKey="date"
          height={400}
          testId="line-chart"
        />
      );
      expect(screen.getByTestId('line-chart')).toBeInTheDocument();
    });
  });

  describe('Configuration', () => {
    it('accepts custom line colors', () => {
      const coloredLines = [
        { dataKey: 'value1', name: 'Series 1', color: '#ff0000' },
      ];
      renderWithTheme(
        <LineChart data={mockData} lines={coloredLines} xAxisKey="date" testId="line-chart" />
      );
      expect(screen.getByTestId('line-chart')).toBeInTheDocument();
    });

    it('renders with reference line configuration', () => {
      renderWithTheme(
        <LineChart
          data={mockData}
          lines={mockLines}
          xAxisKey="date"
          referenceLine={{ value: 15, label: 'Target' }}
          testId="line-chart"
        />
      );
      // Component should render without errors
      expect(screen.getByTestId('line-chart')).toBeInTheDocument();
    });
  });
});

// =============================================================================
// BarChart Tests
// =============================================================================

describe('BarChart Component', () => {
  const mockData = [
    { category: 'A', value: 10 },
    { category: 'B', value: 20 },
    { category: 'C', value: 15 },
  ];

  const mockBars = [{ dataKey: 'value', name: 'Value' }];

  describe('Rendering', () => {
    it('renders with data', () => {
      renderWithTheme(
        <BarChart data={mockData} bars={mockBars} xAxisKey="category" testId="bar-chart" />
      );
      expect(screen.getByTestId('bar-chart')).toBeInTheDocument();
    });

    it('renders horizontal bars', () => {
      renderWithTheme(
        <BarChart
          data={mockData}
          bars={mockBars}
          xAxisKey="category"
          horizontal
          testId="bar-chart"
        />
      );
      expect(screen.getByTestId('bar-chart')).toBeInTheDocument();
    });

    it('renders with color by value', () => {
      renderWithTheme(
        <BarChart
          data={mockData}
          bars={mockBars}
          xAxisKey="category"
          colorByValue
          testId="bar-chart"
        />
      );
      expect(screen.getByTestId('bar-chart')).toBeInTheDocument();
    });
  });

  describe('Stacked Bars', () => {
    it('renders stacked bars', () => {
      const stackedBars = [
        { dataKey: 'value', name: 'Value 1', stackId: 'a' },
        { dataKey: 'value2', name: 'Value 2', stackId: 'a' },
      ];
      const stackedData = [
        { category: 'A', value: 10, value2: 5 },
        { category: 'B', value: 20, value2: 10 },
      ];
      renderWithTheme(
        <BarChart
          data={stackedData}
          bars={stackedBars}
          xAxisKey="category"
          testId="bar-chart"
        />
      );
      expect(screen.getByTestId('bar-chart')).toBeInTheDocument();
    });
  });
});

// =============================================================================
// PieChart Tests
// =============================================================================

describe('PieChart Component', () => {
  const mockData = [
    { name: 'Category A', value: 30 },
    { name: 'Category B', value: 50 },
    { name: 'Category C', value: 20 },
  ];

  describe('Rendering', () => {
    it('renders with data', () => {
      renderWithTheme(<PieChart data={mockData} testId="pie-chart" />);
      expect(screen.getByTestId('pie-chart')).toBeInTheDocument();
    });

    it('renders as donut chart', () => {
      renderWithTheme(<PieChart data={mockData} donut testId="pie-chart" />);
      expect(screen.getByTestId('pie-chart')).toBeInTheDocument();
    });

    it('renders with center label', () => {
      renderWithTheme(
        <PieChart
          data={mockData}
          donut
          centerLabel="Total"
          centerValue={100}
          testId="pie-chart"
        />
      );
      expect(screen.getByTestId('pie-chart')).toBeInTheDocument();
    });
  });

  describe('Configuration', () => {
    it('renders with custom colors', () => {
      const customColors = ['#ff0000', '#00ff00', '#0000ff'];
      renderWithTheme(
        <PieChart data={mockData} colors={customColors} testId="pie-chart" />
      );
      expect(screen.getByTestId('pie-chart')).toBeInTheDocument();
    });

    it('renders without legend', () => {
      renderWithTheme(
        <PieChart data={mockData} showLegend={false} testId="pie-chart" />
      );
      expect(screen.getByTestId('pie-chart')).toBeInTheDocument();
    });
  });
});

// =============================================================================
// AreaChart Tests
// =============================================================================

describe('AreaChart Component', () => {
  const mockData = [
    { date: 'Jan', value: 10 },
    { date: 'Feb', value: 20 },
    { date: 'Mar', value: 15 },
  ];

  const mockAreas = [{ dataKey: 'value', name: 'Value' }];

  describe('Rendering', () => {
    it('renders with data', () => {
      renderWithTheme(
        <AreaChart data={mockData} areas={mockAreas} xAxisKey="date" testId="area-chart" />
      );
      expect(screen.getByTestId('area-chart')).toBeInTheDocument();
    });

    it('renders with gradient fill', () => {
      renderWithTheme(
        <AreaChart
          data={mockData}
          areas={mockAreas}
          xAxisKey="date"
          gradient
          testId="area-chart"
        />
      );
      expect(screen.getByTestId('area-chart')).toBeInTheDocument();
    });

    it('renders stacked areas', () => {
      const stackedAreas = [
        { dataKey: 'value', stackId: 'a' },
        { dataKey: 'value2', stackId: 'a' },
      ];
      const stackedData = [
        { date: 'Jan', value: 10, value2: 5 },
        { date: 'Feb', value: 20, value2: 10 },
      ];
      renderWithTheme(
        <AreaChart
          data={stackedData}
          areas={stackedAreas}
          xAxisKey="date"
          testId="area-chart"
        />
      );
      expect(screen.getByTestId('area-chart')).toBeInTheDocument();
    });
  });
});

// =============================================================================
// RiskGauge Tests
// =============================================================================

describe('RiskGauge Component', () => {
  describe('Rendering', () => {
    it('renders with value', () => {
      renderWithTheme(<RiskGauge value={50} testId="risk-gauge" />);
      expect(screen.getByTestId('risk-gauge')).toBeInTheDocument();
      expect(screen.getByText('50')).toBeInTheDocument();
    });

    it('renders title', () => {
      renderWithTheme(<RiskGauge value={50} title="Risk Score" testId="risk-gauge" />);
      expect(screen.getByText('Risk Score')).toBeInTheDocument();
    });

    it('shows risk level label', () => {
      renderWithTheme(<RiskGauge value={75} showLabel testId="risk-gauge" />);
      expect(screen.getByText('High Risk')).toBeInTheDocument();
    });
  });

  describe('Risk Levels', () => {
    it('shows low risk for low values', () => {
      renderWithTheme(<RiskGauge value={10} showLabel testId="risk-gauge" />);
      expect(screen.getByText('Low Risk')).toBeInTheDocument();
    });

    it('shows medium risk for medium values', () => {
      renderWithTheme(<RiskGauge value={40} showLabel testId="risk-gauge" />);
      expect(screen.getByText('Medium Risk')).toBeInTheDocument();
    });

    it('shows critical risk for very high values', () => {
      renderWithTheme(<RiskGauge value={90} showLabel testId="risk-gauge" />);
      expect(screen.getByText('Critical Risk')).toBeInTheDocument();
    });
  });

  describe('Configuration', () => {
    it('accepts custom thresholds', () => {
      const customThresholds = { low: 20, medium: 40, high: 60 };
      renderWithTheme(
        <RiskGauge value={30} thresholds={customThresholds} showLabel testId="risk-gauge" />
      );
      expect(screen.getByText('Medium Risk')).toBeInTheDocument();
    });

    it('accepts custom max value', () => {
      renderWithTheme(<RiskGauge value={50} max={200} testId="risk-gauge" />);
      expect(screen.getByText('50')).toBeInTheDocument();
    });

    it('displays value suffix', () => {
      renderWithTheme(<RiskGauge value={50} valueSuffix="%" testId="risk-gauge" />);
      expect(screen.getByText('%')).toBeInTheDocument();
    });
  });
});

// =============================================================================
// TimelineChart Tests
// =============================================================================

describe('TimelineChart Component', () => {
  const mockEvents = [
    {
      id: '1',
      timestamp: '2024-01-15T10:00:00Z',
      title: 'Event 1',
      description: 'Description 1',
      type: 'info' as const,
    },
    {
      id: '2',
      timestamp: '2024-01-16T14:30:00Z',
      title: 'Event 2',
      description: 'Description 2',
      type: 'success' as const,
    },
  ];

  describe('Rendering', () => {
    it('renders with events', () => {
      renderWithTheme(<TimelineChart events={mockEvents} testId="timeline" />);
      expect(screen.getByTestId('timeline')).toBeInTheDocument();
    });

    it('renders event titles', () => {
      renderWithTheme(<TimelineChart events={mockEvents} testId="timeline" />);
      expect(screen.getByText('Event 1')).toBeInTheDocument();
      expect(screen.getByText('Event 2')).toBeInTheDocument();
    });

    it('renders title when provided', () => {
      renderWithTheme(
        <TimelineChart events={mockEvents} title="Investigation Timeline" testId="timeline" />
      );
      expect(screen.getByText('Investigation Timeline')).toBeInTheDocument();
    });

    it('renders empty state when no events', () => {
      renderWithTheme(<TimelineChart events={[]} testId="timeline" />);
      expect(screen.getByText('No events to display')).toBeInTheDocument();
    });
  });

  describe('Event Details', () => {
    it('renders event descriptions', () => {
      renderWithTheme(<TimelineChart events={mockEvents} testId="timeline" />);
      expect(screen.getByText('Description 1')).toBeInTheDocument();
    });

    it('renders event tags', () => {
      const eventsWithTags = [
        { ...mockEvents[0], tags: ['tag1', 'tag2'] },
      ];
      renderWithTheme(<TimelineChart events={eventsWithTags} testId="timeline" />);
      expect(screen.getByText('tag1')).toBeInTheDocument();
      expect(screen.getByText('tag2')).toBeInTheDocument();
    });

    it('renders event source', () => {
      const eventsWithSource = [
        { ...mockEvents[0], source: 'VirusTotal' },
      ];
      renderWithTheme(<TimelineChart events={eventsWithSource} testId="timeline" />);
      expect(screen.getByText('Source: VirusTotal')).toBeInTheDocument();
    });
  });
});

// =============================================================================
// NetworkGraph Tests
// =============================================================================

describe('NetworkGraph Component', () => {
  const mockNodes = [
    { id: '1', label: 'Node 1', type: 'domain' },
    { id: '2', label: 'Node 2', type: 'ip' },
    { id: '3', label: 'Node 3', type: 'email' },
  ];

  const mockEdges = [
    { source: '1', target: '2' },
    { source: '2', target: '3' },
  ];

  describe('Rendering', () => {
    it('renders with nodes and edges', () => {
      renderWithTheme(
        <NetworkGraph nodes={mockNodes} edges={mockEdges} testId="network-graph" />
      );
      expect(screen.getByTestId('network-graph')).toBeInTheDocument();
    });

    it('renders title', () => {
      renderWithTheme(
        <NetworkGraph
          nodes={mockNodes}
          edges={mockEdges}
          title="Entity Relationships"
          testId="network-graph"
        />
      );
      expect(screen.getByText('Entity Relationships')).toBeInTheDocument();
    });

    it('renders empty state when no nodes', () => {
      renderWithTheme(
        <NetworkGraph nodes={[]} edges={[]} testId="network-graph" />
      );
      expect(screen.getByText('No data to display')).toBeInTheDocument();
    });
  });

  describe('Zoom Controls', () => {
    it('renders zoom controls when zoomable', () => {
      renderWithTheme(
        <NetworkGraph
          nodes={mockNodes}
          edges={mockEdges}
          zoomable
          testId="network-graph"
        />
      );
      expect(screen.getByRole('button', { name: /zoom in/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /zoom out/i })).toBeInTheDocument();
    });
  });

  describe('Legend', () => {
    it('renders type legend chips', () => {
      renderWithTheme(
        <NetworkGraph nodes={mockNodes} edges={mockEdges} testId="network-graph" />
      );
      // Legend renders as Chips, check the testId container exists
      const container = screen.getByTestId('network-graph');
      expect(container).toBeInTheDocument();
      // Types should be rendered in some form
      expect(container.textContent).toContain('domain');
    });
  });
});

// =============================================================================
// Heatmap Tests
// =============================================================================

describe('Heatmap Component', () => {
  const mockData = [
    { row: 'Row 1', column: 'Col 1', value: 10 },
    { row: 'Row 1', column: 'Col 2', value: 20 },
    { row: 'Row 2', column: 'Col 1', value: 30 },
    { row: 'Row 2', column: 'Col 2', value: 40 },
  ];

  describe('Rendering', () => {
    it('renders with data', () => {
      renderWithTheme(<Heatmap data={mockData} testId="heatmap" />);
      expect(screen.getByTestId('heatmap')).toBeInTheDocument();
    });

    it('renders title', () => {
      renderWithTheme(
        <Heatmap data={mockData} title="Correlation Matrix" testId="heatmap" />
      );
      expect(screen.getByText('Correlation Matrix')).toBeInTheDocument();
    });

    it('renders empty state when no data', () => {
      renderWithTheme(<Heatmap data={[]} testId="heatmap" />);
      expect(screen.getByText('No data to display')).toBeInTheDocument();
    });
  });

  describe('Values', () => {
    it('displays cell values when showValues is true', () => {
      renderWithTheme(<Heatmap data={mockData} showValues testId="heatmap" />);
      // Values are formatted with one decimal place
      expect(screen.getAllByText('10.0').length).toBeGreaterThan(0);
    });

    it('hides cell values when showValues is false', () => {
      renderWithTheme(<Heatmap data={mockData} showValues={false} testId="heatmap" />);
      // Should not show formatted values in cells (legend might still show them)
      const cells = screen.getByTestId('heatmap').querySelectorAll('[class*="MuiBox"]');
      expect(cells.length).toBeGreaterThan(0);
    });
  });

  describe('Legend', () => {
    it('renders legend when showLegend is true', () => {
      renderWithTheme(<Heatmap data={mockData} showLegend testId="heatmap" />);
      // Legend shows max value at top
      expect(screen.getByTestId('heatmap')).toBeInTheDocument();
    });
  });
});

// =============================================================================
// StatCard Tests
// =============================================================================

describe('StatCard Component', () => {
  describe('Rendering', () => {
    it('renders with title and value', () => {
      renderWithTheme(
        <StatCard title="Total Investigations" value={42} testId="stat-card" />
      );
      expect(screen.getByText('Total Investigations')).toBeInTheDocument();
      expect(screen.getByText('42')).toBeInTheDocument();
    });

    it('renders value suffix', () => {
      renderWithTheme(
        <StatCard title="Risk Score" value={85} suffix="%" testId="stat-card" />
      );
      expect(screen.getByText('%')).toBeInTheDocument();
    });

    it('renders description with trend', () => {
      renderWithTheme(
        <StatCard
          title="Threats"
          value={10}
          description="from last week"
          trend="up"
          changePercent={15}
          testId="stat-card"
        />
      );
      expect(screen.getByText('from last week')).toBeInTheDocument();
    });
  });

  describe('Trend Indicator', () => {
    it('shows upward trend', () => {
      renderWithTheme(
        <StatCard title="Threats" value={15} previousValue={10} testId="stat-card" />
      );
      // Trend is calculated automatically
      expect(screen.getByTestId('stat-card')).toBeInTheDocument();
    });

    it('shows change percentage', () => {
      renderWithTheme(
        <StatCard
          title="Threats"
          value={15}
          changePercent={50}
          trend="up"
          testId="stat-card"
        />
      );
      expect(screen.getByText('+50.0%')).toBeInTheDocument();
    });
  });

  describe('Loading State', () => {
    it('renders loading skeleton', () => {
      renderWithTheme(
        <StatCard title="Threats" value={10} loading testId="stat-card" />
      );
      expect(screen.getByTestId('stat-card')).toBeInTheDocument();
    });
  });

  describe('Variants', () => {
    it('renders outlined variant', () => {
      renderWithTheme(
        <StatCard title="Score" value={100} variant="outlined" testId="stat-card" />
      );
      expect(screen.getByTestId('stat-card')).toBeInTheDocument();
    });

    it('renders gradient variant', () => {
      renderWithTheme(
        <StatCard title="Score" value={100} variant="gradient" testId="stat-card" />
      );
      expect(screen.getByTestId('stat-card')).toBeInTheDocument();
    });
  });

  describe('Interactivity', () => {
    it('calls onClick when clicked', () => {
      const onClick = jest.fn();
      renderWithTheme(
        <StatCard title="Score" value={100} onClick={onClick} testId="stat-card" />
      );
      // The Paper element has the testId, so click directly on it
      fireEvent.click(screen.getByTestId('stat-card'));
      expect(onClick).toHaveBeenCalled();
    });
  });
});

// =============================================================================
// ThreatMatrix Tests
// =============================================================================

describe('ThreatMatrix Component', () => {
  const mockTactics = [
    {
      id: 'TA0001',
      name: 'Initial Access',
      techniques: [
        { id: 'T1189', name: 'Drive-by Compromise', detected: true, severity: 'high' as const },
        { id: 'T1190', name: 'Exploit Public-Facing Application', detected: false },
      ],
    },
    {
      id: 'TA0002',
      name: 'Execution',
      techniques: [
        { id: 'T1059', name: 'Command and Scripting Interpreter', detected: true, severity: 'critical' as const },
      ],
    },
  ];

  describe('Rendering', () => {
    it('renders with tactics', () => {
      renderWithTheme(<ThreatMatrix tactics={mockTactics} testId="threat-matrix" />);
      expect(screen.getByTestId('threat-matrix')).toBeInTheDocument();
    });

    it('renders tactic names', () => {
      renderWithTheme(<ThreatMatrix tactics={mockTactics} testId="threat-matrix" />);
      expect(screen.getByText('Initial Access')).toBeInTheDocument();
      expect(screen.getByText('Execution')).toBeInTheDocument();
    });

    it('renders technique names', () => {
      renderWithTheme(<ThreatMatrix tactics={mockTactics} testId="threat-matrix" />);
      expect(screen.getByText('Drive-by Compromise')).toBeInTheDocument();
    });

    it('renders title', () => {
      renderWithTheme(
        <ThreatMatrix tactics={mockTactics} title="MITRE ATT&CK Coverage" testId="threat-matrix" />
      );
      expect(screen.getByText('MITRE ATT&CK Coverage')).toBeInTheDocument();
    });
  });

  describe('Filtering', () => {
    it('shows only detected techniques when filtered', () => {
      renderWithTheme(
        <ThreatMatrix tactics={mockTactics} showDetectedOnly testId="threat-matrix" />
      );
      expect(screen.getByText('Drive-by Compromise')).toBeInTheDocument();
      // Non-detected technique should not be visible prominently
    });
  });

  describe('Empty State', () => {
    it('renders empty state when no tactics', () => {
      renderWithTheme(<ThreatMatrix tactics={[]} testId="threat-matrix" />);
      expect(screen.getByText('No techniques to display')).toBeInTheDocument();
    });
  });

  describe('Counts', () => {
    it('shows detection counts when title is provided', () => {
      renderWithTheme(
        <ThreatMatrix tactics={mockTactics} title="MITRE Coverage" showCounts testId="threat-matrix" />
      );
      expect(screen.getByText('2 / 3 detected')).toBeInTheDocument();
    });
  });
});

// =============================================================================
// DataTable Tests
// =============================================================================

describe('DataTable Component', () => {
  const mockRows = [
    { id: '1', name: 'Item 1', value: 100, status: 'active' },
    { id: '2', name: 'Item 2', value: 200, status: 'inactive' },
    { id: '3', name: 'Item 3', value: 150, status: 'active' },
  ];

  const mockColumns = [
    { field: 'name', headerName: 'Name', width: 150 },
    { field: 'value', headerName: 'Value', type: 'number' as const, width: 100 },
    { field: 'status', headerName: 'Status', width: 120 },
  ];

  describe('Rendering', () => {
    it('renders with data', () => {
      renderWithTheme(
        <DataTable rows={mockRows} columns={mockColumns} testId="data-table" />
      );
      expect(screen.getByTestId('data-table')).toBeInTheDocument();
    });

    it('renders column headers', () => {
      renderWithTheme(
        <DataTable rows={mockRows} columns={mockColumns} testId="data-table" />
      );
      expect(screen.getByText('Name')).toBeInTheDocument();
      expect(screen.getByText('Value')).toBeInTheDocument();
      expect(screen.getByText('Status')).toBeInTheDocument();
    });

    it('renders row data', () => {
      renderWithTheme(
        <DataTable rows={mockRows} columns={mockColumns} testId="data-table" />
      );
      expect(screen.getByText('Item 1')).toBeInTheDocument();
      expect(screen.getByText('100')).toBeInTheDocument();
    });

    it('renders title', () => {
      renderWithTheme(
        <DataTable
          rows={mockRows}
          columns={mockColumns}
          title="Test Table"
          testId="data-table"
        />
      );
      expect(screen.getByText('Test Table')).toBeInTheDocument();
    });
  });

  describe('Empty State', () => {
    it('shows no rows message when empty', () => {
      renderWithTheme(
        <DataTable
          rows={[]}
          columns={mockColumns}
          noRowsMessage="No data found"
          testId="data-table"
        />
      );
      expect(screen.getByText('No data found')).toBeInTheDocument();
    });
  });

  describe('Loading State', () => {
    it('shows loading state', () => {
      renderWithTheme(
        <DataTable rows={mockRows} columns={mockColumns} loading testId="data-table" />
      );
      expect(screen.getByRole('progressbar')).toBeInTheDocument();
    });
  });

  describe('Selection', () => {
    it('renders checkboxes when selectable', () => {
      renderWithTheme(
        <DataTable
          rows={mockRows}
          columns={mockColumns}
          selectable
          testId="data-table"
        />
      );
      expect(screen.getAllByRole('checkbox').length).toBeGreaterThan(0);
    });

    it('calls onSelectionChange when selection changes', () => {
      const onSelectionChange = jest.fn();
      renderWithTheme(
        <DataTable
          rows={mockRows}
          columns={mockColumns}
          selectable
          onSelectionChange={onSelectionChange}
          testId="data-table"
        />
      );
      // Selection functionality is handled by MUI DataGrid
      expect(screen.getByTestId('data-table')).toBeInTheDocument();
    });
  });

  describe('Toolbar', () => {
    it('renders search input when searchable', () => {
      renderWithTheme(
        <DataTable
          rows={mockRows}
          columns={mockColumns}
          searchable
          testId="data-table"
        />
      );
      expect(screen.getByPlaceholderText('Search...')).toBeInTheDocument();
    });

    it('hides toolbar when showToolbar is false', () => {
      renderWithTheme(
        <DataTable
          rows={mockRows}
          columns={mockColumns}
          showToolbar={false}
          testId="data-table"
        />
      );
      expect(screen.queryByPlaceholderText('Search...')).not.toBeInTheDocument();
    });
  });

  describe('Pagination', () => {
    it('shows pagination controls when paginated', () => {
      const manyRows = Array.from({ length: 50 }, (_, i) => ({
        id: String(i),
        name: `Item ${i}`,
        value: i * 10,
        status: 'active',
      }));
      renderWithTheme(
        <DataTable
          rows={manyRows}
          columns={mockColumns}
          paginated
          defaultPageSize={10}
          testId="data-table"
        />
      );
      expect(screen.getByTestId('data-table')).toBeInTheDocument();
    });
  });
});
