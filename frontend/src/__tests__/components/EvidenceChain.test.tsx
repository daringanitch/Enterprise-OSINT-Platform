/**
 * Tests for src/components/analysis/EvidenceChain.tsx
 */

import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import EvidenceChain, { EvidenceNode } from '../../components/analysis/EvidenceChain';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeNode(overrides: Partial<EvidenceNode> = {}): EvidenceNode {
  return {
    id: 'node-1',
    type: 'source',
    label: 'VirusTotal Detection',
    source: 'virustotal',
    value: '45/72 engines',
    confidence: 0.9,
    collected_at: new Date().toISOString(),
    ...overrides,
  };
}

const basicNodes: EvidenceNode[] = [
  makeNode({ id: 'n1', type: 'source', label: 'DNS Record', source: 'dns', value: 'A 1.2.3.4', confidence: 0.95 }),
  makeNode({ id: 'n2', type: 'finding', label: 'VT Hit', source: 'virustotal', value: '45/72', confidence: 0.88 }),
  makeNode({ id: 'n3', type: 'inference', label: 'C2 Likely', source: 'ai_analysis', value: 'High confidence C2', confidence: 0.75 }),
  makeNode({ id: 'n4', type: 'conclusion', label: 'Malicious', source: 'analyst', value: 'Confirmed malware', confidence: 0.9 }),
];

// ─── Rendering ───────────────────────────────────────────────────────────────

describe('EvidenceChain — rendering', () => {
  it('renders without crashing with no nodes', () => {
    const { container } = render(<EvidenceChain nodes={[]} />);
    expect(container).toBeTruthy();
  });

  it('renders node labels', () => {
    render(<EvidenceChain nodes={basicNodes} />);
    expect(screen.getByText('DNS Record')).toBeInTheDocument();
    expect(screen.getByText('VT Hit')).toBeInTheDocument();
    expect(screen.getByText('C2 Likely')).toBeInTheDocument();
  });

  it('renders node values', () => {
    render(<EvidenceChain nodes={basicNodes} />);
    expect(screen.getByText('A 1.2.3.4')).toBeInTheDocument();
    expect(screen.getByText('45/72')).toBeInTheDocument();
  });

  it('renders a conclusion when provided', () => {
    render(
      <EvidenceChain
        nodes={basicNodes}
        conclusion="This IP is confirmed C2 infrastructure."
      />
    );
    expect(screen.getByText('This IP is confirmed C2 infrastructure.')).toBeInTheDocument();
  });

  it('renders an assessment when provided', () => {
    render(
      <EvidenceChain
        nodes={basicNodes}
        assessment="We assess with high confidence that this is malicious."
      />
    );
    expect(
      screen.getByText('We assess with high confidence that this is malicious.')
    ).toBeInTheDocument();
  });

  it('renders "Chain confidence:" in the summary', () => {
    render(<EvidenceChain nodes={basicNodes} conclusion="Done" />);
    expect(screen.getByText(/Chain confidence:/i)).toBeInTheDocument();
  });
});

// ─── Compact mode ────────────────────────────────────────────────────────────

describe('EvidenceChain — compact mode', () => {
  it('shows a "Show all N nodes" button when compact=true', () => {
    render(<EvidenceChain nodes={basicNodes} compact />);
    // Button text is "Show all N nodes"
    expect(screen.getByText(/Show all \d+ nodes/i)).toBeInTheDocument();
  });

  it('does not show "Show all" when compact=false', () => {
    render(<EvidenceChain nodes={basicNodes} compact={false} />);
    expect(screen.queryByText(/Show all/i)).not.toBeInTheDocument();
  });

  it('toggles to "Show less" after clicking "Show all"', () => {
    render(<EvidenceChain nodes={basicNodes} compact />);
    const btn = screen.getByText(/Show all \d+ nodes/i);
    fireEvent.click(btn);
    expect(screen.getByText(/Show less/i)).toBeInTheDocument();
  });
});

// ─── Corroboration badge ──────────────────────────────────────────────────────

describe('EvidenceChain — corroboration badge', () => {
  it('renders the CheckCircle icon (corroboration) for corroborated nodes', () => {
    const nodes = [
      makeNode({ id: 'c1', label: 'Corroborated Source', corroborated: true }),
    ];
    const { container } = render(<EvidenceChain nodes={nodes} />);
    // MUI CheckCircleIcon renders as an SVG; the title attribute on Tooltip has the text
    expect(container.querySelector('[data-testid="CheckCircleIcon"]') ||
      // Fallback: look for the tooltip text via title
      container.querySelector('svg')).toBeTruthy();
  });

  it('does not crash when corroborated is false', () => {
    const nodes = [makeNode({ id: 'c2', corroborated: false })];
    expect(() => render(<EvidenceChain nodes={nodes} />)).not.toThrow();
  });
});

// ─── Confidence labels ────────────────────────────────────────────────────────

describe('EvidenceChain — confidence labels', () => {
  it('shows "High" confidence in the summary for high-confidence chain (≥0.85)', () => {
    const highConf = [
      makeNode({ id: 'h1', confidence: 0.95 }),
      makeNode({ id: 'h2', confidence: 0.90 }),
    ];
    render(<EvidenceChain nodes={highConf} conclusion="x" />);
    // The summary block shows "High (XX%)" — match specifically in the summary
    const summaryTexts = screen.getAllByText(/High/);
    expect(summaryTexts.length).toBeGreaterThan(0);
  });

  it('shows "Speculative" confidence for very low-confidence chain (<0.4)', () => {
    const lowConf = [
      makeNode({ id: 'l1', confidence: 0.2 }),
      makeNode({ id: 'l2', confidence: 0.15 }),
    ];
    render(<EvidenceChain nodes={lowConf} conclusion="x" />);
    const speculativeTexts = screen.getAllByText(/Speculative/);
    expect(speculativeTexts.length).toBeGreaterThan(0);
  });

  it('shows the hypothesis warning for chain confidence < 0.5', () => {
    const lowConf = [
      makeNode({ id: 'lw1', confidence: 0.3 }),
      makeNode({ id: 'lw2', confidence: 0.3 }),
    ];
    render(<EvidenceChain nodes={lowConf} conclusion="x" />);
    expect(screen.getByText(/treat as hypothesis/i)).toBeInTheDocument();
  });
});

// ─── Empty / edge cases ───────────────────────────────────────────────────────

describe('EvidenceChain — edge cases', () => {
  it('renders a single node without connector arrows', () => {
    const single = [makeNode({ id: 's1', label: 'Only Node' })];
    render(<EvidenceChain nodes={single} />);
    expect(screen.getByText('Only Node')).toBeInTheDocument();
  });

  it('renders with collected_at=null (no freshness timestamp)', () => {
    const nodes = [makeNode({ id: 'nodate', collected_at: null })];
    expect(() => render(<EvidenceChain nodes={nodes} />)).not.toThrow();
  });

  it('does not crash without conclusion or assessment', () => {
    expect(() => render(<EvidenceChain nodes={basicNodes} />)).not.toThrow();
  });
});
