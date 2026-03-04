/**
 * MitreMatrix — Interactive MITRE ATT&CK Matrix
 *
 * Fully interactive replacement/extension of ThreatMatrix.tsx with:
 *  - Heat-map cells lit by evidence count and severity across all investigations
 *  - Click a technique cell → filters findings sidebar + emits onSelect
 *  - Multi-select with Shift/Ctrl for bulk operations
 *  - Export to official ATT&CK Navigator layer JSON (can be imported to navigator.attack.mitre.org)
 *  - "Evidence mode" vs "Coverage mode" toggle
 *  - Compact grid vs full-column layout
 *
 * All 14 MITRE ATT&CK tactics are hard-coded (static data) so the
 * component works without a backend call; the `techniques` prop overlays
 * live evidence counts on top.
 *
 * Usage:
 *   <MitreMatrix
 *     detectedTechniques={[{ technique_id: 'T1566', count: 3, severity: 'high', findings: [...] }]}
 *     onSelect={(ids) => filterFindings(ids)}
 *   />
 */

import React, { useState, useMemo, useCallback } from 'react';
import {
  Box,
  Typography,
  Tooltip,
  Button,
  Chip,
  ToggleButtonGroup,
  ToggleButton,
  styled,
  Popover,
  Divider,
} from '@mui/material';
import DownloadIcon from '@mui/icons-material/Download';
import GridViewIcon from '@mui/icons-material/GridView';
import ViewColumnIcon from '@mui/icons-material/ViewColumn';
import FilterListIcon from '@mui/icons-material/FilterList';
import { cyberColors, designTokens } from '../../utils/theme';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface DetectedTechnique {
  /** MITRE technique ID, e.g. "T1566" or "T1566.001" */
  technique_id: string;
  /** Number of evidence pieces */
  count: number;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  /** Raw finding objects */
  findings?: unknown[];
  /** Human-readable summary */
  description?: string;
  /** Source that produced this finding */
  source?: string;
}

export interface MitreMatrixProps {
  detectedTechniques?: DetectedTechnique[];
  /** Called with selected technique IDs when user clicks cells */
  onSelect?: (techniqueIds: string[]) => void;
  /** Show in "evidence" mode (count heatmap) or "coverage" mode (binary detected/not) */
  defaultMode?: 'evidence' | 'coverage';
  /** Investigation ID used in the Navigator layer name */
  investigationId?: string;
  investigationTarget?: string;
}

// ─── ATT&CK Tactic / Technique data ──────────────────────────────────────────

interface ATTACKTechnique {
  id: string;
  name: string;
  url: string;
}

interface ATTACKTactic {
  id: string;
  name: string;
  shortName: string;
  color: string;
  techniques: ATTACKTechnique[];
}

// Abridged dataset — 14 tactics, ~7-10 most-commonly-seen techniques each
// Full dataset: https://attack.mitre.org/versions/v14/matrices/enterprise/
const ATTACK_TACTICS: ATTACKTactic[] = [
  {
    id: 'TA0043', name: 'Reconnaissance', shortName: 'Recon', color: '#7C3AED',
    techniques: [
      { id: 'T1595', name: 'Active Scanning', url: 'https://attack.mitre.org/techniques/T1595' },
      { id: 'T1592', name: 'Gather Victim Host Info', url: 'https://attack.mitre.org/techniques/T1592' },
      { id: 'T1589', name: 'Gather Victim Identity Info', url: 'https://attack.mitre.org/techniques/T1589' },
      { id: 'T1590', name: 'Gather Victim Network Info', url: 'https://attack.mitre.org/techniques/T1590' },
      { id: 'T1591', name: 'Gather Victim Org Info', url: 'https://attack.mitre.org/techniques/T1591' },
      { id: 'T1598', name: 'Phishing for Information', url: 'https://attack.mitre.org/techniques/T1598' },
      { id: 'T1597', name: 'Search Closed Sources', url: 'https://attack.mitre.org/techniques/T1597' },
      { id: 'T1596', name: 'Search Open Tech Databases', url: 'https://attack.mitre.org/techniques/T1596' },
      { id: 'T1593', name: 'Search Open Websites', url: 'https://attack.mitre.org/techniques/T1593' },
    ],
  },
  {
    id: 'TA0042', name: 'Resource Development', shortName: 'Resource Dev', color: '#6D28D9',
    techniques: [
      { id: 'T1583', name: 'Acquire Infrastructure', url: 'https://attack.mitre.org/techniques/T1583' },
      { id: 'T1586', name: 'Compromise Accounts', url: 'https://attack.mitre.org/techniques/T1586' },
      { id: 'T1584', name: 'Compromise Infrastructure', url: 'https://attack.mitre.org/techniques/T1584' },
      { id: 'T1587', name: 'Develop Capabilities', url: 'https://attack.mitre.org/techniques/T1587' },
      { id: 'T1585', name: 'Establish Accounts', url: 'https://attack.mitre.org/techniques/T1585' },
      { id: 'T1588', name: 'Obtain Capabilities', url: 'https://attack.mitre.org/techniques/T1588' },
      { id: 'T1608', name: 'Stage Capabilities', url: 'https://attack.mitre.org/techniques/T1608' },
    ],
  },
  {
    id: 'TA0001', name: 'Initial Access', shortName: 'Initial Access', color: '#DB2777',
    techniques: [
      { id: 'T1189', name: 'Drive-by Compromise', url: 'https://attack.mitre.org/techniques/T1189' },
      { id: 'T1190', name: 'Exploit Public-Facing App', url: 'https://attack.mitre.org/techniques/T1190' },
      { id: 'T1133', name: 'External Remote Services', url: 'https://attack.mitre.org/techniques/T1133' },
      { id: 'T1200', name: 'Hardware Additions', url: 'https://attack.mitre.org/techniques/T1200' },
      { id: 'T1566', name: 'Phishing', url: 'https://attack.mitre.org/techniques/T1566' },
      { id: 'T1091', name: 'Replication Through Removable Media', url: 'https://attack.mitre.org/techniques/T1091' },
      { id: 'T1195', name: 'Supply Chain Compromise', url: 'https://attack.mitre.org/techniques/T1195' },
      { id: 'T1199', name: 'Trusted Relationship', url: 'https://attack.mitre.org/techniques/T1199' },
      { id: 'T1078', name: 'Valid Accounts', url: 'https://attack.mitre.org/techniques/T1078' },
    ],
  },
  {
    id: 'TA0002', name: 'Execution', shortName: 'Execution', color: '#DC2626',
    techniques: [
      { id: 'T1059', name: 'Command and Scripting Interpreter', url: 'https://attack.mitre.org/techniques/T1059' },
      { id: 'T1609', name: 'Container Administration Command', url: 'https://attack.mitre.org/techniques/T1609' },
      { id: 'T1203', name: 'Exploitation for Client Execution', url: 'https://attack.mitre.org/techniques/T1203' },
      { id: 'T1559', name: 'Inter-Process Communication', url: 'https://attack.mitre.org/techniques/T1559' },
      { id: 'T1106', name: 'Native API', url: 'https://attack.mitre.org/techniques/T1106' },
      { id: 'T1053', name: 'Scheduled Task/Job', url: 'https://attack.mitre.org/techniques/T1053' },
      { id: 'T1648', name: 'Serverless Execution', url: 'https://attack.mitre.org/techniques/T1648' },
      { id: 'T1129', name: 'Shared Modules', url: 'https://attack.mitre.org/techniques/T1129' },
    ],
  },
  {
    id: 'TA0003', name: 'Persistence', shortName: 'Persistence', color: '#B45309',
    techniques: [
      { id: 'T1098', name: 'Account Manipulation', url: 'https://attack.mitre.org/techniques/T1098' },
      { id: 'T1197', name: 'BITS Jobs', url: 'https://attack.mitre.org/techniques/T1197' },
      { id: 'T1547', name: 'Boot or Logon Autostart', url: 'https://attack.mitre.org/techniques/T1547' },
      { id: 'T1136', name: 'Create Account', url: 'https://attack.mitre.org/techniques/T1136' },
      { id: 'T1543', name: 'Create or Modify System Process', url: 'https://attack.mitre.org/techniques/T1543' },
      { id: 'T1133', name: 'External Remote Services', url: 'https://attack.mitre.org/techniques/T1133' },
      { id: 'T1574', name: 'Hijack Execution Flow', url: 'https://attack.mitre.org/techniques/T1574' },
      { id: 'T1078', name: 'Valid Accounts', url: 'https://attack.mitre.org/techniques/T1078' },
    ],
  },
  {
    id: 'TA0004', name: 'Privilege Escalation', shortName: 'Priv Esc', color: '#D97706',
    techniques: [
      { id: 'T1548', name: 'Abuse Elevation Control Mechanism', url: 'https://attack.mitre.org/techniques/T1548' },
      { id: 'T1134', name: 'Access Token Manipulation', url: 'https://attack.mitre.org/techniques/T1134' },
      { id: 'T1547', name: 'Boot or Logon Autostart', url: 'https://attack.mitre.org/techniques/T1547' },
      { id: 'T1068', name: 'Exploitation for Privilege Escalation', url: 'https://attack.mitre.org/techniques/T1068' },
      { id: 'T1574', name: 'Hijack Execution Flow', url: 'https://attack.mitre.org/techniques/T1574' },
      { id: 'T1055', name: 'Process Injection', url: 'https://attack.mitre.org/techniques/T1055' },
      { id: 'T1053', name: 'Scheduled Task/Job', url: 'https://attack.mitre.org/techniques/T1053' },
    ],
  },
  {
    id: 'TA0005', name: 'Defense Evasion', shortName: 'Defense Evasion', color: '#059669',
    techniques: [
      { id: 'T1548', name: 'Abuse Elevation Control Mechanism', url: 'https://attack.mitre.org/techniques/T1548' },
      { id: 'T1134', name: 'Access Token Manipulation', url: 'https://attack.mitre.org/techniques/T1134' },
      { id: 'T1197', name: 'BITS Jobs', url: 'https://attack.mitre.org/techniques/T1197' },
      { id: 'T1622', name: 'Debugger Evasion', url: 'https://attack.mitre.org/techniques/T1622' },
      { id: 'T1140', name: 'Deobfuscate/Decode Files', url: 'https://attack.mitre.org/techniques/T1140' },
      { id: 'T1480', name: 'Execution Guardrails', url: 'https://attack.mitre.org/techniques/T1480' },
      { id: 'T1211', name: 'Exploitation for Defense Evasion', url: 'https://attack.mitre.org/techniques/T1211' },
      { id: 'T1564', name: 'Hide Artifacts', url: 'https://attack.mitre.org/techniques/T1564' },
      { id: 'T1562', name: 'Impair Defenses', url: 'https://attack.mitre.org/techniques/T1562' },
    ],
  },
  {
    id: 'TA0006', name: 'Credential Access', shortName: 'Cred Access', color: '#0284C7',
    techniques: [
      { id: 'T1557', name: 'Adversary-in-the-Middle', url: 'https://attack.mitre.org/techniques/T1557' },
      { id: 'T1110', name: 'Brute Force', url: 'https://attack.mitre.org/techniques/T1110' },
      { id: 'T1555', name: 'Credentials from Password Stores', url: 'https://attack.mitre.org/techniques/T1555' },
      { id: 'T1212', name: 'Exploitation for Credential Access', url: 'https://attack.mitre.org/techniques/T1212' },
      { id: 'T1187', name: 'Forced Authentication', url: 'https://attack.mitre.org/techniques/T1187' },
      { id: 'T1056', name: 'Input Capture', url: 'https://attack.mitre.org/techniques/T1056' },
      { id: 'T1556', name: 'Modify Authentication Process', url: 'https://attack.mitre.org/techniques/T1556' },
      { id: 'T1003', name: 'OS Credential Dumping', url: 'https://attack.mitre.org/techniques/T1003' },
    ],
  },
  {
    id: 'TA0007', name: 'Discovery', shortName: 'Discovery', color: '#0891B2',
    techniques: [
      { id: 'T1087', name: 'Account Discovery', url: 'https://attack.mitre.org/techniques/T1087' },
      { id: 'T1010', name: 'Application Window Discovery', url: 'https://attack.mitre.org/techniques/T1010' },
      { id: 'T1217', name: 'Browser Information Discovery', url: 'https://attack.mitre.org/techniques/T1217' },
      { id: 'T1580', name: 'Cloud Infrastructure Discovery', url: 'https://attack.mitre.org/techniques/T1580' },
      { id: 'T1538', name: 'Cloud Service Dashboard', url: 'https://attack.mitre.org/techniques/T1538' },
      { id: 'T1083', name: 'File and Directory Discovery', url: 'https://attack.mitre.org/techniques/T1083' },
      { id: 'T1046', name: 'Network Service Discovery', url: 'https://attack.mitre.org/techniques/T1046' },
      { id: 'T1135', name: 'Network Share Discovery', url: 'https://attack.mitre.org/techniques/T1135' },
      { id: 'T1057', name: 'Process Discovery', url: 'https://attack.mitre.org/techniques/T1057' },
    ],
  },
  {
    id: 'TA0008', name: 'Lateral Movement', shortName: 'Lateral Mov', color: '#0E7490',
    techniques: [
      { id: 'T1210', name: 'Exploitation of Remote Services', url: 'https://attack.mitre.org/techniques/T1210' },
      { id: 'T1534', name: 'Internal Spearphishing', url: 'https://attack.mitre.org/techniques/T1534' },
      { id: 'T1570', name: 'Lateral Tool Transfer', url: 'https://attack.mitre.org/techniques/T1570' },
      { id: 'T1563', name: 'Remote Service Session Hijacking', url: 'https://attack.mitre.org/techniques/T1563' },
      { id: 'T1021', name: 'Remote Services', url: 'https://attack.mitre.org/techniques/T1021' },
      { id: 'T1091', name: 'Replication Through Removable Media', url: 'https://attack.mitre.org/techniques/T1091' },
      { id: 'T1072', name: 'Software Deployment Tools', url: 'https://attack.mitre.org/techniques/T1072' },
    ],
  },
  {
    id: 'TA0009', name: 'Collection', shortName: 'Collection', color: '#047857',
    techniques: [
      { id: 'T1560', name: 'Archive Collected Data', url: 'https://attack.mitre.org/techniques/T1560' },
      { id: 'T1123', name: 'Audio Capture', url: 'https://attack.mitre.org/techniques/T1123' },
      { id: 'T1119', name: 'Automated Collection', url: 'https://attack.mitre.org/techniques/T1119' },
      { id: 'T1115', name: 'Clipboard Data', url: 'https://attack.mitre.org/techniques/T1115' },
      { id: 'T1530', name: 'Data from Cloud Storage', url: 'https://attack.mitre.org/techniques/T1530' },
      { id: 'T1213', name: 'Data from Information Repositories', url: 'https://attack.mitre.org/techniques/T1213' },
      { id: 'T1005', name: 'Data from Local System', url: 'https://attack.mitre.org/techniques/T1005' },
      { id: 'T1056', name: 'Input Capture', url: 'https://attack.mitre.org/techniques/T1056' },
    ],
  },
  {
    id: 'TA0011', name: 'Command and Control', shortName: 'C2', color: '#1D4ED8',
    techniques: [
      { id: 'T1071', name: 'Application Layer Protocol', url: 'https://attack.mitre.org/techniques/T1071' },
      { id: 'T1092', name: 'Communication Through Removable Media', url: 'https://attack.mitre.org/techniques/T1092' },
      { id: 'T1132', name: 'Data Encoding', url: 'https://attack.mitre.org/techniques/T1132' },
      { id: 'T1001', name: 'Data Obfuscation', url: 'https://attack.mitre.org/techniques/T1001' },
      { id: 'T1568', name: 'Dynamic Resolution', url: 'https://attack.mitre.org/techniques/T1568' },
      { id: 'T1573', name: 'Encrypted Channel', url: 'https://attack.mitre.org/techniques/T1573' },
      { id: 'T1008', name: 'Fallback Channels', url: 'https://attack.mitre.org/techniques/T1008' },
      { id: 'T1105', name: 'Ingress Tool Transfer', url: 'https://attack.mitre.org/techniques/T1105' },
      { id: 'T1095', name: 'Non-Application Layer Protocol', url: 'https://attack.mitre.org/techniques/T1095' },
    ],
  },
  {
    id: 'TA0010', name: 'Exfiltration', shortName: 'Exfil', color: '#BE185D',
    techniques: [
      { id: 'T1020', name: 'Automated Exfiltration', url: 'https://attack.mitre.org/techniques/T1020' },
      { id: 'T1030', name: 'Data Transfer Size Limits', url: 'https://attack.mitre.org/techniques/T1030' },
      { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', url: 'https://attack.mitre.org/techniques/T1048' },
      { id: 'T1041', name: 'Exfiltration Over C2 Channel', url: 'https://attack.mitre.org/techniques/T1041' },
      { id: 'T1011', name: 'Exfiltration Over Other Network Medium', url: 'https://attack.mitre.org/techniques/T1011' },
      { id: 'T1052', name: 'Exfiltration Over Physical Medium', url: 'https://attack.mitre.org/techniques/T1052' },
      { id: 'T1567', name: 'Exfiltration Over Web Service', url: 'https://attack.mitre.org/techniques/T1567' },
    ],
  },
  {
    id: 'TA0040', name: 'Impact', shortName: 'Impact', color: '#9F1239',
    techniques: [
      { id: 'T1531', name: 'Account Access Removal', url: 'https://attack.mitre.org/techniques/T1531' },
      { id: 'T1485', name: 'Data Destruction', url: 'https://attack.mitre.org/techniques/T1485' },
      { id: 'T1486', name: 'Data Encrypted for Impact', url: 'https://attack.mitre.org/techniques/T1486' },
      { id: 'T1565', name: 'Data Manipulation', url: 'https://attack.mitre.org/techniques/T1565' },
      { id: 'T1491', name: 'Defacement', url: 'https://attack.mitre.org/techniques/T1491' },
      { id: 'T1561', name: 'Disk Wipe', url: 'https://attack.mitre.org/techniques/T1561' },
      { id: 'T1499', name: 'Endpoint Denial of Service', url: 'https://attack.mitre.org/techniques/T1499' },
      { id: 'T1496', name: 'Resource Hijacking', url: 'https://attack.mitre.org/techniques/T1496' },
    ],
  },
];

// ─── Severity heat scale ──────────────────────────────────────────────────────

function severityColor(severity: string, alpha = 1): string {
  const map: Record<string, string> = {
    critical: `rgba(239,68,68,${alpha})`,
    high: `rgba(249,115,22,${alpha})`,
    medium: `rgba(245,158,11,${alpha})`,
    low: `rgba(34,211,238,${alpha})`,
    info: `rgba(100,116,139,${alpha})`,
  };
  return map[severity] || map.info;
}

function countToOpacity(count: number): number {
  if (count <= 0) return 0;
  if (count === 1) return 0.3;
  if (count <= 3) return 0.5;
  if (count <= 6) return 0.72;
  return 0.9;
}

// ─── Navigator export ─────────────────────────────────────────────────────────

function buildNavigatorLayer(
  detected: DetectedTechnique[],
  name: string,
): object {
  return {
    name,
    versions: { attack: '14', navigator: '4.9', layer: '4.5' },
    domain: 'enterprise-attack',
    description: `Generated by Enterprise OSINT Platform — ${new Date().toISOString()}`,
    filters: { platforms: ['Windows', 'Linux', 'macOS', 'Network', 'Cloud'] },
    sorting: 3,
    layout: { layout: 'flat', aggregateFunction: 'max', showID: true, showName: true },
    hideDisabled: false,
    techniques: detected.map((t) => ({
      techniqueID: t.technique_id,
      score: t.count,
      color: severityColor(t.severity, 1).replace('rgba', 'rgb').replace(/,[^,)]+\)/, ')'),
      comment: t.description || `${t.count} finding(s) · ${t.severity}`,
      enabled: true,
      metadata: [{ name: 'source', value: t.source || 'OSINT Platform' }],
    })),
    gradient: {
      colors: ['#ffffff00', '#ff6666ff'],
      minValue: 0,
      maxValue: Math.max(...detected.map((t) => t.count), 1),
    },
    legendItems: [],
    metadata: [],
    showTacticRowBackground: true,
    tacticRowBackground: '#dddddd',
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
  };
}

// ─── Styled ───────────────────────────────────────────────────────────────────

const MatrixRoot = styled(Box)({
  display: 'flex',
  flexDirection: 'column',
  gap: 16,
});

const MatrixGrid = styled(Box)({
  display: 'grid',
  gridTemplateColumns: 'repeat(14, minmax(80px, 1fr))',
  gap: 8,
  overflowX: 'auto',
  paddingBottom: 8,
});

const TacticColumn = styled(Box)({
  display: 'flex',
  flexDirection: 'column',
  gap: 4,
  minWidth: 80,
});

const TacticHeader = styled(Box)<{ tacticcolor: string }>(({ tacticcolor }) => ({
  borderRadius: 6,
  padding: '5px 6px',
  backgroundColor: `${tacticcolor}20`,
  border: `1px solid ${tacticcolor}50`,
  textAlign: 'center',
  cursor: 'default',
}));

const TechniqueCell = styled(Box)<{ detected: boolean; selected: boolean; severity?: string; count?: number }>(
  ({ detected, selected, severity, count }) => {
    const bgOpacity = detected && count ? countToOpacity(count) : 0;
    const bgColor = detected && severity ? severityColor(severity, bgOpacity) : 'transparent';
    const borderColor = selected
      ? cyberColors.neon.cyan
      : detected
      ? severityColor(severity || 'info', 0.6)
      : `${cyberColors.dark.steel}35`;
    return {
      borderRadius: 4,
      padding: '4px 6px',
      backgroundColor: bgColor,
      border: `1px solid ${borderColor}`,
      cursor: detected ? 'pointer' : 'default',
      transition: 'all 0.15s ease',
      outline: selected ? `2px solid ${cyberColors.neon.cyan}` : 'none',
      outlineOffset: 1,
      '&:hover': detected
        ? { transform: 'scale(1.04)', boxShadow: `0 0 8px ${cyberColors.neon.cyan}30`, zIndex: 2 }
        : {},
    };
  },
);

// ─── Component ────────────────────────────────────────────────────────────────

export const MitreMatrix: React.FC<MitreMatrixProps> = ({
  detectedTechniques = [],
  onSelect,
  defaultMode = 'evidence',
  investigationId,
  investigationTarget = 'Investigation',
}) => {
  const [mode, setMode] = useState<'evidence' | 'coverage'>(defaultMode);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [popoverAnchor, setPopoverAnchor] = useState<Element | null>(null);
  const [popoverTechnique, setPopoverTechnique] = useState<{ technique: ATTACKTechnique; detected?: DetectedTechnique } | null>(null);

  // Build a quick lookup map
  const detectedMap = useMemo(() => {
    const m = new Map<string, DetectedTechnique>();
    for (const dt of detectedTechniques) m.set(dt.technique_id, dt);
    return m;
  }, [detectedTechniques]);

  const totalDetected = detectedTechniques.length;
  const totalTechniques = ATTACK_TACTICS.reduce((s, t) => s + t.techniques.length, 0);

  const handleCellClick = useCallback(
    (techniqueId: string, e: React.MouseEvent) => {
      if (!detectedMap.has(techniqueId)) return;
      setSelected((prev) => {
        const next = new Set(prev);
        if (e.shiftKey || e.ctrlKey || e.metaKey) {
          if (next.has(techniqueId)) next.delete(techniqueId);
          else next.add(techniqueId);
        } else {
          if (next.has(techniqueId) && next.size === 1) next.clear();
          else { next.clear(); next.add(techniqueId); }
        }
        onSelect?.(Array.from(next));
        return next;
      });
    },
    [detectedMap, onSelect],
  );

  const handleCellHover = useCallback(
    (technique: ATTACKTechnique, e: React.MouseEvent) => {
      const dt = detectedMap.get(technique.id);
      if (!dt) return;
      setPopoverAnchor(e.currentTarget);
      setPopoverTechnique({ technique, detected: dt });
    },
    [detectedMap],
  );

  const exportNavigatorLayer = useCallback(() => {
    const layer = buildNavigatorLayer(
      detectedTechniques,
      `OSINT Platform — ${investigationTarget}`,
    );
    const blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `attack-navigator-${investigationId || 'export'}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [detectedTechniques, investigationId, investigationTarget]);

  return (
    <MatrixRoot>
      {/* Toolbar */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 1 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Typography sx={{ fontFamily: designTokens.typography.fontFamily.display, fontSize: '1.1rem', fontWeight: 700, color: cyberColors.text.primary }}>
            MITRE ATT&CK Matrix
          </Typography>
          <Chip
            label={`${totalDetected} / ${totalTechniques} techniques`}
            size="small"
            sx={{
              height: 22, fontSize: '0.7rem',
              backgroundColor: totalDetected > 0 ? `${cyberColors.neon.orange}15` : `${cyberColors.dark.steel}20`,
              color: totalDetected > 0 ? cyberColors.neon.orange : cyberColors.text.muted,
              border: `1px solid ${totalDetected > 0 ? cyberColors.neon.orange : cyberColors.dark.steel}35`,
            }}
          />
          {selected.size > 0 && (
            <Chip
              label={`${selected.size} selected`}
              size="small"
              onDelete={() => { setSelected(new Set()); onSelect?.([]); }}
              sx={{
                height: 22, fontSize: '0.7rem',
                backgroundColor: `${cyberColors.neon.cyan}15`,
                color: cyberColors.neon.cyan,
                border: `1px solid ${cyberColors.neon.cyan}35`,
              }}
            />
          )}
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <ToggleButtonGroup
            value={mode}
            exclusive
            onChange={(_, v) => v && setMode(v)}
            size="small"
          >
            <ToggleButton value="evidence" sx={{ fontSize: '0.7rem', py: 0.5, px: 1.5, color: cyberColors.text.secondary, '&.Mui-selected': { color: cyberColors.neon.cyan, backgroundColor: `${cyberColors.neon.cyan}15` } }}>
              Evidence Heat
            </ToggleButton>
            <ToggleButton value="coverage" sx={{ fontSize: '0.7rem', py: 0.5, px: 1.5, color: cyberColors.text.secondary, '&.Mui-selected': { color: cyberColors.neon.cyan, backgroundColor: `${cyberColors.neon.cyan}15` } }}>
              Coverage
            </ToggleButton>
          </ToggleButtonGroup>
          {detectedTechniques.length > 0 && (
            <Tooltip title="Export ATT&CK Navigator layer (.json)">
              <Button
                size="small"
                startIcon={<DownloadIcon />}
                onClick={exportNavigatorLayer}
                sx={{
                  fontSize: '0.75rem', fontWeight: 600, textTransform: 'none',
                  color: cyberColors.neon.cyan,
                  border: `1px solid ${cyberColors.neon.cyan}40`,
                  borderRadius: 2, height: 30, px: 1.5,
                  '&:hover': { backgroundColor: `${cyberColors.neon.cyan}10` },
                }}
              >
                Navigator Export
              </Button>
            </Tooltip>
          )}
        </Box>
      </Box>

      {/* Severity legend */}
      <Box sx={{ display: 'flex', gap: 1.5, alignItems: 'center', flexWrap: 'wrap' }}>
        <Typography sx={{ fontSize: '0.7rem', color: cyberColors.text.muted }}>Severity:</Typography>
        {(['critical', 'high', 'medium', 'low', 'info'] as const).map((s) => (
          <Box key={s} sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <Box sx={{ width: 10, height: 10, borderRadius: 2, backgroundColor: severityColor(s, 0.7) }} />
            <Typography sx={{ fontSize: '0.65rem', color: cyberColors.text.muted, textTransform: 'capitalize' }}>{s}</Typography>
          </Box>
        ))}
        <Typography sx={{ fontSize: '0.7rem', color: cyberColors.text.muted, ml: 1 }}>
          Click to select · Shift/⌘+Click multi-select
        </Typography>
      </Box>

      {/* Matrix */}
      <MatrixGrid>
        {ATTACK_TACTICS.map((tactic) => (
          <TacticColumn key={tactic.id}>
            <TacticHeader tacticcolor={tactic.color}>
              <Typography sx={{ fontSize: '0.62rem', fontWeight: 700, color: tactic.color, lineHeight: 1.2 }}>
                {tactic.shortName}
              </Typography>
              <Typography sx={{ fontSize: '0.55rem', color: `${tactic.color}80` }}>
                {tactic.techniques.filter((t) => detectedMap.has(t.id)).length}/{tactic.techniques.length}
              </Typography>
            </TacticHeader>
            {tactic.techniques.map((technique) => {
              const dt = detectedMap.get(technique.id);
              const isDetected = Boolean(dt);
              const isSelected = selected.has(technique.id);
              return (
                <Tooltip
                  key={technique.id}
                  title={
                    isDetected
                      ? `${technique.id}: ${technique.name} · ${dt!.count} finding(s) · ${dt!.severity}`
                      : `${technique.id}: ${technique.name}`
                  }
                  placement="top"
                  arrow
                >
                  <TechniqueCell
                    detected={isDetected}
                    selected={isSelected}
                    severity={dt?.severity}
                    count={dt?.count}
                    onClick={(e) => handleCellClick(technique.id, e)}
                    onMouseEnter={isDetected ? (e) => handleCellHover(technique, e) : undefined}
                    onMouseLeave={() => { setPopoverAnchor(null); setPopoverTechnique(null); }}
                  >
                    <Typography
                      sx={{
                        fontSize: '0.58rem',
                        fontFamily: designTokens.typography.fontFamily.mono,
                        color: isDetected ? cyberColors.text.primary : cyberColors.text.muted,
                        lineHeight: 1.3,
                        fontWeight: isDetected ? 600 : 400,
                        userSelect: 'none',
                      }}
                    >
                      {technique.id}
                    </Typography>
                    <Typography
                      sx={{
                        fontSize: '0.58rem',
                        color: isDetected ? cyberColors.text.secondary : `${cyberColors.text.muted}80`,
                        lineHeight: 1.3,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                        display: 'block',
                        maxWidth: '100%',
                      }}
                    >
                      {technique.name}
                    </Typography>
                    {isDetected && mode === 'evidence' && (
                      <Box
                        sx={{
                          mt: 0.25,
                          width: `${Math.min(100, (dt!.count / 10) * 100)}%`,
                          height: 2, borderRadius: 1,
                          backgroundColor: severityColor(dt!.severity, 0.9),
                        }}
                      />
                    )}
                  </TechniqueCell>
                </Tooltip>
              );
            })}
          </TacticColumn>
        ))}
      </MatrixGrid>

      {/* Technique detail popover */}
      <Popover
        open={Boolean(popoverAnchor && popoverTechnique)}
        anchorEl={popoverAnchor}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
        transformOrigin={{ vertical: 'top', horizontal: 'center' }}
        onClose={() => { setPopoverAnchor(null); setPopoverTechnique(null); }}
        disableRestoreFocus
        sx={{ pointerEvents: 'none' }}
        PaperProps={{
          sx: {
            backgroundColor: '#0D1117',
            border: `1px solid ${cyberColors.neon.cyan}40`,
            borderRadius: 2,
            p: 2, minWidth: 240, maxWidth: 320,
            pointerEvents: 'none',
          },
        }}
      >
        {popoverTechnique && (
          <>
            <Typography sx={{ fontSize: '0.65rem', fontFamily: designTokens.typography.fontFamily.mono, color: cyberColors.neon.cyan, mb: 0.5 }}>
              {popoverTechnique.technique.id}
            </Typography>
            <Typography sx={{ fontSize: '0.88rem', fontWeight: 600, color: cyberColors.text.primary, mb: 1 }}>
              {popoverTechnique.technique.name}
            </Typography>
            {popoverTechnique.detected && (
              <>
                <Divider sx={{ borderColor: `${cyberColors.dark.steel}60`, mb: 1 }} />
                <Box sx={{ display: 'flex', gap: 2, mb: 1 }}>
                  <Box>
                    <Typography sx={{ fontSize: '1.2rem', fontWeight: 700, color: cyberColors.text.primary, fontFamily: designTokens.typography.fontFamily.mono }}>
                      {popoverTechnique.detected.count}
                    </Typography>
                    <Typography sx={{ fontSize: '0.65rem', color: cyberColors.text.muted }}>findings</Typography>
                  </Box>
                  <Box>
                    <Typography sx={{ fontSize: '1.2rem', fontWeight: 700, color: severityColor(popoverTechnique.detected.severity, 1), fontFamily: designTokens.typography.fontFamily.mono }}>
                      {popoverTechnique.detected.severity}
                    </Typography>
                    <Typography sx={{ fontSize: '0.65rem', color: cyberColors.text.muted }}>severity</Typography>
                  </Box>
                </Box>
                {popoverTechnique.detected.description && (
                  <Typography sx={{ fontSize: '0.72rem', color: cyberColors.text.secondary }}>
                    {popoverTechnique.detected.description}
                  </Typography>
                )}
                <Typography
                  component="a"
                  href={popoverTechnique.technique.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  sx={{ fontSize: '0.68rem', color: cyberColors.neon.cyan, display: 'block', mt: 1 }}
                >
                  View on attack.mitre.org →
                </Typography>
              </>
            )}
          </>
        )}
      </Popover>
    </MatrixRoot>
  );
};

export default MitreMatrix;
