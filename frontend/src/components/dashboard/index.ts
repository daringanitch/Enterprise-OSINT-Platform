/**
 * Dashboard Components Index
 *
 * Re-exports all dashboard components for easy importing.
 */

export { AnomalyPanel } from './AnomalyPanel';
export type { AnomalyPanelProps, AnomalyEntity, AnomalyType } from './AnomalyPanel';

export { MITREDashboard } from './MITREDashboard';
export type { MITREDashboardProps, MITRETactic, MITRETechnique } from './MITREDashboard';

export { RiskCommandCenter } from './RiskCommandCenter';
export type {
  RiskCommandCenterProps,
  RiskCategory,
  CategoryRisk,
  RiskFactor,
  Recommendation,
} from './RiskCommandCenter';

export { ExecutiveSummary } from './ExecutiveSummary';
export type {
  ExecutiveSummaryProps,
  ThreatLevel,
  RiskTrajectory,
  KeyFinding,
  RecommendedAction,
} from './ExecutiveSummary';
