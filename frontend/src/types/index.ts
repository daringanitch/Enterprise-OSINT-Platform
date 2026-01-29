/**
 * TypeScript Type Definitions for OSINT Platform
 */

// =============================================================================
// User & Authentication Types
// =============================================================================

export interface User {
  id: string;
  username: string;
  email: string;
  role: 'admin' | 'analyst' | 'viewer';
  permissions: string[];
  createdAt: string;
  lastLogin?: string;
}

export interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
}

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface AuthResponse {
  access_token: string;
  user: User;
  expires_in: number;
}

// =============================================================================
// Investigation Types
// =============================================================================

export type InvestigationType =
  | 'comprehensive'
  | 'corporate'
  | 'infrastructure'
  | 'social_media'
  | 'threat_assessment'
  | 'compliance_check';

export type InvestigationStatus =
  | 'pending'
  | 'queued'
  | 'planning'
  | 'profiling'
  | 'collecting'
  | 'analyzing'
  | 'assessing_risk'
  | 'verifying'
  | 'generating_report'
  | 'completed'
  | 'failed'
  | 'cancelled';

export type Priority = 'low' | 'normal' | 'high' | 'urgent' | 'critical';

export interface Investigation {
  id: string;
  investigation_id: string;
  target: string;
  type: InvestigationType;
  status: InvestigationStatus;
  priority: Priority;
  investigator: string;
  created_at: string;
  updated_at: string;
  completed_at?: string;
  progress: number;
  current_stage?: string;
  findings_count: number;
  risk_level?: RiskLevel;
  risk_score?: number;
  report_generated?: boolean;
  report_generated_at?: string;
}

export interface InvestigationFormData {
  target: string;
  type: InvestigationType;
  priority: Priority;
  investigator_name: string;
  include_social_media?: boolean;
  include_infrastructure?: boolean;
  include_threat_intelligence?: boolean;
}

export interface InvestigationDetail extends Investigation {
  infrastructure_intelligence?: InfrastructureIntelligence;
  social_intelligence?: SocialIntelligence;
  threat_intelligence?: ThreatIntelligence;
  correlation_results?: CorrelationResults;
  advanced_analysis?: AdvancedAnalysis;
  compliance_reports?: ComplianceReport[];
  audit_trail?: AuditEntry[];
}

// =============================================================================
// Intelligence Types
// =============================================================================

export interface InfrastructureIntelligence {
  domains: Domain[];
  subdomains: string[];
  ip_addresses: IPAddress[];
  certificates: Certificate[];
  dns_records: Record<string, DnsRecord[]>;
  exposed_services: ExposedService[];
}

export interface Domain {
  domain: string;
  registrar?: string;
  creation_date?: string;
  expiration_date?: string;
  registrant?: RegistrantInfo;
}

export interface IPAddress {
  ip: string;
  organization?: string;
  asn?: string;
  country?: string;
  city?: string;
}

export interface Certificate {
  subject: string;
  issuer: string;
  valid_from: string;
  valid_to: string;
  fingerprint: string;
  san?: string[];
  expired?: boolean;
}

export interface DnsRecord {
  type: string;
  value: string;
  ttl?: number;
}

export interface ExposedService {
  port: number;
  service: string;
  version?: string;
  banner?: string;
  risk_level?: RiskLevel;
}

export interface RegistrantInfo {
  name?: string;
  organization?: string;
  email?: string;
  country?: string;
}

export interface SocialIntelligence {
  platforms: Record<string, SocialPlatform>;
  sentiment_analysis: Record<string, number>;
  engagement_metrics: Record<string, number>;
  reputation_score: number;
}

export interface SocialPlatform {
  username: string;
  url?: string;
  followers?: number;
  posts?: number;
  verified?: boolean;
  last_activity?: string;
}

export interface ThreatIntelligence {
  malware_indicators: ThreatIndicator[];
  network_indicators: ThreatIndicator[];
  behavioral_indicators: ThreatIndicator[];
  threat_actors: ThreatActor[];
  campaigns: Campaign[];
  risk_score: number;
  mitre_techniques: string[];
}

export interface ThreatIndicator {
  type: string;
  value: string;
  confidence: number;
  first_seen?: string;
  last_seen?: string;
  threat_type?: string;
  source?: string;
}

export interface ThreatActor {
  name: string;
  aliases?: string[];
  motivation?: string;
  sophistication?: string;
  country?: string;
}

export interface Campaign {
  name: string;
  first_seen: string;
  last_seen: string;
  targets: string[];
  techniques: string[];
}

// =============================================================================
// Correlation Types
// =============================================================================

export interface CorrelationResults {
  entities: Record<string, Entity>;
  entity_count: number;
  relationships: Relationship[];
  relationship_count: number;
  timeline: TimelineEvent[];
  event_count: number;
  clusters: Cluster[];
  key_findings: KeyFinding[];
  confidence_summary: Record<string, number>;
  statistics: CorrelationStatistics;
}

export interface Entity {
  id: string;
  type: EntityType;
  value: string;
  normalized_value: string;
  sources: string[];
  source_count: number;
  confidence: number;
  first_seen?: string;
  last_seen?: string;
  attributes: Record<string, unknown>;
  tags: string[];
}

export type EntityType =
  | 'domain'
  | 'ip_address'
  | 'email'
  | 'person'
  | 'organization'
  | 'url'
  | 'hash'
  | 'phone'
  | 'social_account'
  | 'certificate'
  | 'asn'
  | 'technology';

export interface Relationship {
  source: string;
  target: string;
  type: RelationshipType;
  confidence: number;
  sources: string[];
  first_observed?: string;
  last_observed?: string;
}

export type RelationshipType =
  | 'resolves_to'
  | 'owns'
  | 'registered_by'
  | 'hosts'
  | 'associated_with'
  | 'subdomain_of'
  | 'uses_technology'
  | 'issued_for'
  | 'mentions'
  | 'exposed_in'
  | 'member_of'
  | 'controls';

export interface TimelineEvent {
  timestamp: string;
  event_type: string;
  description: string;
  entities: string[];
  source: string;
  severity: 'info' | 'warning' | 'critical';
  attributes: Record<string, unknown>;
}

export interface Cluster {
  size: number;
  entity_ids: string[];
  entity_types: string[];
  total_sources: number;
}

export interface KeyFinding {
  type: string;
  severity: string;
  title: string;
  description: string;
  entities?: string[];
  events?: TimelineEvent[];
}

export interface CorrelationStatistics {
  total_entities: number;
  entities_by_type: Record<string, number>;
  total_relationships: number;
  relationships_by_type: Record<string, number>;
  total_timeline_events: number;
  events_by_severity: Record<string, number>;
  unique_sources: number;
  source_list: string[];
}

// =============================================================================
// Advanced Analysis Types
// =============================================================================

export interface AdvancedAnalysis {
  target: string;
  analyzed_at: string;
  risk_score: RiskScoreDetail;
  mitre_mapping: MITREMapping;
  trends: TrendAnalysis;
  executive_summary: ExecutiveSummary;
  charts: ChartData;
}

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low';

export interface RiskScoreDetail {
  overall_score: number;
  risk_level: RiskLevel;
  category_scores: Record<string, number>;
  factors: RiskFactor[];
  trend: string;
  confidence: number;
}

export interface RiskFactor {
  category: string;
  name: string;
  score: number;
  weight: number;
  evidence: string[];
  recommendations: string[];
}

export interface MITREMapping {
  techniques: MITRETechnique[];
  attack_surface: AttackSurface;
  technique_count: number;
}

export interface MITRETechnique {
  technique_id: string;
  name: string;
  tactic: string;
  description: string;
  detection?: string;
  mitigation?: string;
  severity: string;
  evidence: string[];
  evidence_count: number;
  sources: string[];
}

export interface AttackSurface {
  total_techniques: number;
  tactics_covered: string[];
  tactic_count: number;
  severity_distribution: Record<string, number>;
  critical_count: number;
  high_count: number;
  attack_surface_score: number;
}

export interface TrendAnalysis {
  trend_available: boolean;
  event_distribution?: Record<string, number>;
  severity_distribution?: Record<string, number>;
  temporal_distribution?: Record<string, number>;
  trend_direction?: string;
  patterns?: TrendPattern[];
  total_events?: number;
  analysis_period?: {
    start: string;
    end: string;
    duration_days: number;
  };
  message?: string;
}

export interface TrendPattern {
  type: string;
  description: string;
  significance: string;
}

export interface ExecutiveSummary {
  title: string;
  generated_at: string;
  classification: string;
  overview: string;
  key_findings: SummaryFinding[];
  risk_assessment: RiskAssessmentSummary;
  threat_landscape: ThreatLandscape;
  recommendations: Recommendation[];
  metrics: SummaryMetrics;
  conclusion: string;
}

export interface SummaryFinding {
  category: string;
  finding: string;
  severity: string;
  impact: string;
  priority: string;
}

export interface RiskAssessmentSummary {
  overall_assessment: string;
  score: number;
  category_breakdown: CategoryBreakdown[];
  trend: string;
  confidence: string;
}

export interface CategoryBreakdown {
  category: string;
  score: number;
  level: string;
}

export interface ThreatLandscape {
  attack_surface_score: number;
  techniques_identified: number;
  tactics_covered: string[];
  kill_chain_coverage: string;
  top_techniques: TopTechnique[];
}

export interface TopTechnique {
  id: string;
  name: string;
  severity: string;
}

export interface Recommendation {
  recommendation: string;
  priority: 'immediate' | 'short_term' | 'long_term';
  category: string;
}

export interface SummaryMetrics {
  data_sources_analyzed: number;
  entities_discovered: number;
  relationships_mapped: number;
  timeline_events: number;
  findings_generated: number;
}

// =============================================================================
// Chart Types
// =============================================================================

export interface ChartData {
  risk_distribution?: PieChartData;
  risk_gauge?: GaugeChartData;
  severity_breakdown?: BarChartData;
  timeline?: StackedBarChartData;
  entity_distribution?: BarChartData;
}

export interface PieChartData {
  chart_type: 'pie';
  title: string;
  data: PieChartDataPoint[];
}

export interface PieChartDataPoint {
  label: string;
  value: number;
  color: string;
}

export interface BarChartData {
  chart_type: 'bar' | 'horizontal_bar';
  title: string;
  data: BarChartDataPoint[];
}

export interface BarChartDataPoint {
  label: string;
  value: number;
  color?: string;
}

export interface GaugeChartData {
  chart_type: 'gauge';
  title: string;
  value: number;
  max: number;
  thresholds: GaugeThreshold[];
}

export interface GaugeThreshold {
  value: number;
  color: string;
  label: string;
}

export interface StackedBarChartData {
  chart_type: 'stacked_bar';
  title: string;
  categories: string[];
  series: StackedBarSeries[];
}

export interface StackedBarSeries {
  name: string;
  data: number[];
  color: string;
}

// =============================================================================
// Compliance Types
// =============================================================================

export interface ComplianceReport {
  framework: ComplianceFramework;
  assessment_date: string;
  compliance_score: number;
  findings: ComplianceFinding[];
  recommendations: string[];
}

export type ComplianceFramework = 'gdpr' | 'ccpa' | 'pipeda' | 'lgpd';

export interface ComplianceFinding {
  requirement: string;
  status: 'compliant' | 'non_compliant' | 'partial' | 'not_applicable';
  details: string;
  risk_level: RiskLevel;
}

// =============================================================================
// Audit Types
// =============================================================================

export interface AuditEntry {
  id: string;
  timestamp: string;
  event_type: string;
  user: string;
  action: string;
  target?: string;
  details: Record<string, unknown>;
  ip_address?: string;
}

// =============================================================================
// System Types
// =============================================================================

export interface SystemStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  mode: 'demo' | 'production';
  api_keys: ApiKeyStatus;
  services: ServiceStatus[];
  mcp_servers: MCPServerStatus[];
  uptime: number;
  version: string;
}

export interface ApiKeyStatus {
  available: number;
  total: number;
  keys: Record<string, boolean>;
}

export interface ServiceStatus {
  name: string;
  status: 'healthy' | 'unhealthy';
  latency?: number;
  last_check: string;
}

export interface MCPServerStatus {
  name: string;
  port: number;
  status: 'connected' | 'disconnected' | 'error';
  capabilities: string[];
  last_response_time?: number;
}

// =============================================================================
// API Response Types
// =============================================================================

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
  timestamp?: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

// =============================================================================
// Component Prop Types
// =============================================================================

export type ButtonVariant = 'primary' | 'secondary' | 'success' | 'warning' | 'danger' | 'ghost';
export type ButtonSize = 'sm' | 'md' | 'lg';

export type StatusVariant = 'success' | 'warning' | 'error' | 'info' | 'neutral';

export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}
