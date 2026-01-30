# Changelog

All notable changes to the Enterprise OSINT Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Intelligence Correlation Engine
- Entity extraction from investigation data (domains, IPs, emails, hashes)
- Cross-source relationship mapping and confidence scoring
- Automated timeline reconstruction with event correlation
- Weighted confidence scoring based on source reliability

#### Advanced Analysis Features
- MITRE ATT&CK framework mapping with 14 tactics coverage
- 6-category risk scoring engine (infrastructure, data breach, social engineering, malware, financial, overall)
- Executive summary generation with key findings
- Trend analysis with historical comparison

#### Frontend Component Library (TypeScript)
- Design system with centralized theme and design tokens
- Common components: Button (6 variants), Card (4 variants), Modal, FormField, StatusIndicator, Loading, Toast
- Layout components: Header, Sidebar, responsive Layout wrapper
- 229+ component tests with comprehensive coverage

#### Visualization Components
- Chart components: LineChart, BarChart, PieChart, AreaChart using Recharts
- RiskGauge: Circular gauge with risk level thresholds and labels
- TimelineChart: Vertical timeline with expandable event details
- NetworkGraph: Force-directed graph for entity relationships
- Heatmap: Grid-based color intensity visualization
- StatCard: KPI cards with trends and sparklines
- ThreatMatrix: MITRE ATT&CK style tactic/technique display
- DataTable: MUI DataGrid wrapper with search, filter, and export
- 85+ visualization tests

#### Accessibility & UX Enhancements (WCAG 2.1)
- Custom hooks: useKeyboardNavigation, useFocusTrap, useAnnounce, useMediaQuery
- A11y components: SkipLinks, VisuallyHidden, ErrorBoundary, FocusRing
- Color contrast utilities (WCAG AA/AAA compliance checking)
- Form validation utilities with 15+ validators (email, URL, domain, IP, hash)
- 120+ accessibility and utility tests

#### Data Source Expansion
- 6 new intelligence source collectors
- Caching service with TTL support
- Connection pooling for improved performance

#### Infrastructure
- Comprehensive monitoring stack with Prometheus and Grafana
- Automated health monitoring with 5-minute interval checks
- Custom metrics exporter for OSINT-specific metrics
- Multiple HashiCorp Vault deployment options (minimal, dev, production)
- Job queue system for background task processing
- Structured logging and observability modules (currently disabled for Docker compatibility)
- IMPROVEMENT_ROADMAP.md with 12-month development plan
- Automated CLAUDE.md updates via update-claude.sh script

### Changed
- Backend switched to production mode (FLASK_ENV=production)
- MCP server URLs updated to enhanced versions with new ports:
  - Infrastructure: 8021
  - Threat: 8020
  - AI/Technical: 8050
  - Social: 8010
  - Financial: 8040
- PostgreSQL host renamed to osint-platform-postgresql
- Simplified PostgreSQL audit schema using JSON details column
- Authentication updated to support email-based login
- Frontend image updated to v2.0.1

### Fixed
- Investigation tracking bug (self.investigations -> self.active_investigations)
- Python 3.11 compatibility issues with OpenTelemetry
- Authentication to support both email and username login

### Security
- Vault integration for secure secret management
- JWT authentication improvements
- Production-ready security configurations

## [2.0.1] - 2024-08-17

### Changed
- Frontend image version update
- API URL configuration fixes

## [2.0.0] - 2024-08-16

### Added
- Complete DR Roadmap documentation
- Updated Helm Chart v2.0 with production features
- Professional PDF report generation
- 1-hour investigation lifecycle
- Persistent audit history

### Changed
- Major documentation and architecture updates
- Enhanced MCP server implementations
- Improved compliance framework

## [1.0.0] - 2024-08-12

### Added
- Initial release of Enterprise OSINT Platform
- Multi-agent investigation system
- Flask backend with JWT authentication
- React frontend with Material-UI
- PostgreSQL audit database
- Redis session management
- Kubernetes-native deployment
- MCP servers for specialized intelligence gathering:
  - Infrastructure intelligence
  - Social media intelligence
  - Threat intelligence
  - Financial intelligence
  - Technical intelligence
- GDPR/CCPA/PIPEDA compliance framework
- Professional report generation

### Security
- JWT-based authentication system
- Role-based access control (RBAC)
- Secure API communication
- Kubernetes secrets management

[Unreleased]: https://github.com/yourusername/enterprise-osint-flask/compare/v2.0.1...HEAD
[2.0.1]: https://github.com/yourusername/enterprise-osint-flask/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/yourusername/enterprise-osint-flask/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/yourusername/enterprise-osint-flask/releases/tag/v1.0.0