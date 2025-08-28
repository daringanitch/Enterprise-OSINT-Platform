# Changelog

All notable changes to the Enterprise OSINT Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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