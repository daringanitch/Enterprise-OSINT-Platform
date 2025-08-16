# Contributing to Enterprise OSINT Platform

Thank you for your interest in contributing to the Enterprise OSINT Platform! This document provides guidelines and information for contributors.

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites
- Python 3.9+ for backend development
- Node.js 18+ for frontend development  
- Docker for containerization
- Kubernetes cluster for deployment testing
- Git for version control

### Development Environment Setup

1. **Fork and Clone the Repository**
   ```bash
   git clone https://github.com/your-username/enterprise-osint-flask.git
   cd enterprise-osint-flask
   ```

2. **Backend Setup**
   ```bash
   cd simple-backend
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Frontend Setup**
   ```bash
   cd frontend
   npm install
   ```

4. **Run Tests**
   ```bash
   cd simple-backend
   make test
   ```

## How to Contribute

### Reporting Bugs
- Use the **Bug Report** issue template
- Include detailed reproduction steps
- Provide environment information
- Include relevant logs and screenshots

### Suggesting Features
- Use the **Feature Request** issue template
- Describe the problem and proposed solution
- Consider security and compliance implications
- Discuss implementation approach

### Security Issues
- **DO NOT** report security vulnerabilities in public issues
- Follow responsible disclosure practices
- Email security details privately to maintainers
- Use the **Security Issue** template for guidance

### Submitting Changes

1. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-number-description
   ```

2. **Make Changes**
   - Follow coding standards
   - Add tests for new functionality
   - Update documentation
   - Ensure compliance requirements are met

3. **Test Changes**
   ```bash
   # Backend tests
   cd simple-backend
   make test
   
   # Frontend tests
   cd frontend
   npm test
   ```

4. **Commit Changes**
   ```bash
   git add .
   git commit -m "type: concise description of changes"
   ```

5. **Submit Pull Request**
   - Use the pull request template
   - Link to related issues
   - Provide detailed description of changes
   - Include test evidence

## Coding Standards

### Python Backend
- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Document functions with docstrings
- Maximum line length: 100 characters
- Use `black` for code formatting
- Use `flake8` for linting

### TypeScript Frontend  
- Follow TypeScript best practices
- Use ESLint configuration
- Document complex components
- Use Material-UI design system
- Write unit tests for new components

### General Guidelines
- Write clear, descriptive commit messages
- Include tests for new features
- Update documentation for API changes
- Consider security implications
- Ensure compliance requirements are met

## Commit Message Format

Use conventional commit format:
```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test additions/changes
- `chore`: Build/tool changes
- `security`: Security improvements
- `compliance`: Compliance-related changes

**Examples:**
```
feat(mcp): add GitHub API integration to technical MCP server
fix(auth): resolve JWT token expiration handling
docs(api): update investigation endpoint documentation
security(audit): implement trace ID correlation for audit logs
```

## Testing Requirements

### Unit Tests
- Minimum 80% code coverage
- Test both success and failure scenarios
- Mock external dependencies
- Test edge cases and error conditions

### Integration Tests
- Test component interactions
- Verify MCP server connectivity
- Test authentication flows
- Validate audit logging

### Security Testing
- Test authentication/authorization
- Validate input sanitization
- Check for injection vulnerabilities
- Verify audit trail completeness

## Documentation

### Code Documentation
- Document all public APIs
- Include examples in docstrings
- Comment complex algorithms
- Document security considerations

### User Documentation
- Update user guides for new features
- Provide API documentation
- Include deployment instructions
- Document compliance procedures

## Security Guidelines

### Code Security
- Never commit secrets or credentials
- Validate all user inputs
- Sanitize outputs to prevent XSS
- Use parameterized queries
- Implement proper error handling

### OSINT Ethics
- Respect rate limits and ToS
- Only collect publicly available data
- Implement data minimization
- Provide data subject rights
- Ensure lawful basis for processing

## Compliance Requirements

All contributions must consider:
- **GDPR** compliance for EU data subjects
- **CCPA** compliance for California residents  
- **PIPEDA** compliance for Canadian residents
- **Audit trail** requirements
- **Data retention** policies

## Platform-Specific Guidelines

### MCP Server Development
- Implement health check endpoints
- Follow MCP protocol specification
- Handle rate limiting gracefully
- Provide clear error messages
- Test with real external APIs

### Investigation Features
- Maintain audit trails
- Implement proper authorization
- Consider data sensitivity
- Provide compliance assessments
- Enable data subject rights

### Kubernetes Deployment
- Use security best practices
- Implement resource limits
- Follow network policies
- Use service mesh where appropriate
- Provide monitoring capabilities

## Review Process

### Pull Request Review
1. **Automated Checks**
   - Tests must pass
   - Code coverage requirements met
   - Security scanning completed
   - Style guidelines followed

2. **Manual Review**
   - Code quality assessment
   - Security review
   - Compliance verification
   - Documentation review

3. **Approval Requirements**
   - At least one maintainer approval
   - Security approval for sensitive changes
   - Compliance approval for data handling changes

### Merge Process
- Squash commits for clean history
- Include issue references
- Update version numbers if needed
- Deploy to staging for verification

## Getting Help

### Community Support
- **GitHub Discussions**: Ask questions and share ideas
- **Issues**: Report bugs and request features
- **Documentation**: Check existing guides and references

### Maintainer Contact
For sensitive security issues or complex contribution questions:
- Email: [maintainer-email]
- Security: [security-email]

## Recognition

Contributors will be recognized in:
- Repository CONTRIBUTORS.md file
- Release notes for significant contributions
- Annual contributor recognition

Thank you for contributing to making OSINT investigations more effective, compliant, and secure!