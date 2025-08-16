---
name: Security Issue
about: Report a security vulnerability (use private disclosure)
title: '[SECURITY] '
labels: 'security, critical, needs-triage'
assignees: ''
---

⚠️ **IMPORTANT**: Please do not report security vulnerabilities in public issues. 
For security issues, please follow responsible disclosure practices:

1. Email security details to the project maintainers privately
2. Allow reasonable time for assessment and fix development
3. Coordinate public disclosure timing

---

## Security Issue Type
- [ ] Authentication/Authorization vulnerability
- [ ] Data exposure/privacy issue
- [ ] Injection vulnerability (SQL, command, etc.)
- [ ] Cross-site scripting (XSS)
- [ ] Cross-site request forgery (CSRF)
- [ ] Insecure data transmission
- [ ] Privilege escalation
- [ ] API security issue
- [ ] Configuration security issue
- [ ] Compliance violation
- [ ] Other: _______________

## Affected Components
- [ ] Authentication system
- [ ] Investigation APIs
- [ ] MCP server communication
- [ ] Report generation
- [ ] Audit logging
- [ ] Database queries
- [ ] File handling
- [ ] Configuration management
- [ ] External API integrations
- [ ] Kubernetes deployment

## Impact Assessment
- [ ] **Critical**: Remote code execution, full system compromise
- [ ] **High**: Data breach, privilege escalation, authentication bypass
- [ ] **Medium**: Limited data exposure, partial functionality compromise
- [ ] **Low**: Information disclosure, minor security weakness

## Environment Details
- **Platform Version**: [e.g., v1.2.3]
- **Deployment Type**: [Kubernetes/Docker/Local]
- **Components Affected**: [List specific services/modules]
- **Network Configuration**: [Internal/External access, proxy setup, etc.]

## Vulnerability Details
**Please provide a detailed description of the security issue:**

### Attack Vector
How can this vulnerability be exploited?

### Proof of Concept
[Provide minimal reproduction steps - sanitize any sensitive data]

### Potential Impact
What could an attacker achieve by exploiting this vulnerability?

## Compliance Implications
- [ ] Affects GDPR compliance
- [ ] Affects CCPA compliance  
- [ ] Affects PIPEDA compliance
- [ ] Affects SOC 2 compliance
- [ ] Affects audit requirements
- [ ] May require breach notification

## Remediation Suggestions
If you have suggestions for fixing this issue, please provide them:

## Timeline
- **Discovery Date**: [When did you discover this issue?]
- **Disclosure Deadline**: [When do you plan to publicly disclose?]
- **Coordinated Disclosure**: [Are you willing to coordinate disclosure timing?]

## Additional Information
Any other relevant details, references, or context.