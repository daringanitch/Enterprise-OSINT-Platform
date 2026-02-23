"""
RFC 7807 Problem+JSON Error Handling for OSINT Platform
Standardizes API error responses across the platform
"""
import json
import traceback
from typing import Dict, Any, Optional, Union
from datetime import datetime
from flask import jsonify, request, g, current_app
from werkzeug.exceptions import HTTPException
from trace_context import TraceContextManager, StructuredLogger

logger = StructuredLogger(__name__)

# Problem type base URL
PROBLEM_TYPE_BASE = "https://osint.platform/errors"


class ProblemDetail:
    """RFC 7807 Problem Detail class"""
    
    def __init__(self, 
                 type_suffix: str = "about:blank",
                 title: str = "An error occurred",
                 status: int = 500,
                 detail: Optional[str] = None,
                 instance: Optional[str] = None,
                 trace_id: Optional[str] = None,
                 **extensions):
        """
        Create a Problem Detail object
        
        Args:
            type_suffix: Suffix for the problem type URI
            title: Short human-readable summary
            status: HTTP status code
            detail: Human-readable explanation
            instance: URI identifying the specific occurrence
            trace_id: Correlation ID for debugging
            **extensions: Additional problem-specific fields
        """
        self.type = f"{PROBLEM_TYPE_BASE}/{type_suffix}" if type_suffix != "about:blank" else type_suffix
        self.title = title
        self.status = status
        self.detail = detail
        self.instance = instance or request.path if request else None
        self.trace_id = trace_id or TraceContextManager.get_current_trace_id()
        self.timestamp = datetime.utcnow().isoformat()
        self.extensions = extensions
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = {
            "type": self.type,
            "title": self.title,
            "status": self.status,
            "timestamp": self.timestamp
        }
        
        if self.detail:
            result["detail"] = self.detail
        if self.instance:
            result["instance"] = self.instance
        if self.trace_id:
            result["trace_id"] = self.trace_id
        
        # Add any extensions
        result.update(self.extensions)
        
        return result
    
    def to_json_response(self):
        """Convert to Flask JSON response"""
        response = jsonify(self.to_dict())
        response.status_code = self.status
        response.headers['Content-Type'] = 'application/problem+json'
        return response


class ProblemJSONMiddleware:
    """Flask middleware for RFC 7807 Problem+JSON error handling"""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the middleware with Flask app"""
        # Register error handlers for different exception types
        app.errorhandler(400)(self.handle_bad_request)
        app.errorhandler(401)(self.handle_unauthorized)
        app.errorhandler(403)(self.handle_forbidden)
        app.errorhandler(404)(self.handle_not_found)
        app.errorhandler(409)(self.handle_conflict)
        app.errorhandler(422)(self.handle_unprocessable_entity)
        app.errorhandler(429)(self.handle_rate_limit)
        app.errorhandler(500)(self.handle_internal_server_error)
        app.errorhandler(502)(self.handle_bad_gateway)
        app.errorhandler(503)(self.handle_service_unavailable)
        app.errorhandler(504)(self.handle_gateway_timeout)
        
        # Generic exception handler
        app.errorhandler(Exception)(self.handle_generic_exception)
        
        # Custom OSINT-specific exception handlers
        app.errorhandler(InvestigationNotFoundError)(self.handle_investigation_not_found)
        app.errorhandler(MCPServerError)(self.handle_mcp_server_error)
        app.errorhandler(ComplianceViolationError)(self.handle_compliance_violation)
        app.errorhandler(APIQuotaExceededError)(self.handle_api_quota_exceeded)
        app.errorhandler(VaultConfigurationError)(self.handle_vault_configuration_error)
        app.errorhandler(JobQueueError)(self.handle_job_queue_error)
        
        logger.info("Problem+JSON middleware initialized")
    
    def handle_bad_request(self, error):
        """Handle 400 Bad Request errors"""
        problem = ProblemDetail(
            type_suffix="bad-request",
            title="Bad Request",
            status=400,
            detail=getattr(error, 'description', 'The request could not be understood by the server'),
            validation_errors=getattr(error, 'validation_errors', None)
        )
        return self._log_and_respond(problem, error)
    
    def handle_unauthorized(self, error):
        """Handle 401 Unauthorized errors"""
        problem = ProblemDetail(
            type_suffix="unauthorized",
            title="Authentication Required",
            status=401,
            detail="Valid authentication credentials are required",
            auth_scheme=getattr(error, 'auth_scheme', 'Bearer')
        )
        return self._log_and_respond(problem, error)
    
    def handle_forbidden(self, error):
        """Handle 403 Forbidden errors"""
        problem = ProblemDetail(
            type_suffix="forbidden",
            title="Access Forbidden", 
            status=403,
            detail=getattr(error, 'description', 'You do not have permission to access this resource'),
            required_permissions=getattr(error, 'required_permissions', None)
        )
        return self._log_and_respond(problem, error)
    
    def handle_not_found(self, error):
        """Handle 404 Not Found errors"""
        problem = ProblemDetail(
            type_suffix="not-found",
            title="Resource Not Found",
            status=404,
            detail=f"The requested resource '{request.path}' was not found",
            available_endpoints=getattr(error, 'available_endpoints', None)
        )
        return self._log_and_respond(problem, error)
    
    def handle_conflict(self, error):
        """Handle 409 Conflict errors"""
        problem = ProblemDetail(
            type_suffix="conflict",
            title="Resource Conflict",
            status=409,
            detail=getattr(error, 'description', 'The request conflicts with the current state of the resource'),
            conflicting_resource=getattr(error, 'conflicting_resource', None)
        )
        return self._log_and_respond(problem, error)
    
    def handle_unprocessable_entity(self, error):
        """Handle 422 Unprocessable Entity errors"""
        problem = ProblemDetail(
            type_suffix="validation-failed",
            title="Validation Failed",
            status=422,
            detail="The request was well-formed but contains semantic errors",
            validation_errors=getattr(error, 'validation_errors', None)
        )
        return self._log_and_respond(problem, error)
    
    def handle_rate_limit(self, error):
        """Handle 429 Rate Limit errors"""
        problem = ProblemDetail(
            type_suffix="rate-limit-exceeded",
            title="Rate Limit Exceeded",
            status=429,
            detail="Too many requests. Please try again later.",
            retry_after=getattr(error, 'retry_after', None),
            limit=getattr(error, 'limit', None),
            window=getattr(error, 'window', None)
        )
        return self._log_and_respond(problem, error)
    
    def handle_internal_server_error(self, error):
        """Handle 500 Internal Server Error"""
        problem = ProblemDetail(
            type_suffix="internal-server-error",
            title="Internal Server Error",
            status=500,
            detail="An unexpected error occurred. Please try again later."
        )
        
        # Include error details in development mode
        if current_app.config.get('DEBUG', False):
            problem.extensions['error_type'] = error.__class__.__name__
            problem.extensions['error_message'] = str(error)
            if hasattr(error, '__traceback__'):
                problem.extensions['traceback'] = traceback.format_exc()
        
        return self._log_and_respond(problem, error, level='error')
    
    def handle_bad_gateway(self, error):
        """Handle 502 Bad Gateway errors"""
        problem = ProblemDetail(
            type_suffix="bad-gateway",
            title="Bad Gateway",
            status=502,
            detail="The server received an invalid response from an upstream server",
            upstream_service=getattr(error, 'upstream_service', None)
        )
        return self._log_and_respond(problem, error)
    
    def handle_service_unavailable(self, error):
        """Handle 503 Service Unavailable errors"""
        problem = ProblemDetail(
            type_suffix="service-unavailable", 
            title="Service Unavailable",
            status=503,
            detail="The service is temporarily unavailable. Please try again later.",
            retry_after=getattr(error, 'retry_after', None),
            maintenance_mode=getattr(error, 'maintenance_mode', False)
        )
        return self._log_and_respond(problem, error)
    
    def handle_gateway_timeout(self, error):
        """Handle 504 Gateway Timeout errors"""
        problem = ProblemDetail(
            type_suffix="gateway-timeout",
            title="Gateway Timeout", 
            status=504,
            detail="The server did not receive a timely response from an upstream server",
            timeout_duration=getattr(error, 'timeout_duration', None),
            upstream_service=getattr(error, 'upstream_service', None)
        )
        return self._log_and_respond(problem, error)
    
    def handle_generic_exception(self, error):
        """Handle any unhandled exceptions"""
        # Don't handle HTTPExceptions here (they have specific handlers)
        if isinstance(error, HTTPException):
            return error
        
        problem = ProblemDetail(
            type_suffix="unexpected-error",
            title="Unexpected Error",
            status=500,
            detail="An unexpected error occurred"
        )
        
        # Include error details in development mode
        if current_app.config.get('DEBUG', False):
            problem.extensions['error_type'] = error.__class__.__name__
            problem.extensions['error_message'] = str(error)
            problem.extensions['traceback'] = traceback.format_exc()
        
        return self._log_and_respond(problem, error, level='error')
    
    # OSINT-specific error handlers
    
    def handle_investigation_not_found(self, error):
        """Handle investigation not found errors"""
        problem = ProblemDetail(
            type_suffix="investigation-not-found",
            title="Investigation Not Found",
            status=404,
            detail=f"Investigation '{error.investigation_id}' was not found",
            investigation_id=error.investigation_id,
            available_investigations=getattr(error, 'available_investigations', None)
        )
        return self._log_and_respond(problem, error)
    
    def handle_mcp_server_error(self, error):
        """Handle MCP server errors"""
        problem = ProblemDetail(
            type_suffix="mcp-server-error",
            title="MCP Server Error",
            status=502,
            detail=f"Error communicating with MCP server: {error.server_name}",
            server_name=error.server_name,
            server_url=getattr(error, 'server_url', None),
            operation=getattr(error, 'operation', None),
            retry_suggested=True
        )
        return self._log_and_respond(problem, error)
    
    def handle_compliance_violation(self, error):
        """Handle compliance violation errors"""
        problem = ProblemDetail(
            type_suffix="compliance-violation",
            title="Compliance Violation",
            status=403,
            detail=f"Operation violates {error.framework} compliance requirements",
            framework=error.framework,
            violation_type=getattr(error, 'violation_type', None),
            required_actions=getattr(error, 'required_actions', None)
        )
        return self._log_and_respond(problem, error)
    
    def handle_api_quota_exceeded(self, error):
        """Handle API quota exceeded errors"""
        problem = ProblemDetail(
            type_suffix="api-quota-exceeded",
            title="API Quota Exceeded",
            status=429,
            detail=f"API quota exceeded for service: {error.service_name}",
            service_name=error.service_name,
            quota_limit=getattr(error, 'quota_limit', None),
            quota_reset=getattr(error, 'quota_reset', None),
            alternative_services=getattr(error, 'alternative_services', None)
        )
        return self._log_and_respond(problem, error)
    
    def handle_vault_configuration_error(self, error):
        """Handle Vault configuration errors"""
        problem = ProblemDetail(
            type_suffix="vault-configuration-error",
            title="Vault Configuration Error",
            status=500,
            detail="Failed to retrieve configuration from Vault",
            vault_path=getattr(error, 'vault_path', None),
            fallback_available=getattr(error, 'fallback_available', False)
        )
        return self._log_and_respond(problem, error)
    
    def handle_job_queue_error(self, error):
        """Handle job queue errors"""
        problem = ProblemDetail(
            type_suffix="job-queue-error",
            title="Job Queue Error",
            status=503,
            detail="Failed to queue background job",
            queue_name=getattr(error, 'queue_name', None),
            job_type=getattr(error, 'job_type', None),
            retry_available=True
        )
        return self._log_and_respond(problem, error)
    
    def _log_and_respond(self, problem: ProblemDetail, error: Exception, level: str = 'warning'):
        """Log the error and return Problem+JSON response"""
        log_data = {
            'error_type': error.__class__.__name__,
            'error_message': str(error),
            'status_code': problem.status,
            'trace_id': problem.trace_id,
            'instance': problem.instance
        }
        
        if level == 'error':
            logger.error(f"Error {problem.status}: {problem.title}", extra=log_data)
        else:
            logger.warning(f"Error {problem.status}: {problem.title}", extra=log_data)
        
        return problem.to_json_response()


# Custom OSINT Platform Exceptions

class OSINTPlatformError(Exception):
    """Base exception for OSINT Platform errors"""
    pass


class InvestigationNotFoundError(OSINTPlatformError):
    """Raised when an investigation is not found"""
    def __init__(self, investigation_id: str, available_investigations: Optional[list] = None):
        self.investigation_id = investigation_id
        self.available_investigations = available_investigations
        super().__init__(f"Investigation {investigation_id} not found")


class MCPServerError(OSINTPlatformError):
    """Raised when MCP server communication fails"""
    def __init__(self, server_name: str, server_url: str = None, operation: str = None):
        self.server_name = server_name
        self.server_url = server_url
        self.operation = operation
        super().__init__(f"MCP server error: {server_name}")


class ComplianceViolationError(OSINTPlatformError):
    """Raised when an operation violates compliance requirements"""
    def __init__(self, framework: str, violation_type: str = None, required_actions: list = None):
        self.framework = framework
        self.violation_type = violation_type
        self.required_actions = required_actions
        super().__init__(f"Compliance violation: {framework}")


class APIQuotaExceededError(OSINTPlatformError):
    """Raised when API quota is exceeded"""
    def __init__(self, service_name: str, quota_limit: int = None, quota_reset: str = None, alternative_services: list = None):
        self.service_name = service_name
        self.quota_limit = quota_limit
        self.quota_reset = quota_reset
        self.alternative_services = alternative_services
        super().__init__(f"API quota exceeded: {service_name}")


class VaultConfigurationError(OSINTPlatformError):
    """Raised when Vault configuration fails"""
    def __init__(self, vault_path: str = None, fallback_available: bool = False):
        self.vault_path = vault_path
        self.fallback_available = fallback_available
        super().__init__("Vault configuration error")


class JobQueueError(OSINTPlatformError):
    """Raised when job queue operations fail"""
    def __init__(self, queue_name: str = None, job_type: str = None):
        self.queue_name = queue_name
        self.job_type = job_type
        super().__init__("Job queue error")


# Utility functions for creating common problems

def create_validation_problem(validation_errors: Dict[str, list]) -> ProblemDetail:
    """Create a validation problem with detailed field errors"""
    return ProblemDetail(
        type_suffix="validation-failed",
        title="Request Validation Failed",
        status=422,
        detail="One or more request fields failed validation",
        validation_errors=validation_errors
    )


def create_authentication_problem(auth_scheme: str = "Bearer") -> ProblemDetail:
    """Create an authentication problem"""
    return ProblemDetail(
        type_suffix="authentication-required",
        title="Authentication Required",
        status=401,
        detail="Valid authentication credentials are required to access this resource",
        auth_scheme=auth_scheme
    )


def create_authorization_problem(required_permissions: list = None) -> ProblemDetail:
    """Create an authorization problem"""
    return ProblemDetail(
        type_suffix="insufficient-permissions",
        title="Insufficient Permissions",
        status=403,
        detail="You do not have the required permissions to perform this action",
        required_permissions=required_permissions
    )


def create_rate_limit_problem(limit: int, window: str, retry_after: int = None) -> ProblemDetail:
    """Create a rate limiting problem"""
    return ProblemDetail(
        type_suffix="rate-limit-exceeded",
        title="Rate Limit Exceeded",
        status=429,
        detail=f"Request rate limit of {limit} per {window} exceeded",
        limit=limit,
        window=window,
        retry_after=retry_after
    )