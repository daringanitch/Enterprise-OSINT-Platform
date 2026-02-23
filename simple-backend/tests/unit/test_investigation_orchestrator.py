"""
Unit tests for Investigation Orchestrator
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from investigation_orchestrator import InvestigationOrchestrator
from models import (
    OSINTInvestigation, InvestigationType, InvestigationStatus, Priority,
    TargetProfile, InvestigationScope
)


class TestInvestigationOrchestrator:
    """Test InvestigationOrchestrator functionality"""
    
    @pytest.fixture
    def orchestrator(self):
        """Create orchestrator instance for testing"""
        return InvestigationOrchestrator()
    
    @pytest.fixture
    def sample_target_profile(self):
        """Create sample target profile"""
        return TargetProfile(
            target_id="target_123",
            target_type="domain",
            primary_identifier="example.com",
            created_at=datetime.utcnow()
        )
    
    @pytest.fixture
    def sample_investigation_scope(self):
        """Create sample investigation scope"""
        return InvestigationScope()
    
    def test_create_investigation(self, orchestrator):
        """Test investigation creation without execution"""
        investigation_id = orchestrator.create_investigation(
            target="example.com",
            investigation_type=InvestigationType.COMPREHENSIVE,
            investigator_name="test_user",
            priority=Priority.HIGH
        )
        
        assert investigation_id is not None
        assert investigation_id in orchestrator.investigations
        
        investigation = orchestrator.investigations[investigation_id]
        assert investigation.target_profile.primary_identifier == "example.com"
        assert investigation.investigation_type == InvestigationType.COMPREHENSIVE
        assert investigation.investigator_name == "test_user"
        assert investigation.priority == Priority.HIGH
        assert investigation.status == InvestigationStatus.QUEUED
    
    def test_start_investigation(self, orchestrator):
        """Test full investigation start and execution"""
        with patch.object(orchestrator, '_execute_investigation') as mock_execute:
            investigation_id = orchestrator.start_investigation(
                target="example.com",
                investigation_type=InvestigationType.INFRASTRUCTURE,
                investigator_name="test_user"
            )
            
            assert investigation_id is not None
            assert investigation_id in orchestrator.investigations
            assert investigation_id in orchestrator.active_investigations
            mock_execute.assert_called_once_with(investigation_id)
    
    def test_get_investigation_existing(self, orchestrator):
        """Test getting existing investigation"""
        investigation_id = orchestrator.create_investigation(
            target="example.com",
            investigation_type=InvestigationType.COMPREHENSIVE,
            investigator_name="test_user"
        )
        
        retrieved = orchestrator.get_investigation(investigation_id)
        assert retrieved is not None
        assert retrieved.id == investigation_id
    
    def test_get_investigation_nonexistent(self, orchestrator):
        """Test getting non-existent investigation"""
        result = orchestrator.get_investigation("nonexistent_id")
        assert result is None
    
    def test_list_investigations_empty(self, orchestrator):
        """Test listing investigations when none exist"""
        investigations = orchestrator.list_investigations()
        assert investigations == []
    
    def test_list_investigations_with_data(self, orchestrator):
        """Test listing investigations with data"""
        # Create multiple investigations
        id1 = orchestrator.create_investigation(
            target="example1.com",
            investigation_type=InvestigationType.COMPREHENSIVE,
            investigator_name="user1"
        )
        
        id2 = orchestrator.create_investigation(
            target="example2.com", 
            investigation_type=InvestigationType.INFRASTRUCTURE,
            investigator_name="user2"
        )
        
        investigations = orchestrator.list_investigations()
        assert len(investigations) == 2
        
        investigation_ids = [inv.id for inv in investigations]
        assert id1 in investigation_ids
        assert id2 in investigation_ids
    
    def test_list_investigations_by_status(self, orchestrator):
        """Test filtering investigations by status"""
        # Create investigations with different statuses
        id1 = orchestrator.create_investigation(
            target="example1.com",
            investigation_type=InvestigationType.COMPREHENSIVE,
            investigator_name="user1"
        )
        
        id2 = orchestrator.create_investigation(
            target="example2.com",
            investigation_type=InvestigationType.INFRASTRUCTURE, 
            investigator_name="user2"
        )
        
        # Update one investigation status
        orchestrator.investigations[id2].status = InvestigationStatus.COMPLETED
        
        # Test filtering
        queued = orchestrator.list_investigations(status=InvestigationStatus.QUEUED)
        completed = orchestrator.list_investigations(status=InvestigationStatus.COMPLETED)
        
        assert len(queued) == 1
        assert len(completed) == 1
        assert queued[0].id == id1
        assert completed[0].id == id2
    
    def test_cancel_investigation_existing(self, orchestrator):
        """Test canceling existing investigation"""
        investigation_id = orchestrator.create_investigation(
            target="example.com",
            investigation_type=InvestigationType.COMPREHENSIVE,
            investigator_name="test_user"
        )
        
        success = orchestrator.cancel_investigation(investigation_id)
        assert success is True
        
        investigation = orchestrator.investigations[investigation_id]
        assert investigation.status == InvestigationStatus.CANCELLED
    
    def test_cancel_investigation_nonexistent(self, orchestrator):
        """Test canceling non-existent investigation"""
        success = orchestrator.cancel_investigation("nonexistent_id")
        assert success is False
    
    def test_cancel_investigation_already_completed(self, orchestrator):
        """Test canceling already completed investigation"""
        investigation_id = orchestrator.create_investigation(
            target="example.com",
            investigation_type=InvestigationType.COMPREHENSIVE,
            investigator_name="test_user"
        )
        
        # Mark as completed
        orchestrator.investigations[investigation_id].status = InvestigationStatus.COMPLETED
        
        success = orchestrator.cancel_investigation(investigation_id)
        assert success is False
    
    @patch('investigation_orchestrator.logger')
    def test_execute_investigation_async_success(self, mock_logger, orchestrator):
        """Test successful async investigation execution"""
        # Create investigation
        investigation_id = orchestrator.create_investigation(
            target="example.com",
            investigation_type=InvestigationType.COMPREHENSIVE,
            investigator_name="test_user"
        )
        
        job_data = {
            'job_id': 'job_123',
            'trace_id': 'trace_123',
            'target': 'example.com'
        }
        
        with patch.object(orchestrator, '_execute_investigation') as mock_execute:
            with patch('investigation_orchestrator.update_job_progress') as mock_progress:
                result = orchestrator.execute_investigation_async(investigation_id, job_data)
                
                mock_execute.assert_called_once_with(investigation_id)
                mock_progress.assert_called()
                
                assert result['investigation_id'] == investigation_id
                assert result['status'] == InvestigationStatus.QUEUED.value  # Would be updated in real execution
    
    def test_execute_investigation_async_not_found(self, orchestrator):
        """Test async execution with non-existent investigation"""
        job_data = {'job_id': 'job_123', 'trace_id': 'trace_123'}
        
        with pytest.raises(ValueError, match="Investigation nonexistent not found"):
            orchestrator.execute_investigation_async("nonexistent", job_data)
    
    @patch('investigation_orchestrator.mark_job_failed')
    def test_execute_investigation_async_failure(self, mock_mark_failed, orchestrator):
        """Test async execution with execution failure"""
        investigation_id = orchestrator.create_investigation(
            target="example.com",
            investigation_type=InvestigationType.COMPREHENSIVE,
            investigator_name="test_user"
        )
        
        job_data = {'job_id': 'job_123', 'trace_id': 'trace_123'}
        
        with patch.object(orchestrator, '_execute_investigation', side_effect=Exception("Test error")):
            with pytest.raises(Exception, match="Test error"):
                orchestrator.execute_investigation_async(investigation_id, job_data)
            
            # Verify job was marked as failed
            mock_mark_failed.assert_called_once()
            
            # Verify investigation status was updated
            investigation = orchestrator.investigations[investigation_id]
            assert investigation.status == InvestigationStatus.FAILED
    
    def test_register_progress_callback(self, orchestrator):
        """Test registering progress callback"""
        callback = Mock()
        investigation_id = "test_id"
        
        orchestrator.register_progress_callback(investigation_id, callback)
        
        assert investigation_id in orchestrator.progress_callbacks
        assert callback in orchestrator.progress_callbacks[investigation_id]
    
    def test_notify_progress(self, orchestrator):
        """Test progress notification"""
        callback = Mock()
        investigation_id = "test_id"
        
        # Create mock investigation
        investigation = Mock()
        
        orchestrator.register_progress_callback(investigation_id, callback)
        orchestrator._notify_progress(investigation_id, investigation)
        
        callback.assert_called_once_with(investigation)
    
    def test_transition_to_stage(self, orchestrator):
        """Test stage transition"""
        investigation = Mock()
        investigation.id = "test_id"
        investigation.progress = Mock()
        
        orchestrator._transition_to_stage(investigation, InvestigationStatus.COLLECTING)
        
        assert investigation.status == InvestigationStatus.COLLECTING
        assert investigation.progress.stage == InvestigationStatus.COLLECTING
        assert investigation.progress.stage_progress == 0.0
        assert investigation.progress.current_activity == "Starting collecting stage"
    
    def test_scope_parameter_handling(self, orchestrator):
        """Test investigation creation with custom scope"""
        custom_scope = InvestigationScope()
        custom_scope.include_social_media = False
        custom_scope.max_data_points = 1000
        
        investigation_id = orchestrator.create_investigation(
            target="example.com",
            investigation_type=InvestigationType.COMPREHENSIVE,
            investigator_name="test_user",
            scope=custom_scope
        )
        
        investigation = orchestrator.investigations[investigation_id]
        assert investigation.scope.include_social_media is False
        assert investigation.scope.max_data_points == 1000
    
    def test_investigation_type_mapping(self, orchestrator):
        """Test different investigation types are handled correctly"""
        # Test each investigation type
        for inv_type in InvestigationType:
            investigation_id = orchestrator.create_investigation(
                target=f"{inv_type.value}.com",
                investigation_type=inv_type,
                investigator_name="test_user"
            )
            
            investigation = orchestrator.investigations[investigation_id]
            assert investigation.investigation_type == inv_type
    
    def test_priority_mapping(self, orchestrator):
        """Test different priority levels are handled correctly"""
        # Test each priority level
        for priority in Priority:
            investigation_id = orchestrator.create_investigation(
                target=f"{priority.value}.com",
                investigation_type=InvestigationType.COMPREHENSIVE,
                investigator_name="test_user",
                priority=priority
            )
            
            investigation = orchestrator.investigations[investigation_id]
            assert investigation.priority == priority


class TestInvestigationWorkflow:
    """Test investigation workflow and stage management"""
    
    @pytest.fixture
    def orchestrator(self):
        return InvestigationOrchestrator()
    
    @pytest.fixture
    def sample_investigation(self, orchestrator):
        """Create a sample investigation for testing"""
        investigation_id = orchestrator.create_investigation(
            target="example.com",
            investigation_type=InvestigationType.COMPREHENSIVE,
            investigator_name="test_user"
        )
        return orchestrator.investigations[investigation_id]
    
    def test_investigation_lifecycle(self, orchestrator, sample_investigation):
        """Test complete investigation lifecycle"""
        investigation_id = sample_investigation.id
        
        # Mock the stage execution methods
        with patch.object(orchestrator, '_stage_planning') as mock_planning, \
             patch.object(orchestrator, '_stage_profiling') as mock_profiling, \
             patch.object(orchestrator, '_stage_collecting') as mock_collecting, \
             patch.object(orchestrator, '_stage_analyzing') as mock_analyzing, \
             patch.object(orchestrator, '_stage_verifying') as mock_verifying, \
             patch.object(orchestrator, '_stage_risk_assessment') as mock_risk, \
             patch.object(orchestrator, '_stage_report_generation') as mock_report:
            
            orchestrator.active_investigations[investigation_id] = sample_investigation
            orchestrator._execute_investigation(investigation_id)
            
            # Verify all stages were called
            mock_planning.assert_called_once()
            mock_profiling.assert_called_once()
            mock_collecting.assert_called_once()
            mock_analyzing.assert_called_once()
            mock_verifying.assert_called_once()
            mock_risk.assert_called_once()
            mock_report.assert_called_once()
            
            # Verify final status
            assert sample_investigation.status == InvestigationStatus.COMPLETED
            assert sample_investigation.completed_at is not None
    
    def test_investigation_failure_handling(self, orchestrator, sample_investigation):
        """Test investigation failure handling"""
        investigation_id = sample_investigation.id
        
        # Mock stage to raise exception
        with patch.object(orchestrator, '_stage_planning', side_effect=Exception("Test failure")):
            orchestrator.active_investigations[investigation_id] = sample_investigation
            orchestrator._execute_investigation(investigation_id)
            
            # Verify failure status
            assert sample_investigation.status == InvestigationStatus.FAILED
            assert sample_investigation.completed_at is not None
            assert len(sample_investigation.progress.warnings) > 0
    
    def test_processing_time_calculation(self, orchestrator, sample_investigation):
        """Test processing time calculation"""
        investigation_id = sample_investigation.id
        
        # Set started time
        sample_investigation.started_at = datetime.utcnow() - timedelta(seconds=30)
        
        with patch.object(orchestrator, '_stage_planning'), \
             patch.object(orchestrator, '_stage_profiling'), \
             patch.object(orchestrator, '_stage_collecting'), \
             patch.object(orchestrator, '_stage_analyzing'), \
             patch.object(orchestrator, '_stage_verifying'), \
             patch.object(orchestrator, '_stage_risk_assessment'), \
             patch.object(orchestrator, '_stage_report_generation'):
            
            orchestrator.active_investigations[investigation_id] = sample_investigation
            orchestrator._execute_investigation(investigation_id)
            
            # Verify processing time was calculated
            assert hasattr(sample_investigation, 'processing_time_seconds')
            assert sample_investigation.processing_time_seconds > 0


class TestInvestigationFiltering:
    """Test investigation filtering and search functionality"""
    
    @pytest.fixture
    def orchestrator_with_investigations(self):
        """Create orchestrator with multiple test investigations"""
        orchestrator = InvestigationOrchestrator()
        
        # Create investigations with different characteristics
        test_data = [
            ("example1.com", InvestigationType.COMPREHENSIVE, "user1", Priority.HIGH),
            ("example2.com", InvestigationType.INFRASTRUCTURE, "user2", Priority.NORMAL),
            ("example3.com", InvestigationType.SOCIAL_MEDIA, "user1", Priority.LOW),
            ("example4.com", InvestigationType.THREAT_ASSESSMENT, "user3", Priority.URGENT),
        ]
        
        for target, inv_type, user, priority in test_data:
            orchestrator.create_investigation(target, inv_type, user, priority)
        
        return orchestrator
    
    def test_filter_by_investigator(self, orchestrator_with_investigations):
        """Test filtering investigations by investigator"""
        user1_investigations = orchestrator_with_investigations.list_investigations(
            investigator="user1"
        )
        
        assert len(user1_investigations) == 2
        for inv in user1_investigations:
            assert inv.investigator_name == "user1"
    
    def test_filter_by_type(self, orchestrator_with_investigations):
        """Test filtering investigations by type"""
        infra_investigations = orchestrator_with_investigations.list_investigations(
            investigation_type=InvestigationType.INFRASTRUCTURE
        )
        
        assert len(infra_investigations) == 1
        assert infra_investigations[0].investigation_type == InvestigationType.INFRASTRUCTURE
    
    def test_filter_by_priority(self, orchestrator_with_investigations):
        """Test filtering investigations by priority"""
        high_priority = orchestrator_with_investigations.list_investigations(
            priority=Priority.HIGH
        )
        
        assert len(high_priority) == 1
        assert high_priority[0].priority == Priority.HIGH
    
    def test_filter_by_target_pattern(self, orchestrator_with_investigations):
        """Test filtering investigations by target pattern"""
        # This would require implementing target search functionality
        # For now, just test that the method exists and doesn't error
        all_investigations = orchestrator_with_investigations.list_investigations()
        assert len(all_investigations) == 4