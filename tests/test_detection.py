"""
Unit tests for AnalysisAgent and AnalysisAgent.
Tests classification correctness, safe-mode behavior, learning mode, and score validation.
"""
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


from backend.agents.analysis_agent import AnalysisAgent
from backend.agents.queues import AgentQueues, get_queues
from backend.ml.inference import MLInferencePipeline
from backend.models.messages import FeatureVector, ThreatScore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def feature_vector() -> FeatureVector:
    """Create a sample FeatureVector for testing."""
    return FeatureVector(
        flow_id="test_flow_123",
        timestamp=datetime.utcnow(),
        src_ip="192.168.1.100",
        dst_ip="10.0.0.50",
        src_port=54321,
        dst_port=1883,  # MQTT port
        protocol="TCP",
        packet_rate=150.0,
        byte_rate=45000.0,
        flow_duration=2.5,
        tcp_flags="PA",
        connection_errors=0,
        port_entropy=0.8,
        is_known_iot_port=True,
    )


@pytest.fixture
def mock_pipeline() -> MLInferencePipeline:
    """Create a mocked ML pipeline with controlled predictions."""
    pipeline = MagicMock(spec=MLInferencePipeline)
    pipeline.lightgbm_available = True
    pipeline.if_available = True
    pipeline.load_models = MagicMock()
    return pipeline


@pytest.fixture
def agent_queues() -> AgentQueues:
    """Create fresh agent queues for each test."""
    return AgentQueues(
        detection_queue=asyncio.Queue(maxsize=1000),
        anomaly_queue=asyncio.Queue(maxsize=1000),
        risk_queue=asyncio.Queue(maxsize=1000),
        orchestrator_queue=asyncio.PriorityQueue(maxsize=1000),
        prevention_queue=asyncio.Queue(maxsize=1000),
        healing_queue=asyncio.Queue(maxsize=1000),
        logging_queue=asyncio.Queue(maxsize=10000),
    )


@pytest.fixture(autouse=True)
def setup_queues(agent_queues, monkeypatch):
    """Ensure get_queues() returns our test queues."""
    monkeypatch.setattr("backend.agents.queues._queues", agent_queues)
    monkeypatch.setattr("backend.agents.analysis_agent.get_queues", lambda: agent_queues)
    


# ---------------------------------------------------------------------------
# AnalysisAgent Tests (Task 9.1)
# ---------------------------------------------------------------------------

class TestAnalysisAgent:
    """Unit tests for AnalysisAgent (Requirements 7.1, 7.2, 7.5)."""

    @pytest.mark.asyncio
    async def test_valid_feature_vector_emits_threat_score_with_lightgbm_source(
        self, feature_vector, mock_pipeline, agent_queues
    ):
        """
        Test: valid FeatureVector with loaded lightgbm model emits ThreatScore with source="lightgbm"
        Validates: Requirement 7.1
        """
        # Mock lightgbm prediction to return attack type and probability
        mock_pipeline.predict_lightgbm.return_value = ("DDoS", 0.85)
        
        agent = AnalysisAgent(pipeline=mock_pipeline)
        
        # Classify the feature vector
        result = await agent.classify(feature_vector)
        
        # Verify ThreatScore was created
        assert result is not None
        assert isinstance(result, ThreatScore)
        assert result.source == "lightgbm"
        assert result.flow_id == feature_vector.flow_id
        assert result.score == 0.85
        assert result.attack_type == "DDoS"
        
        # Verify ThreatScore was emitted to risk_queue
        assert agent_queues.risk_queue.qsize() == 1
        queued_score = await agent_queues.risk_queue.get()
        assert queued_score.source == "lightgbm"
        assert queued_score.score == 0.85

    @pytest.mark.asyncio
    async def test_safe_mode_prevents_threat_score_emission(
        self, feature_vector, mock_pipeline, agent_queues
    ):
        """
        Test: safe_mode prevents ThreatScore emission
        Validates: Requirement 7.2
        """
        # Force safe mode by making lightgbm model unavailable
        mock_pipeline.lightgbm_available = False
        
        agent = AnalysisAgent(pipeline=mock_pipeline)
        agent._safe_mode = True  # Explicitly set safe mode
        
        # Classify the feature vector
        result = await agent.classify(feature_vector)
        
        # Verify no ThreatScore was created
        assert result is None
        
        # Verify risk_queue is empty (no emission)
        assert agent_queues.risk_queue.qsize() == 0
        
        # Verify log entry was created instead
        assert agent_queues.logging_queue.qsize() == 1
        log_entry = await agent_queues.logging_queue.get()
        assert log_entry.event_type == "safe_mode_skip"

    @pytest.mark.asyncio
    async def test_score_always_in_valid_range(
        self, feature_vector, mock_pipeline, agent_queues
    ):
        """
        Test: score is always in range [0.0, 1.0]
        Validates: Requirement 7.5
        """
        # Test multiple score values
        test_scores = [0.0, 0.25, 0.5, 0.75, 1.0, 0.65, 0.9]
        
        for score in test_scores:
            mock_pipeline.predict_lightgbm.return_value = ("TestAttack", score)
            
            agent = AnalysisAgent(pipeline=mock_pipeline)
            result = await agent.classify(feature_vector)
            
            assert result is not None
            assert 0.0 <= result.score <= 1.0, f"Score {result.score} out of range"
            assert result.score == score
            
            # Clear queue for next iteration
            await agent_queues.risk_queue.get()

    @pytest.mark.asyncio
    async def test_benign_classification_has_no_attack_type(
        self, feature_vector, mock_pipeline, agent_queues
    ):
        """
        Test: BENIGN classification results in attack_type=None
        """
        mock_pipeline.predict_lightgbm.return_value = ("BENIGN", 0.1)
        
        agent = AnalysisAgent(pipeline=mock_pipeline)
        result = await agent.classify(feature_vector)
        
        assert result is not None
        assert result.attack_type is None
        assert result.score == 0.1

    @pytest.mark.asyncio
    async def test_model_load_failure_enters_safe_mode(self, agent_queues):
        """
        Test: Model load failure causes agent to enter safe mode
        """
        mock_pipeline = MagicMock(spec=MLInferencePipeline)
        mock_pipeline.load_models.side_effect = Exception("Model file not found")
        mock_pipeline.lightgbm_available = False
        
        agent = AnalysisAgent(pipeline=mock_pipeline)
        await agent._load_model()
        
        assert agent.safe_mode is True

    @pytest.mark.asyncio
    async def test_lightgbm_unavailable_enters_safe_mode(self, agent_queues):
        """
        Test: lightgbm model unavailable causes agent to enter safe mode
        """
        mock_pipeline = MagicMock(spec=MLInferencePipeline)
        mock_pipeline.load_models = MagicMock()
        mock_pipeline.lightgbm_available = False
        
        agent = AnalysisAgent(pipeline=mock_pipeline)
        await agent._load_model()
        
        assert agent.safe_mode is True

    @pytest.mark.asyncio
    async def test_pipeline_returns_none_does_not_emit(
        self, feature_vector, mock_pipeline, agent_queues
    ):
        """
        Test: When pipeline returns None, no ThreatScore is emitted
        """
        mock_pipeline.predict_lightgbm.return_value = None
        
        agent = AnalysisAgent(pipeline=mock_pipeline)
        result = await agent.classify(feature_vector)
        
        assert result is None
        assert agent_queues.risk_queue.qsize() == 0


# ---------------------------------------------------------------------------
# AnalysisAgent Tests (Task 9.4)
# ---------------------------------------------------------------------------

class TestAnalysisAgent:
    """Unit tests for AnalysisAgent (Requirements 7.3, 7.4, 7.8)."""

    @pytest.mark.asyncio
    async def test_learning_mode_prevents_threat_score_emission(
        self, feature_vector, mock_pipeline, agent_queues
    ):
        """
        Test: learning_mode prevents ThreatScore emission
        Validates: Requirement 7.3
        """
        mock_pipeline.predict_if.return_value = 0.75
        
        agent = AnalysisAgent(pipeline=mock_pipeline)
        agent.learning_mode = True
        
        # Score the feature vector
        result = await agent.score(feature_vector)
        
        # Verify no ThreatScore was created
        assert result is None
        
        # Verify risk_queue is empty (no emission)
        assert agent_queues.risk_queue.qsize() == 0
        
        # Verify learning stats were collected
        assert len(agent._learning_stats["packet_rate"]) == 1
        assert agent._learning_stats["packet_rate"][0] == feature_vector.packet_rate
        assert len(agent._learning_stats["byte_rate"]) == 1
        assert agent._learning_stats["byte_rate"][0] == feature_vector.byte_rate

    @pytest.mark.asyncio
    async def test_valid_feature_vector_emits_threat_score_with_if_source(
        self, feature_vector, mock_pipeline, agent_queues
    ):
        """
        Test: valid FeatureVector with loaded IF model emits ThreatScore with source="if"
        Validates: Requirement 7.4
        """
        mock_pipeline.predict_if.return_value = 0.72
        
        agent = AnalysisAgent(pipeline=mock_pipeline)
        agent.learning_mode = False  # Ensure not in learning mode
        
        # Score the feature vector
        result = await agent.score(feature_vector)
        
        # Verify ThreatScore was created
        assert result is not None
        assert isinstance(result, ThreatScore)
        assert result.source == "if"
        assert result.flow_id == feature_vector.flow_id
        assert result.score == 0.72
        assert result.attack_type == "zero_day_anomaly"
        
        # Verify ThreatScore was emitted to risk_queue
        assert agent_queues.risk_queue.qsize() == 1
        queued_score = await agent_queues.risk_queue.get()
        assert queued_score.source == "if"
        assert queued_score.score == 0.72

    @pytest.mark.asyncio
    async def test_learning_period_expiry_establishes_baseline(
        self, feature_vector, mock_pipeline, agent_queues
    ):
        """
        Test: learning period expiry calls establish_baseline and sets learning_mode=False
        Validates: Requirement 7.8
        """
        agent = AnalysisAgent(pipeline=mock_pipeline)
        
        # Enter learning mode with very short duration
        await agent.enter_learning_mode(duration_days=7)
        assert agent.learning_mode is True
        
        # Collect some learning stats
        agent._learning_stats["packet_rate"] = [100.0, 150.0, 200.0]
        agent._learning_stats["byte_rate"] = [30000.0, 45000.0, 60000.0]
        agent._learning_stats["src_ips"] = ["192.168.1.1", "192.168.1.2"]
        
        # Manually expire learning period
        agent._learning_end = datetime.utcnow() - timedelta(seconds=1)
        
        # Call establish_baseline
        baseline = await agent.establish_baseline()
        
        # Verify baseline was created
        assert baseline is not None
        assert baseline.mean_packet_rate == 150.0  # mean of [100, 150, 200]
        assert baseline.mean_byte_rate == 45000.0  # mean of [30000, 45000, 60000]
        assert baseline.active_device_count == 2
        assert baseline.is_active is True
        
        # Verify learning mode was disabled
        assert agent.learning_mode is False

    @pytest.mark.asyncio
    async def test_score_always_in_valid_range(
        self, feature_vector, mock_pipeline, agent_queues
    ):
        """
        Test: anomaly score is always in range [0.0, 1.0]
        Validates: Requirement 7.6
        """
        # Test multiple score values
        test_scores = [0.0, 0.3, 0.5, 0.7, 1.0, 0.6, 0.85]
        
        for score in test_scores:
            mock_pipeline.predict_if.return_value = score
            
            agent = AnalysisAgent(pipeline=mock_pipeline)
            agent.learning_mode = False
            result = await agent.score(feature_vector)
            
            assert result is not None
            assert 0.0 <= result.score <= 1.0, f"Score {result.score} out of range"
            assert result.score == score
            
            # Clear queue for next iteration
            await agent_queues.risk_queue.get()

    @pytest.mark.asyncio
    async def test_low_anomaly_score_has_no_attack_type(
        self, feature_vector, mock_pipeline, agent_queues
    ):
        """
        Test: Low anomaly scores (< 0.6) result in attack_type=None
        """
        mock_pipeline.predict_if.return_value = 0.4
        
        agent = AnalysisAgent(pipeline=mock_pipeline)
        agent.learning_mode = False
        result = await agent.score(feature_vector)
        
        assert result is not None
        assert result.attack_type is None
        assert result.score == 0.4

    @pytest.mark.asyncio
    async def test_high_anomaly_score_has_attack_type(
        self, feature_vector, mock_pipeline, agent_queues
    ):
        """
        Test: High anomaly scores (> 0.6) result in attack_type="zero_day_anomaly"
        """
        mock_pipeline.predict_if.return_value = 0.8
        
        agent = AnalysisAgent(pipeline=mock_pipeline)
        agent.learning_mode = False
        result = await agent.score(feature_vector)
        
        assert result is not None
        assert result.attack_type == "zero_day_anomaly"
        assert result.score == 0.8

    @pytest.mark.asyncio
    async def test_safe_mode_prevents_scoring(
        self, feature_vector, mock_pipeline, agent_queues
    ):
        """
        Test: safe_mode prevents scoring
        """
        mock_pipeline.if_available = False
        
        agent = AnalysisAgent(pipeline=mock_pipeline)
        agent._safe_mode = True
        agent.learning_mode = False
        
        result = await agent.score(feature_vector)
        
        assert result is None
        assert agent_queues.risk_queue.qsize() == 0

    @pytest.mark.asyncio
    async def test_model_load_failure_enters_safe_mode(self, agent_queues):
        """
        Test: Model load failure causes agent to enter safe mode
        """
        mock_pipeline = MagicMock(spec=MLInferencePipeline)
        mock_pipeline.load_models.side_effect = Exception("Model file not found")
        mock_pipeline.if_available = False
        
        agent = AnalysisAgent(pipeline=mock_pipeline)
        await agent._load_model()
        
        assert agent.safe_mode is True

    @pytest.mark.asyncio
    async def test_if_unavailable_enters_safe_mode(self, agent_queues):
        """
        Test: IF model unavailable causes agent to enter safe mode
        """
        mock_pipeline = MagicMock(spec=MLInferencePipeline)
        mock_pipeline.load_models = MagicMock()
        mock_pipeline.if_available = False
        
        agent = AnalysisAgent(pipeline=mock_pipeline)
        await agent._load_model()
        
        assert agent.safe_mode is True

    @pytest.mark.asyncio
    async def test_pipeline_returns_none_does_not_emit(
        self, feature_vector, mock_pipeline, agent_queues
    ):
        """
        Test: When pipeline returns None, no ThreatScore is emitted
        """
        mock_pipeline.predict_if.return_value = None
        
        agent = AnalysisAgent(pipeline=mock_pipeline)
        agent.learning_mode = False
        result = await agent.score(feature_vector)
        
        assert result is None
        assert agent_queues.risk_queue.qsize() == 0

    @pytest.mark.asyncio
    async def test_establish_baseline_with_no_stats_returns_none(self, mock_pipeline):
        """
        Test: establish_baseline with no collected stats returns None
        """
        agent = AnalysisAgent(pipeline=mock_pipeline)
        agent._learning_stats.clear()
        
        baseline = await agent.establish_baseline()
        
        assert baseline is None

    @pytest.mark.asyncio
    async def test_establish_baseline_handles_single_value(self, mock_pipeline):
        """
        Test: establish_baseline handles single value (std dev = 0)
        """
        agent = AnalysisAgent(pipeline=mock_pipeline)
        agent._learning_stats["packet_rate"] = [100.0]
        agent._learning_stats["byte_rate"] = [30000.0]
        agent._learning_stats["src_ips"] = ["192.168.1.1"]
        
        baseline = await agent.establish_baseline()
        
        assert baseline is not None
        assert baseline.mean_packet_rate == 100.0
        assert baseline.std_packet_rate == 0.0
        assert baseline.mean_byte_rate == 30000.0
        assert baseline.std_byte_rate == 0.0


# ---------------------------------------------------------------------------
# Property-Based Tests for AnalysisAgent (Task 9.5)
# ---------------------------------------------------------------------------

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st


# Strategy: generate valid FeatureVectors with arbitrary but realistic values
_feature_vector_strategy = st.builds(
    FeatureVector,
    flow_id=st.text(min_size=1, max_size=64, alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"), whitelist_characters="_-")),
    timestamp=st.just(datetime.utcnow()),
    src_ip=st.just("192.168.1.1"),
    dst_ip=st.just("10.0.0.1"),
    src_port=st.integers(min_value=1, max_value=65535),
    dst_port=st.integers(min_value=1, max_value=65535),
    protocol=st.sampled_from(["TCP", "UDP", "ICMP", "HTTP", "MQTT", "CoAP", "Modbus"]),
    packet_rate=st.floats(min_value=0.0, max_value=1_000_000.0, allow_nan=False, allow_infinity=False),
    byte_rate=st.floats(min_value=0.0, max_value=1_000_000_000.0, allow_nan=False, allow_infinity=False),
    flow_duration=st.floats(min_value=0.0, max_value=3600.0, allow_nan=False, allow_infinity=False),
    tcp_flags=st.sampled_from(["A", "S", "PA", "SA", "R", "F"]),
    connection_errors=st.integers(min_value=0, max_value=1000),
    port_entropy=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
    is_known_iot_port=st.booleans(),
)


class TestAnalysisAgentScoreRangeProperty:
    """
    Property-based tests for AnalysisAgent score normalisation.

    **Validates: Requirements 7.6**
    """

    @given(
        fv=_feature_vector_strategy,
        raw_score=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    def test_anomaly_score_always_normalised(self, fv, raw_score, agent_queues):
        """
        Property 6: Anomaly score is always normalised — 0.0 <= score <= 1.0.

        For any valid FeatureVector and any pipeline score in [0.0, 1.0],
        the ThreatScore emitted by AnalysisAgent must have score in [0.0, 1.0].

        **Validates: Requirements 7.6**
        """
        # Build a mock pipeline whose predict_if returns the hypothesis-generated score
        pipeline = MagicMock(spec=MLInferencePipeline)
        pipeline.lightgbm_available = True
        pipeline.if_available = True
        pipeline.load_models = MagicMock()
        pipeline.predict_if.return_value = raw_score

        agent = AnalysisAgent(pipeline=pipeline)
        agent.learning_mode = False  # Ensure scoring path is active

        result = asyncio.new_event_loop().run_until_complete(agent.score(fv))

        assert result is not None, (
            f"AnalysisAgent.score() returned None for raw_score={raw_score}"
        )
        assert 0.0 <= result.score <= 1.0, (
            f"Score {result.score} is outside [0.0, 1.0] for raw_score={raw_score}"
        )

        # Drain the risk_queue to keep it clean between examples
        while not agent_queues.risk_queue.empty():
            try:
                agent_queues.risk_queue.get_nowait()
            except asyncio.QueueEmpty:
                break


# ---------------------------------------------------------------------------
# Property-Based Tests for AnalysisAgent (Tasks 9.2 and 9.3)
# ---------------------------------------------------------------------------

from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

def feature_vector_strategy():
    """Strategy that generates valid FeatureVectors for property testing."""
    return st.builds(
        FeatureVector,
        flow_id=st.text(min_size=1, max_size=20),
        timestamp=st.just(datetime.utcnow()),
        src_ip=st.ip_addresses(v=4).map(str),
        dst_ip=st.ip_addresses(v=4).map(str),
        src_port=st.integers(min_value=1, max_value=65535),
        dst_port=st.integers(min_value=1, max_value=65535),
        protocol=st.sampled_from(["TCP", "UDP", "ICMP", "HTTP", "MQTT", "CoAP", "Modbus"]),
        packet_rate=st.floats(min_value=0.0, max_value=10000.0, allow_nan=False, allow_infinity=False),
        byte_rate=st.floats(min_value=0.0, max_value=10000.0, allow_nan=False, allow_infinity=False),
        flow_duration=st.floats(min_value=0.0, max_value=10000.0, allow_nan=False, allow_infinity=False),
        tcp_flags=st.sampled_from(["A", "S", "PA", "SA", "R", "F"]),
        connection_errors=st.integers(min_value=0, max_value=1000),
        port_entropy=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
        is_known_iot_port=st.booleans(),
    )


class TestAnalysisAgentProperties:
    """
    Property-based tests for AnalysisAgent.

    **Validates: Requirements 7.5, 7.7**
    """

    @pytest.mark.asyncio
    @given(
        fv=feature_vector_strategy(),
        score=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
        attack_type=st.text(min_size=1, max_size=20),
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    async def test_property_4_score_is_always_valid_probability(
        self, fv, score, attack_type, agent_queues, monkeypatch
    ):
        """
        Property 4: Score is always a valid probability.

        **Validates: Requirements 7.5**

        For any valid FeatureVector and any score returned by the supervised pipeline,
        the ThreatScore emitted by AnalysisAgent must satisfy 0.0 <= score <= 1.0.
        """
        monkeypatch.setattr("backend.agents.analysis_agent.get_queues", lambda: agent_queues)

        mock_pipeline = MagicMock(spec=MLInferencePipeline)
        mock_pipeline.lightgbm_available = True
        mock_pipeline.load_models = MagicMock()
        mock_pipeline.predict_lightgbm.return_value = (attack_type, score)

        agent = AnalysisAgent(pipeline=mock_pipeline)

        result = await agent.classify(fv)

        assert result is not None, "AnalysisAgent must emit a ThreatScore in normal mode"
        assert 0.0 <= result.score <= 1.0, (
            f"ThreatScore.score={result.score} is outside [0.0, 1.0]"
        )

        # Drain the queue to avoid interference between hypothesis examples
        while not agent_queues.risk_queue.empty():
            agent_queues.risk_queue.get_nowait()

    @pytest.mark.asyncio
    @given(
        feature_vectors=st.lists(feature_vector_strategy(), min_size=1, max_size=20),
        score=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
        attack_type=st.text(min_size=1, max_size=20),
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    async def test_property_5_no_silent_drops_in_normal_mode(
        self, feature_vectors, score, attack_type, agent_queues, monkeypatch
    ):
        """
        Property 5: No silent drops in normal mode.

        **Validates: Requirements 7.7**

        When N FeatureVectors are processed by AnalysisAgent in normal mode
        (not safe_mode), exactly N ThreatScores must be emitted to the risk_queue.
        """
        monkeypatch.setattr("backend.agents.analysis_agent.get_queues", lambda: agent_queues)

        mock_pipeline = MagicMock(spec=MLInferencePipeline)
        mock_pipeline.lightgbm_available = True
        mock_pipeline.load_models = MagicMock()
        mock_pipeline.predict_lightgbm.return_value = (attack_type, score)

        agent = AnalysisAgent(pipeline=mock_pipeline)

        # Drain any leftover items from previous examples
        while not agent_queues.risk_queue.empty():
            agent_queues.risk_queue.get_nowait()

        n = len(feature_vectors)
        for fv in feature_vectors:
            result = await agent.classify(fv)
            assert result is not None, (
                "AnalysisAgent must not silently drop FeatureVectors in normal mode"
            )

        emitted = agent_queues.risk_queue.qsize()
        assert emitted == n, (
            f"Expected exactly {n} ThreatScores emitted, got {emitted}"
        )

        # Drain the queue to avoid interference between hypothesis examples
        while not agent_queues.risk_queue.empty():
            agent_queues.risk_queue.get_nowait()


# ---------------------------------------------------------------------------
# Property-Based Tests for AnalysisAgent Score Range (Task 9.2)
# ---------------------------------------------------------------------------


class TestAnalysisAgentPropertyTests:
    """
    Property-based tests for AnalysisAgent score range validation.

    **Validates: Requirements 7.5**
    """

    @pytest.mark.asyncio
    @given(score=st.floats(min_value=0.0, max_value=1.0, allow_nan=False))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    async def test_property_4_score_is_always_valid_probability(
        self, score, agent_queues, monkeypatch
    ):
        """
        Property 4: Score is always a valid probability.

        For any score value in [0.0, 1.0] returned by the supervised pipeline,
        the ThreatScore emitted by AnalysisAgent must satisfy 0.0 <= score <= 1.0.

        **Validates: Requirements 7.5**
        """
        monkeypatch.setattr("backend.agents.analysis_agent.get_queues", lambda: agent_queues)

        # Build a mock pipeline that returns the hypothesis-generated score
        mock_pipeline = MagicMock(spec=MLInferencePipeline)
        mock_pipeline.lightgbm_available = True
        mock_pipeline.load_models = MagicMock()
        mock_pipeline.predict_lightgbm.return_value = ("TestAttack", score)

        # Create a fresh FeatureVector for each example
        feature_vector = FeatureVector(
            flow_id="prop_test_flow",
            timestamp=datetime.utcnow(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.50",
            src_port=54321,
            dst_port=1883,
            protocol="TCP",
            packet_rate=150.0,
            byte_rate=45000.0,
            flow_duration=2.5,
            tcp_flags="PA",
            connection_errors=0,
            port_entropy=0.8,
            is_known_iot_port=True,
        )

        agent = AnalysisAgent(pipeline=mock_pipeline)

        result = await agent.classify(feature_vector)

        assert result is not None, (
            f"AnalysisAgent.classify() returned None for score={score}"
        )
        assert 0.0 <= result.score <= 1.0, (
            f"ThreatScore.score={result.score} is outside [0.0, 1.0] for pipeline score={score}"
        )

        # Drain the risk_queue to avoid interference between hypothesis examples
        while not agent_queues.risk_queue.empty():
            try:
                agent_queues.risk_queue.get_nowait()
            except asyncio.QueueEmpty:
                break


# ---------------------------------------------------------------------------
# Property-Based Tests for AnalysisAgent Score Range (Task 9.2)
# ---------------------------------------------------------------------------


class TestAnalysisAgentScoreRangeProperty:
    """
    Property-based tests for AnalysisAgent score range validation.

    **Validates: Requirements 7.5**

    Property 4: Score is always a valid probability.
    For any valid FeatureVector and any score in [0.0, 1.0] returned by the
    supervised pipeline, the ThreatScore emitted by AnalysisAgent must satisfy
    0.0 <= score <= 1.0.
    """

    @given(
        fv=st.builds(
            FeatureVector,
            flow_id=st.text(
                min_size=1,
                max_size=10,
                alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd")),
            ),
            timestamp=st.just(datetime.utcnow()),
            src_ip=st.just("192.168.1.1"),
            dst_ip=st.just("10.0.0.1"),
            src_port=st.integers(min_value=1, max_value=65535),
            dst_port=st.integers(min_value=1, max_value=65535),
            protocol=st.sampled_from(["TCP", "UDP", "ICMP", "HTTP", "MQTT", "CoAP", "Modbus"]),
            packet_rate=st.floats(min_value=0.0, max_value=1_000_000.0, allow_nan=False, allow_infinity=False),
            byte_rate=st.floats(min_value=0.0, max_value=1_000_000_000.0, allow_nan=False, allow_infinity=False),
            flow_duration=st.floats(min_value=0.0, max_value=3600.0, allow_nan=False, allow_infinity=False),
            tcp_flags=st.sampled_from(["A", "S", "PA", "SA", "R", "F"]),
            connection_errors=st.integers(min_value=0, max_value=1000),
            port_entropy=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
            is_known_iot_port=st.booleans(),
        ),
        score=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
        attack_type=st.text(
            min_size=1,
            max_size=10,
            alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd")),
        ),
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    def test_score_is_always_valid_probability(self, fv, score, attack_type):
        """
        Property 4: Score is always a valid probability.

        For any valid FeatureVector and any score in [0.0, 1.0] returned by
        the supervised pipeline, the ThreatScore emitted by AnalysisAgent must
        satisfy 0.0 <= score <= 1.0.

        **Validates: Requirements 7.5**
        """
        # Build a mock pipeline whose predict_supervised returns the hypothesis-generated score
        mock_pipeline = MagicMock(spec=MLInferencePipeline)
        mock_pipeline.lightgbm_available = True
        mock_pipeline.load_models = MagicMock()
        mock_pipeline.predict_lightgbm.return_value = (attack_type, score)

        # Agent must NOT be in safe_mode
        agent = AnalysisAgent(pipeline=mock_pipeline)
        assert agent._safe_mode is False, "Agent must not be in safe_mode for this property"

        # Create a self-contained event loop with its own queues (hypothesis-safe)
        loop = asyncio.new_event_loop()
        try:
            queues = AgentQueues(
                detection_queue=asyncio.Queue(maxsize=1000),
                anomaly_queue=asyncio.Queue(maxsize=1000),
                risk_queue=asyncio.Queue(maxsize=1000),
                orchestrator_queue=asyncio.PriorityQueue(maxsize=1000),
                prevention_queue=asyncio.Queue(maxsize=1000),
                healing_queue=asyncio.Queue(maxsize=1000),
                logging_queue=asyncio.Queue(maxsize=10000),
            )

            with patch("backend.agents.analysis_agent.get_queues", return_value=queues):
                result = loop.run_until_complete(agent.classify(fv))
        finally:
            loop.close()

        assert result is not None, (
            f"AnalysisAgent.classify() returned None for score={score}; "
            "agent must emit a ThreatScore when not in safe_mode"
        )
        assert 0.0 <= result.score <= 1.0, (
            f"ThreatScore.score={result.score} is outside [0.0, 1.0] "
            f"for pipeline score={score}"
        )


# ---------------------------------------------------------------------------
# Property-Based Tests for AnalysisAgent No Silent Drops (Task 9.3)
# ---------------------------------------------------------------------------


class TestAnalysisAgentNoSilentDropsProperty:
    """
    Property-based tests for AnalysisAgent no-silent-drops guarantee.

    **Validates: Requirements 7.7**

    Property 5: No silent drops in normal mode.
    For any N FeatureVectors processed by AnalysisAgent in normal mode
    (not safe_mode), exactly N ThreatScores must be emitted to the risk_queue.
    """

    @given(
        n=st.integers(min_value=1, max_value=20),
        score=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    def test_property_5_no_silent_drops_in_normal_mode(self, n, score, agent_queues):
        """
        Property 5: No silent drops in normal mode.

        Process N FeatureVectors through AnalysisAgent in normal mode and
        verify exactly N ThreatScores are emitted to the risk_queue.

        **Validates: Requirements 7.7**
        """
        # Build a mock pipeline that returns a fixed (attack_type, score) tuple
        mock_pipeline = MagicMock(spec=MLInferencePipeline)
        mock_pipeline.lightgbm_available = True
        mock_pipeline.load_models = MagicMock()
        mock_pipeline.predict_lightgbm.return_value = ("TestAttack", score)

        agent = AnalysisAgent(pipeline=mock_pipeline)

        # Drain any leftover items from previous hypothesis examples
        while not agent_queues.risk_queue.empty():
            try:
                agent_queues.risk_queue.get_nowait()
            except asyncio.QueueEmpty:
                break

        # Create a single fixed FeatureVector and reuse it N times
        fixed_fv = FeatureVector(
            flow_id="no_drop_prop_test",
            timestamp=datetime.utcnow(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.50",
            src_port=54321,
            dst_port=1883,
            protocol="TCP",
            packet_rate=150.0,
            byte_rate=45000.0,
            flow_duration=2.5,
            tcp_flags="PA",
            connection_errors=0,
            port_entropy=0.8,
            is_known_iot_port=True,
        )

        loop = asyncio.new_event_loop()
        try:
            # Call agent.classify(fv) N times
            for _ in range(n):
                loop.run_until_complete(agent.classify(fixed_fv))
        finally:
            loop.close()

        # Assert exactly N ThreatScores were emitted
        assert agent_queues.risk_queue.qsize() == n, (
            f"Expected exactly {n} ThreatScores in risk_queue, "
            f"got {agent_queues.risk_queue.qsize()}"
        )

        # Drain the queue after the assertion
        while not agent_queues.risk_queue.empty():
            try:
                agent_queues.risk_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
