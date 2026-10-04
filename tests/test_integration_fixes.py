import asyncio
import json
from datetime import datetime
from pathlib import Path

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

from backend.agents.analysis_agent import AnalysisAgent
from backend.agents.response_agent import ResponseAgent
from backend.ml.feature_extraction import OPTIMIZED_FEATURE_NAMES
from backend.ml.inference import MLInferencePipeline
from backend.ml.isolation_forest_model import IsolationForestModel
from backend.models.messages import FeatureVector, ThreatScore


@pytest.fixture
def sample_feature_vector() -> FeatureVector:
    return FeatureVector(
        flow_id="flow-1",
        timestamp=datetime.utcnow(),
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=12345,
        dst_port=80,
        protocol="TCP",
        packet_rate=10.0,
        byte_rate=1000.0,
        flow_duration=1.0,
        tcp_flags="A",
        connection_errors=0,
        port_entropy=0.5,
        is_known_iot_port=False,
        syn_flag_count=0,
        ack_flag_count=1,
        rst_flag_count=0,
        fwd_packets_per_second=5.0,
        bwd_packets_per_second=5.0,
        packet_length_mean=100.0,
        fwd_packet_length_mean=100.0,
        bwd_packet_length_mean=100.0,
        total_fwd_packets=5,
        total_bwd_packets=5,
        fwd_bytes=500,
        bwd_bytes=500,
    )


def test_detection_agent_preserves_benign_label(sample_feature_vector):
    class FakePipeline:
        def predict_lightgbm(self, fv):
            return ("BENIGN", 0.02)
        
        def load_models(self):
            pass
            
        lightgbm_available = True
        if_available = True

    agent = AnalysisAgent(pipeline=FakePipeline())  # type: ignore[arg-type]
    score = asyncio.run(agent.classify(sample_feature_vector))

    assert score is not None
    assert score.attack_type is None
    assert score.feature_vector is sample_feature_vector


def test_isolation_forest_model_disables_on_feature_mismatch(tmp_path):
    model_path = tmp_path / "legacy_if.joblib"
    metadata_path = tmp_path / "metadata_if_optimized.json"
    X = np.random.default_rng(0).normal(size=(20, 8))
    model = IsolationForest(random_state=0, contamination=0.1)
    model.fit(X)
    model_path.write_bytes(b"")
    joblib = pytest.importorskip("joblib")
    joblib.dump(model, model_path)
    metadata_path.write_text(json.dumps({"feature_names": OPTIMIZED_FEATURE_NAMES[:8]}))

    wrapper = IsolationForestModel()

    with pytest.raises(ValueError, match="requires 17"):
        wrapper.load(model_path)

    assert wrapper.is_loaded is False


def test_healing_agent_skips_repeated_restarts_for_cooldown(sample_feature_vector):
    agent = ResponseAgent()

    async def _run():
        first = await agent._restart_service("suricata")
        second = await agent._restart_service("suricata")
        return first, second

    with pytest.MonkeyPatch.context() as monkeypatch:
        import backend.agents.response_agent as response_agent_module

        async def fake_restart(service, attempt=1):
            return False

        monkeypatch.setattr(response_agent_module, "restart_service", fake_restart)
        first, second = asyncio.run(_run())

    assert first is False
    assert second is False


def test_optimized_metadata_reports_expected_feature_count():
    metadata_path = Path("models/metadata_optimized.json")
    data = json.loads(metadata_path.read_text())
    feature_names = data.get("feature_names", [])

    assert len(feature_names) == 17
    assert feature_names[0] == "packet_rate"
    assert feature_names[-1] == "bwd_bytes"
