"""
FastAPI application entry point for the IoT IDS/IPS system.
Implements lifespan management, agent supervision, graceful shutdown, and route registration.
"""
from __future__ import annotations

# Load .env FIRST — before any other imports that read environment variables
from dotenv import load_dotenv
load_dotenv()

import asyncio
import json
import logging
import os
import signal
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import platform
import sklearn
import joblib
import psutil

from backend.agents.analysis_agent import AnalysisAgent
from backend.agents.observability_agent import ObservabilityAgent
from backend.agents.orchestrator import LLMOrchestrator
from backend.agents.response_agent import ResponseAgent
from backend.agents.queues import get_queues
from backend.agents.traffic_agent import TrafficAgent
from backend.api.auth import router as auth_router
from backend.api.health import router as health_router
from backend.api.loki_routes import router as loki_router
from backend.api.routes import router as api_router
from backend.database.connection import close_db, init_db
from backend.ml.inference import MLInferencePipeline
from backend.utils.config_loader import load_config
from backend.api.ws_manager import ws_manager
from backend import metrics as metrics_module

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Version
VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Agent Creation and Management
# ---------------------------------------------------------------------------

def _create_agents(pipeline: MLInferencePipeline, config: Any) -> dict[str, Any]:
    """Create all five agent instances."""
    return {
        "traffic": TrafficAgent(),
        "analysis": AnalysisAgent(pipeline),
        "orchestrator": LLMOrchestrator(composite_threshold=config.composite_threshold),
        "response": ResponseAgent(whitelist=config.whitelist_ips),
        "observability": ObservabilityAgent(),
    }


async def _start_agents(agents: dict[str, Any]) -> dict[str, asyncio.Task]:
    """Start all agents and return their tasks."""
    tasks = {}
    for name, agent in agents.items():
        await agent.start()
        # Get the agent's internal task if it has one
        if hasattr(agent, "_task") and agent._task:
            tasks[name] = agent._task
        else:
            # Create a dummy task that never completes for agents without internal tasks
            tasks[name] = asyncio.create_task(asyncio.sleep(float("inf")))
    logger.info("Started %d agents", len(agents))
    return tasks


async def _supervise_agent(
    name: str,
    agent: Any,
    tasks: dict[str, asyncio.Task],
    restart_counts: dict[str, int],
) -> None:
    """
    Supervise a single agent task and restart on failure.
    Requirements: 1.7
    """
    while True:
        try:
            task = tasks.get(name)
            if task:
                await task
            else:
                # Agent doesn't have a task, just sleep
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            logger.info("Agent supervisor for %s cancelled", name)
            break
        except Exception as exc:
            restart_counts[name] = restart_counts.get(name, 0) + 1
            logger.error(
                "Agent %s crashed: %s - restarting (restart count: %d)",
                name,
                exc,
                restart_counts[name],
                exc_info=True,
            )
            
            if restart_counts[name] > 5:
                logger.warning(
                    "Agent %s has restarted %d times - potential recurring issue",
                    name,
                    restart_counts[name],
                )
            
            # Wait a bit before restarting
            await asyncio.sleep(1)
            
            # Restart the agent
            try:
                await agent.start()
                if hasattr(agent, "_task") and agent._task:
                    tasks[name] = agent._task
                logger.info("Agent %s restarted successfully", name)
            except Exception as restart_exc:
                logger.error(
                    "Failed to restart agent %s: %s",
                    name,
                    restart_exc,
                    exc_info=True,
                )
                await asyncio.sleep(5)  # Wait longer before next attempt


async def _start_supervisors(
    agents: dict[str, Any],
    tasks: dict[str, asyncio.Task],
) -> list[asyncio.Task]:
    """Start supervisor tasks for all agents."""
    restart_counts: dict[str, int] = {}
    supervisors = []
    
    for name, agent in agents.items():
        supervisor = asyncio.create_task(
            _supervise_agent(name, agent, tasks, restart_counts)
        )
        supervisors.append(supervisor)
    
    logger.info("Started %d agent supervisors", len(supervisors))
    return supervisors


# ---------------------------------------------------------------------------
# Graceful Shutdown
# ---------------------------------------------------------------------------

async def _drain_queue(queue: asyncio.Queue, name: str, timeout: float) -> bool:
    """
    Drain a queue with timeout.
    Returns True if drained successfully, False if timed out.
    """
    try:
        await asyncio.wait_for(queue.join(), timeout=timeout)
        logger.info("Queue %s drained successfully", name)
        return True
    except asyncio.TimeoutError:
        remaining = queue.qsize()
        logger.warning(
            "Queue %s drain timeout after %.1fs - %d items remaining",
            name,
            timeout,
            remaining,
        )
        return False


async def _graceful_shutdown(
    agents: dict[str, Any],
    supervisors: list[asyncio.Task],
) -> dict[str, Any]:
    """
    Gracefully shutdown all agents with queue draining.
    Requirements: 1.5, 1.6, 12.1, 12.2, 12.3, 12.4, 12.5, 12.6
    """
    start_time = datetime.utcnow()
    timeout_info: dict[str, Any] = {"timed_out_queues": []}
    
    logger.info("Starting graceful shutdown sequence")
    
    # Step 1: Stop Traffic_Agent first to prevent new events (Req 12.1)
    if "traffic" in agents:
        logger.info("Stopping Traffic_Agent to prevent new events")
        await agents["traffic"].stop()
    
# Step 2: Drain detection/anomaly/risk/orchestrator queues concurrently (Req 12.2)
    queues = get_queues()
    logger.info("Draining detection pipeline queues (30s timeout)")

    drain_results = await asyncio.gather(
        _drain_queue(queues.detection_queue, "detection", 30.0),
        _drain_queue(queues.anomaly_queue, "anomaly", 30.0),
        _drain_queue(queues.risk_queue, "risk", 30.0),
        _drain_queue(queues.orchestrator_queue, "orchestrator", 30.0),
        return_exceptions=True,
    )

    for name, result in zip(
        ["detection", "anomaly", "risk", "orchestrator"], drain_results
    ):
        if result is False or isinstance(result, Exception):
            timeout_info["timed_out_queues"].append(name)

    # Stop analysis and orchestrator agents
    for agent_name in ["analysis", "orchestrator"]:
        if agent_name in agents:
            await agents[agent_name].stop()
    
    # Step 3: Drain prevention/healing queues (Req 12.3)
    logger.info("Draining prevention and healing queues (30s timeout)")
    
    drain_results = await asyncio.gather(
        _drain_queue(queues.prevention_queue, "prevention", 30.0),
        _drain_queue(queues.healing_queue, "healing", 30.0),
        return_exceptions=True,
    )
    
    for i, (name, result) in enumerate(zip(["prevention", "healing"], drain_results)):
        if not result:
            timeout_info["timed_out_queues"].append(name)
    
# Stop response agent
    if "response" in agents:
        await agents["response"].stop()
    
    # Step 4: Drain logging queue (Req 12.4)
    logger.info("Draining logging queue (10s timeout)")
    
    if not await _drain_queue(queues.logging_queue, "logging", 10.0):
        timeout_info["timed_out_queues"].append("logging")
    
    # Stop observability agent
    if "observability" in agents:
        await agents["observability"].stop()
    
    # Cancel all supervisors
    logger.info("Cancelling agent supervisors")
    for supervisor in supervisors:
        supervisor.cancel()
    
    await asyncio.gather(*supervisors, return_exceptions=True)
    
    # Calculate total drain time
    end_time = datetime.utcnow()
    total_drain_time = (end_time - start_time).total_seconds()
    timeout_info["total_drain_time_seconds"] = total_drain_time
    
    logger.info("Graceful shutdown completed in %.2fs", total_drain_time)
    
    return timeout_info


def _log_startup(model_paths: dict[str, str], agent_count: int) -> None:
    """
    Log structured JSON startup message.
    Requirements: 1.9
    """
    # Include runtime and training metadata for diagnostics
    training_version = None
    meta_candidates = ["models/metadata_optimized.json", "models/metadata.json"]
    for m in meta_candidates:
        try:
            with open(m, 'r') as f:
                data = json.load(f)
                training_version = data.get('version')
                break
        except Exception:
            continue

    message = {
        "event": "startup",
        "version": VERSION,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "model_paths": model_paths,
        "agent_count": agent_count,
        "python_version": platform.python_version(),
        "sklearn_version": sklearn.__version__,
        "joblib_version": getattr(joblib, '__version__', 'unknown'),
        "model_training_version": training_version,
    }
    logger.info("STARTUP: %s", json.dumps(message))


def _log_shutdown(timeout_info: dict[str, Any]) -> None:
    """
    Log structured JSON shutdown message.
    Requirements: 12.6
    """
    message = {
        "event": "shutdown",
        "version": VERSION,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "total_drain_time_seconds": timeout_info.get("total_drain_time_seconds", 0),
        "timed_out_queues": timeout_info.get("timed_out_queues", []),
    }
    logger.info("SHUTDOWN: %s", json.dumps(message))


# ---------------------------------------------------------------------------
# Admin user seeding
# ---------------------------------------------------------------------------

async def _seed_admin_user() -> None:
    """
    Create an admin user on first startup when credentials are configured.
    """
    username = os.environ.get("ADMIN_USERNAME", "").strip()
    password = os.environ.get("ADMIN_PASSWORD", "")
    if not username or not password.strip() or len(password) < 12:
        logger.warning(
            "Skipping admin user seeding: set ADMIN_USERNAME and an ADMIN_PASSWORD of at least 12 characters"
        )
        return

    from sqlalchemy import select, func
    from backend.database.connection import session_context
    from backend.database.models import UserModel
    from backend.api.auth import AuthService

    try:
        async with session_context() as session:
            count = await session.scalar(select(func.count()).select_from(UserModel))
            if count and count > 0:
                return  # Users already exist — skip seeding

            password_hash = AuthService.hash_password(password)
            user = UserModel(username=username, password_hash=password_hash, role="admin")
            session.add(user)
            logger.info(
                "Seeded default admin user '%s' — change the password after first login", username
            )
    except Exception as exc:
        logger.warning("Admin user seeding failed (non-fatal): %s", exc)


async def _seed_mock_devices() -> None:
    """
    Seed mock IoT devices on startup to populate the devices page.
    """
    from sqlalchemy import select, func
    from backend.database.connection import session_context
    from backend.database.models import IoTDeviceModel
    from datetime import datetime as _dt

    try:
        async with session_context() as session:
            count = await session.scalar(select(func.count()).select_from(IoTDeviceModel))
            if count and count > 0:
                return  # Devices already exist

            now = _dt.utcnow()
            devices = [
                IoTDeviceModel(
                    device_id="smart-thermostat-01",
                    ip_address="192.168.1.100",
                    mac_address="00:1A:2B:3C:4D:5E",
                    device_type="sensor",
                    protocols=["MQTT", "TCP"],
                    first_seen=now,
                    last_seen=now,
                    is_isolated=False,
                    baseline_packet_rate=12.5,
                    baseline_byte_rate=1024.0,
                ),
                IoTDeviceModel(
                    device_id="security-camera-02",
                    ip_address="192.168.1.101",
                    mac_address="00:1A:2B:3C:4D:5F",
                    device_type="camera",
                    protocols=["RTSP", "HTTP", "TCP"],
                    first_seen=now,
                    last_seen=now,
                    is_isolated=False,
                    baseline_packet_rate=45.0,
                    baseline_byte_rate=81920.0,
                ),
                IoTDeviceModel(
                    device_id="smart-lock-03",
                    ip_address="192.168.1.102",
                    mac_address="00:1A:2B:3C:4D:60",
                    device_type="actuator",
                    protocols=["CoAP", "UDP"],
                    first_seen=now,
                    last_seen=now,
                    is_isolated=False,
                    baseline_packet_rate=2.0,
                    baseline_byte_rate=256.0,
                ),
            ]
            session.add_all(devices)
            logger.info("Seeded %d mock IoT devices", len(devices))
    except Exception as exc:
        logger.warning("IoT devices seeding failed (non-fatal): %s", exc)


# ---------------------------------------------------------------------------
# Mock traffic injection
# ---------------------------------------------------------------------------

async def _run_mock_traffic(agents: dict[str, Any]) -> None:
    """
    Inject synthetic FeatureVectors into the detection pipeline when
    MOCK_DATA_ENABLED=true. Rate controlled by MOCK_TRAFFIC_RATE (events/sec).
    """
    import random
    from datetime import datetime as _dt
    from backend.models.messages import FeatureVector
    from backend.models.messages import compute_flow_id
    from backend.agents.queues import get_queues, safe_put

    rate = int(os.environ.get("MOCK_TRAFFIC_RATE", "10"))
    interval = 1.0 / max(rate, 1)

    ATTACK_TYPES_CHANCE = [
        ("BENIGN", 0.70),
        ("DDoS", 0.08),
        ("PortScan", 0.07),
        ("DoS Hulk", 0.05),
        ("Bot", 0.04),
        ("Infiltration", 0.03),
        ("Web Attack", 0.03),
    ]
    PROTOCOLS = ["TCP", "UDP", "ICMP", "MQTT", "CoAP"]
    FLAGS = ["S", "SA", "PA", "A", "R"]

    logger.info("Mock traffic injector started at %d events/sec", rate)

    try:
        while True:
            now = _dt.utcnow()
            # 50% chance to simulate traffic/attack from one of the seeded mock devices
            if random.random() < 0.5:
                src_ip = random.choice(["192.168.1.100", "192.168.1.101", "192.168.1.102"])
            else:
                src_ip = f"192.168.{random.randint(1,10)}.{random.randint(1,254)}"
            dst_ip = f"10.0.{random.randint(0,5)}.{random.randint(1,50)}"
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 1883, 5683, 502, 8080, 22, 23, 3389])
            protocol = random.choice(PROTOCOLS)

            # Bias packet/byte rates for attack types
            r = random.random()
            cumulative = 0.0
            attack_label = "BENIGN"
            for label, prob in ATTACK_TYPES_CHANCE:
                cumulative += prob
                if r <= cumulative:
                    attack_label = label
                    break

            if attack_label != "BENIGN":
                packet_rate = random.uniform(50000, 200000)
                byte_rate = random.uniform(5000000, 20000000)
            else:
                packet_rate = random.uniform(1, 100)
                byte_rate = random.uniform(100, 10000)

            fv = FeatureVector(
                flow_id=compute_flow_id(src_ip, src_port, dst_ip, dst_port, protocol, now),
                timestamp=now,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_rate=packet_rate,
                byte_rate=byte_rate,
                flow_duration=random.uniform(0.1, 60.0),
                tcp_flags=random.choice(FLAGS),
                connection_errors=random.randint(5, 20) if attack_label != "BENIGN" else 0,
                port_entropy=random.uniform(0.0, 4.0),
                is_known_iot_port=dst_port in {1883, 8883, 5683, 5684, 502, 47808},
            )

            queues = get_queues()
            await safe_put(queues.detection_queue, fv, drop_counter=True)
            await safe_put(queues.anomaly_queue, fv, drop_counter=True)

            # Record TrafficAgent throughput and network bytes/packets
            metrics_module.increment_events_processed("TrafficAgent")
            
            bytes_count = (fv.fwd_bytes or 0.0) + (fv.bwd_bytes or 0.0)
            if bytes_count <= 0.0:
                bytes_count = (fv.byte_rate or 0.0) * max(fv.flow_duration or 0.0, 0.1)
            
            packets_count = (fv.total_fwd_packets or 0.0) + (fv.total_bwd_packets or 0.0)
            if packets_count <= 0.0:
                packets_count = (fv.packet_rate or 0.0) * max(fv.flow_duration or 0.0, 0.1)
                
            metrics_module.add_network_stats(bytes_count, packets_count)

            traffic_agent = agents.get("traffic")
            if traffic_agent is not None and hasattr(traffic_agent, "_recent_flows"):
                traffic_agent._recent_flows.append(fv)
                try:
                    traffic_agent._flow_broadcast_buffer.append({
                        "flow_id": fv.flow_id,
                        "timestamp": fv.timestamp.isoformat() if hasattr(fv.timestamp, "isoformat") else str(fv.timestamp),
                        "src_ip": fv.src_ip,
                        "dst_ip": fv.dst_ip,
                        "src_port": fv.src_port,
                        "dst_port": fv.dst_port,
                        "protocol": fv.protocol,
                        "packet_rate": fv.packet_rate,
                        "byte_rate": fv.byte_rate,
                        "flow_duration": fv.flow_duration,
                        "tcp_flags": fv.tcp_flags,
                        "connection_errors": fv.connection_errors,
                        "is_known_iot_port": fv.is_known_iot_port,
                    })
                except Exception:
                    pass

            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        logger.info("Mock traffic injector stopped")


async def _log_infra_metrics_task() -> None:
    """
    Periodically collect and log infrastructure metrics (CPU, memory, disk, network)
    to the system log file so they are parsed by Promtail/Loki.
    """
    from backend.logs_module.file_logger import write_to_log_file
    from backend.models.messages import LogEntry

    # Warm up CPU percent calculation
    psutil.cpu_percent(interval=None)

    logger.info("Infrastructure metrics logging task started")
    try:
        while True:
            await asyncio.sleep(60)
            try:
                cpu = psutil.cpu_percent(interval=None)
                mem = psutil.virtual_memory().percent
                disk = psutil.disk_usage("/").percent
                
                # Get network stats
                net = psutil.net_io_counters()
                
                entry = LogEntry(
                    level="info",
                    source_agent="system",
                    event_type="infra_metrics",
                    payload={
                        "cpu_percent": cpu,
                        "memory_percent": mem,
                        "disk_percent": disk,
                        "network_bytes_sent": net.bytes_sent,
                        "network_bytes_recv": net.bytes_recv,
                    },
                    timestamp=datetime.utcnow(),
                )
                await write_to_log_file(entry)
            except Exception as exc:
                logger.warning("Failed to collect infrastructure metrics: %s", exc)
    except asyncio.CancelledError:
        logger.info("Infrastructure metrics logging task stopped")


# ---------------------------------------------------------------------------
# Lifespan Context Manager
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager for startup and shutdown.
    Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.9
    """
    # Startup sequence
    logger.info("Starting IoT IDS/IPS System v%s", VERSION)
    
    # 1. Initialize database (Req 1.4)
    logger.info("Initializing database connection pool")
    await init_db()
    
    # 2. Initialize AgentQueues singleton (Req 1.1)
    logger.info("Initializing agent queues")
    get_queues()
    
    # 3. Load ML models (Req 1.2)
    logger.info("Loading ML models")
    pipeline = MLInferencePipeline()
    
    # Get model paths from environment or use optimized defaults.
    # Environment variables allow runtime configuration without code changes.
    # Optimized models are preferred for better performance and memory efficiency.
    supervised_path = os.environ.get("LGB_MODEL_PATH", "models/lgb_model_optimized.joblib")
    if_path = os.environ.get("IF_MODEL_PATH", "models/if_model_optimized.joblib")
    scaler_path = os.environ.get("SCALER_PATH", "models/scaler_optimized.joblib")
    
    pipeline.load_models(supervised_path, if_path, scaler_path)
    
    model_paths = {
        "lightgbm_model": supervised_path,
        "if_model": if_path,
        "scaler": scaler_path,
    }
    
    # 4. Load system configuration
    logger.info("Loading system configuration")
    try:
        config = load_config()
    except Exception as exc:
        logger.warning("Failed to load config, using defaults: %s", exc)
        from backend.utils.config_loader import SystemConfig
        config = SystemConfig()
    
    # 5. Create and start agents (Req 1.3)
    logger.info("Creating agents")
    agents = _create_agents(pipeline, config)
    
    logger.info("Starting agents")
    agent_tasks = await _start_agents(agents)
    
    # 6. Start agent supervisors (Req 1.7)
    supervisors = await _start_supervisors(agents, agent_tasks)
    
    # 7. Store state in app
    app.state.agents = agents
    app.state.agent_tasks = agent_tasks
    app.state.supervisors = supervisors
    app.state.pipeline = pipeline
    app.state.config = config
    app.state.ollama_url = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    
    # 8. Log structured startup message (Req 1.9)
    _log_startup(model_paths, len(agents))

    # 9. Seed default admin user if no users exist
    await _seed_admin_user()
    await _seed_mock_devices()

    # 10. Start mock traffic injector if enabled
    mock_task = None
    if os.environ.get("MOCK_DATA_ENABLED", "false").lower() == "true":
        mock_task = asyncio.create_task(_run_mock_traffic(agents))

    # Start periodic metrics broadcaster task
    async def _metrics_broadcaster(app: FastAPI):
        last_bytes = 0
        last_packets = 0
        last_time = datetime.utcnow()
        try:
            while True:
                try:
                    queues = get_queues()
                    queue_depths = {
                        "detection": queues.detection_queue.qsize(),
                        "anomaly": queues.anomaly_queue.qsize(),
                        "risk": queues.risk_queue.qsize(),
                        "orchestrator": queues.orchestrator_queue.qsize(),
                        "prevention": queues.prevention_queue.qsize(),
                        "healing": queues.healing_queue.qsize(),
                        "logging": queues.logging_queue.qsize(),
                    }

                    ml_raw = metrics_module.get_ml_latency_stats()
                    # Normalise to the shape the dashboard expects:
                    # { lightgbm_p50, lightgbm_p95, lightgbm_p99, if_p50, if_p95, if_p99 }
                    lightgbm = ml_raw.get("lightgbm", {"p50": 0.0, "p95": 0.0, "p99": 0.0})
                    if_ = ml_raw.get("if", {"p50": 0.0, "p95": 0.0, "p99": 0.0})
                    ml_latency_ms = {
                        "lightgbm_p50": lightgbm.get("p50", 0.0),
                        "lightgbm_p95": lightgbm.get("p95", 0.0),
                        "lightgbm_p99": lightgbm.get("p99", 0.0),
                        "if_p50": if_.get("p50", 0.0),
                        "if_p95": if_.get("p95", 0.0),
                        "if_p99": if_.get("p99", 0.0),
                    }

                    events_by_agent = metrics_module.get_events_processed()
                    total_events = sum(events_by_agent.values())
                    mitigations_by_action = metrics_module.get_mitigations_applied()
                    total_mitigations = sum(mitigations_by_action.values())
                    packet_drops = metrics_module.get_packet_drops()

                    # Calculate network throughput rates (kbps & pps)
                    now = datetime.utcnow()
                    curr_bytes, curr_packets = metrics_module.get_network_stats()
                    elapsed = (now - last_time).total_seconds()
                    
                    if elapsed > 0:
                        kbps = max(((curr_bytes - last_bytes) * 8.0 / 1000.0) / elapsed, 0.0)
                        pps = max((curr_packets - last_packets) / elapsed, 0.0)
                    else:
                        kbps = 0.0
                        pps = 0.0
                        
                    last_bytes = curr_bytes
                    last_packets = curr_packets
                    last_time = now
                    
                    metrics_module.update_current_rates(kbps, pps)

                    # Count active in-memory incidents from orchestrator
                    active_incidents = 0
                    orchestrator = app.state.agents.get("orchestrator") if hasattr(app.state, "agents") else None
                    if orchestrator and hasattr(orchestrator, "_incidents"):
                        active_incidents = sum(
                            1 for inc in orchestrator._incidents.values()
                            if hasattr(inc, "state") and str(inc.state) not in (
                                "resolved", "closed",
                                "IncidentState.RESOLVED", "IncidentState.CLOSED",
                            )
                        )

                    payload = {
                        "queue_depths": queue_depths,
                        "ml_latency_ms": ml_latency_ms,
                        "total_events_processed": total_events,
                        "total_mitigations_applied": total_mitigations,
                        "packet_drops": packet_drops,
                        "active_incidents": active_incidents,
                        "agent_throughput": {
                            "TrafficAgent": events_by_agent.get("TrafficAgent", 0),
                            "AnalysisAgent": events_by_agent.get("AnalysisAgent", 0),
                            "LLMOrchestrator": events_by_agent.get("LLMOrchestrator", 0),
                            "ResponseAgent": events_by_agent.get("ResponseAgent", 0),
                            "ObservabilityAgent": events_by_agent.get("ObservabilityAgent", 0),
                        },
                        "network_throughput": {
                            "kbps": round(kbps, 2),
                            "pps": round(pps, 2),
                        },
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                    }
                    await ws_manager.broadcast({"type": "metrics", "payload": payload})
                except Exception:
                    pass
                await asyncio.sleep(5)
        except asyncio.CancelledError:
            return

    metrics_task = asyncio.create_task(_metrics_broadcaster(app))
    infra_metrics_task = asyncio.create_task(_log_infra_metrics_task())
    
    logger.info("IoT IDS/IPS System startup complete - ready to accept requests")
    
    # Yield control to FastAPI
    yield
    # Cancel metrics broadcaster
    try:
        metrics_task.cancel()
        await metrics_task
    except asyncio.CancelledError:
        pass
    except Exception:
        pass

    # Cancel infrastructure metrics logging task
    try:
        infra_metrics_task.cancel()
        await infra_metrics_task
    except asyncio.CancelledError:
        pass
    except Exception:
        pass

    # Cancel mock traffic task if running
    if mock_task:
        mock_task.cancel()
        try:
            await mock_task
        except asyncio.CancelledError:
            pass
        except Exception:
            pass
    
    # Shutdown sequence
    logger.info("Received shutdown signal")
    
    # Graceful shutdown with queue draining (Req 1.5, 1.6, 12.1-12.6)
    timeout_info = await _graceful_shutdown(agents, supervisors)
    
    # Close database (Req 1.6)
    logger.info("Closing database connection pool")
    await close_db()
    
    # Log structured shutdown message (Req 12.6)
    _log_shutdown(timeout_info)
    
    logger.info("IoT IDS/IPS System shutdown complete")


# ---------------------------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------------------------

# Create FastAPI application with lifespan
app = FastAPI(
    title="IoT IDS/IPS System",
    description="Intrusion Detection and Prevention System for IoT Networks",
    version=VERSION,
    lifespan=lifespan,
)

# Configure CORS (Req 15.6)
cors_origins = os.environ.get("CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
# Authentication routes
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])

# API routes
app.include_router(api_router, prefix="/api/v1", tags=["API"])

# Health check routes
app.include_router(health_router, tags=["Health"])

# Loki proxy routes (search)
app.include_router(loki_router, prefix="/loki", tags=["Loki"])


# ---------------------------------------------------------------------------
# Global Exception Handler (Req 15.5)
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Catch-all exception handler.
    Returns HTTP 500 with structured error body and logs full traceback.
    Requirements: 15.5
    """
    logger.error("Unhandled exception on %s %s: %s", request.method, request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


logger.info("FastAPI application initialized with lifespan management")
