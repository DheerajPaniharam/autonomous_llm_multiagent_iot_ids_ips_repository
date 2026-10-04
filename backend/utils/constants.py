"""
System-wide constants for the IoT IDS/IPS system.

Centralises all magic strings, numeric thresholds, port numbers, and
category lists so they can be imported from a single location rather
than scattered as literals across the codebase.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Software version
# ---------------------------------------------------------------------------

VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Composite score thresholds
# ---------------------------------------------------------------------------

COMPOSITE_THRESHOLD_DEFAULT: float = 0.65   # minimum score to create an AttackEvent
COMPOSITE_THRESHOLD_HIGH: float = 0.75      # high-severity boundary
COMPOSITE_THRESHOLD_CRITICAL: float = 0.90  # critical-severity boundary

# LightGBM / IF model weight split (must sum to 1.0)
LIGHTGBM_WEIGHT: float = 0.6
IF_WEIGHT: float = 0.4

# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------

SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

SEVERITY_LEVELS = (SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL)

# ---------------------------------------------------------------------------
# Incident states
# ---------------------------------------------------------------------------

INCIDENT_STATE_DETECTED = "detected"
INCIDENT_STATE_ANALYZING = "analyzing"
INCIDENT_STATE_MITIGATING = "mitigating"
INCIDENT_STATE_RESOLVED = "resolved"
INCIDENT_STATE_CLOSED = "closed"

INCIDENT_ACTIVE_STATES = (
    INCIDENT_STATE_DETECTED,
    INCIDENT_STATE_ANALYZING,
    INCIDENT_STATE_MITIGATING,
)

# ---------------------------------------------------------------------------
# Attack categories
# ---------------------------------------------------------------------------

ATTACK_TYPE_DDOS = "ddos"
ATTACK_TYPE_DOS = "dos"
ATTACK_TYPE_PORT_SCAN = "port_scan"
ATTACK_TYPE_BRUTE_FORCE = "brute_force"
ATTACK_TYPE_BOTNET = "botnet"
ATTACK_TYPE_MALWARE = "malware"
ATTACK_TYPE_UNAUTHORIZED_ACCESS = "unauthorized_access"
ATTACK_TYPE_ZERO_DAY = "zero_day_anomaly"
ATTACK_TYPE_BENIGN = "BENIGN"

ALL_ATTACK_TYPES = (
    ATTACK_TYPE_DDOS,
    ATTACK_TYPE_DOS,
    ATTACK_TYPE_PORT_SCAN,
    ATTACK_TYPE_BRUTE_FORCE,
    ATTACK_TYPE_BOTNET,
    ATTACK_TYPE_MALWARE,
    ATTACK_TYPE_UNAUTHORIZED_ACCESS,
    ATTACK_TYPE_ZERO_DAY,
)

# ---------------------------------------------------------------------------
# IoT protocol port numbers
# ---------------------------------------------------------------------------

PORT_MQTT = 1883          # MQTT (unencrypted)
PORT_MQTT_TLS = 8883      # MQTT over TLS
PORT_COAP = 5683          # CoAP (UDP)
PORT_COAP_DTLS = 5684     # CoAP over DTLS
PORT_MODBUS = 502         # Modbus TCP
PORT_BACNET = 47808       # BACnet
PORT_OPCUA = 4840         # OPC-UA
PORT_AMQP = 5672          # AMQP (RabbitMQ)
PORT_HTTP = 80
PORT_HTTPS = 443
PORT_SSH = 22
PORT_TELNET = 23          # Often exploited on IoT devices

KNOWN_IOT_PORTS = frozenset({
    PORT_MQTT, PORT_MQTT_TLS,
    PORT_COAP, PORT_COAP_DTLS,
    PORT_MODBUS, PORT_BACNET,
    PORT_OPCUA, PORT_AMQP,
})

# ---------------------------------------------------------------------------
# Queue names (used in metrics labels)
# ---------------------------------------------------------------------------

QUEUE_DETECTION = "detection"
QUEUE_ANOMALY = "anomaly"
QUEUE_RISK = "risk"
QUEUE_ORCHESTRATOR = "orchestrator"
QUEUE_PREVENTION = "prevention"
QUEUE_HEALING = "healing"
QUEUE_LOGGING = "logging"

ALL_QUEUE_NAMES = (
    QUEUE_DETECTION,
    QUEUE_ANOMALY,
    QUEUE_RISK,
    QUEUE_ORCHESTRATOR,
    QUEUE_PREVENTION,
    QUEUE_HEALING,
    QUEUE_LOGGING,
)

# Default queue capacity (items)
QUEUE_CAPACITY_DEFAULT = 1000
QUEUE_CAPACITY_LOGGING = 10000

# ---------------------------------------------------------------------------
# Agent names
# ---------------------------------------------------------------------------

AGENT_TRAFFIC = "traffic"
AGENT_ANALYSIS = "analysis"
AGENT_ORCHESTRATOR = "orchestrator"
AGENT_RESPONSE = "response"
AGENT_OBSERVABILITY = "observability"

ALL_AGENT_NAMES = (
    AGENT_TRAFFIC,
    AGENT_ANALYSIS,
    AGENT_ORCHESTRATOR,
    AGENT_RESPONSE,
    AGENT_OBSERVABILITY,
)

# ---------------------------------------------------------------------------
# Mitigation actions
# ---------------------------------------------------------------------------

ACTION_BLOCK_IP = "block_ip"
ACTION_RATE_LIMIT = "rate_limit"
ACTION_ISOLATE_DEVICE = "isolate_device"

ALL_MITIGATION_ACTIONS = (ACTION_BLOCK_IP, ACTION_RATE_LIMIT, ACTION_ISOLATE_DEVICE)

# Default TTLs (seconds)
TTL_BLOCK_DEFAULT = 3600       # 1 hour
TTL_RATE_LIMIT_DEFAULT = 1800  # 30 minutes
TTL_ISOLATE_DEFAULT = 7200     # 2 hours

# ---------------------------------------------------------------------------
# Firewall rule comment prefix (used by nftables_manager)
# ---------------------------------------------------------------------------

FIREWALL_BLOCK_PREFIX = "ids-block"
FIREWALL_RATELIMIT_PREFIX = "ids-ratelimit"
FIREWALL_TABLE = "ip"
FIREWALL_CHAIN_INPUT = "INPUT"
FIREWALL_CHAIN_FILTER = "filter"

# ---------------------------------------------------------------------------
# Graceful shutdown timeouts (seconds)
# ---------------------------------------------------------------------------

SHUTDOWN_TIMEOUT_DETECTION_PIPELINE = 30.0
SHUTDOWN_TIMEOUT_PREVENTION_HEALING = 30.0
SHUTDOWN_TIMEOUT_LOGGING = 10.0

# ---------------------------------------------------------------------------
# LLM / Ollama
# ---------------------------------------------------------------------------

LLM_TIMEOUT_SECONDS = 5.0
LLM_DEFAULT_MODEL = "qwen2.5-3b-iot-ids"
LLM_DEFAULT_HOST = "http://localhost:11434"

# ---------------------------------------------------------------------------
# Anomaly agent learning
# ---------------------------------------------------------------------------

ANOMALY_LEARNING_DURATION_DAYS = 7
ANOMALY_SCORE_THRESHOLD = 0.6   # IF scores above this are flagged as anomalous

# ---------------------------------------------------------------------------
# Campaign correlation
# ---------------------------------------------------------------------------

CAMPAIGN_WINDOW_SECONDS = 5
CAMPAIGN_MIN_EVENTS = 3

# ---------------------------------------------------------------------------
# Prometheus metric names (ids_ prefix per Req 13.8)
# ---------------------------------------------------------------------------

METRIC_EVENTS_PROCESSED = "ids_events_processed_total"
METRIC_QUEUE_DEPTH = "ids_queue_depth"
METRIC_ML_LATENCY = "ids_ml_inference_latency_seconds"
METRIC_MITIGATIONS = "ids_mitigations_applied_total"
METRIC_PACKET_DROPS = "ids_packet_drops_total"
METRIC_INCIDENTS_ACTIVE = "ids_incidents_active"

# ---------------------------------------------------------------------------
# API pagination defaults
# ---------------------------------------------------------------------------

PAGINATION_DEFAULT_LIMIT = 50
PAGINATION_MAX_LIMIT = 500
PAGINATION_DEFAULT_OFFSET = 0

# ---------------------------------------------------------------------------
# Log retention
# ---------------------------------------------------------------------------

LOG_RETENTION_DAYS_DEFAULT = 90
LOG_ARCHIVE_BATCH_SIZE = 1000
