"""
config.py — Central Configuration
Single source of truth for paths, settings, and files
used across the Cyber Sentinel system.
"""

import os
import json


# Base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, "config")


# Directories
DATA_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "models")
DATABASE_DIR = os.path.join(BASE_DIR, "database")
SERVICES_DIR = os.path.join(BASE_DIR, "services")
COMPONENTS_DIR = os.path.join(BASE_DIR, "components")
PAGES_DIR = os.path.join(BASE_DIR, "pages")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")


# Create directories if they don't exist
for directory in [
    DATA_DIR,
    MODELS_DIR,
    DATABASE_DIR,
    SERVICES_DIR,
    COMPONENTS_DIR,
    PAGES_DIR,
    REPORTS_DIR,
]:
    os.makedirs(directory, exist_ok=True)


# Data files
LOG_FILE = os.path.join(DATA_DIR, "system.log")
QUARANTINE_FILE = os.path.join(DATA_DIR, "quarantine.txt")
TRAIN_CSV = os.path.join(DATA_DIR, "train.csv")
TEST_CSV = os.path.join(DATA_DIR, "test.csv")


# Database
DB_PATH = os.path.join(DATABASE_DIR, "app.db")


# Model files
MODEL_PATH = os.path.join(MODELS_DIR, "log_classifier.pkl")
NB_MODEL_PATH = os.path.join(MODELS_DIR, "nb_model.pkl")
RF_MODEL_PATH = os.path.join(MODELS_DIR, "rf_model.pkl")
VECTORIZER_PATH = os.path.join(MODELS_DIR, "vectorizer.pkl")
LABEL_MAP_PATH = os.path.join(MODELS_DIR, "label_map.pkl")
METADATA_PATH = os.path.join(MODELS_DIR, "metadata.pkl")


# Load JSON config files
def _load_json(filename):
    path = os.path.join(CONFIG_DIR, filename)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


_threats = _load_json("threats.json")
_theme = _load_json("theme.json")
_geo_data = _load_json("geo_data.json")
_geo_prefixes = _load_json("geo_prefixes.json")


# PART 4 — DEMO MODE & FEATURE FLAGS

DEMO_MODE = True

FEATURES = {
    "live_log_watcher"   : True,
    "auto_remediation"   : True,
    "llm_explanations"   : True,
    "attack_map"         : True,
    "audit_trail"        : True,
    "cve_feed"           : True,
    "live_apis"          : not DEMO_MODE,
}

DEMO_ATTACK_INTERVAL_MIN = 0.15
DEMO_ATTACK_INTERVAL_MAX = 0.4
DEMO_AUTO_START          = True


# PART 5 — ML / ANALYZER SETTINGS

CONFIDENCE_THRESHOLD    = 0.65
HIGH_CONFIDENCE_CUTOFF  = 0.95
UNKNOWN_LABEL           = "Unknown / Needs Review"

LOG_BUFFER_SIZE         = 500
MAX_LINES_PER_CYCLE     = 50
LOG_POLL_INTERVAL       = 2.0

MODEL_ALGORITHMS = ["naive_bayes", "random_forest"]
PREFERRED_ALGORITHM     = "random_forest"
FALLBACK_ALGORITHM      = "naive_bayes"

VECTORIZER_SETTINGS = {
    "max_features"  : 5000,
    "ngram_range"   : (1, 2),
    "sublinear_tf"  : True,
    "min_df"        : 2,
    "analyzer"      : "word",
    "stop_words"    : "english",
}

RANDOM_FOREST_SETTINGS = {
    "n_estimators"      : 200,
    "max_depth"         : None,
    "min_samples_split" : 2,
    "min_samples_leaf"  : 1,
    "class_weight"      : "balanced",
    "random_state"      : 42,
    "n_jobs"            : -1,
}

NAIVE_BAYES_SETTINGS = {
    "alpha"     : 0.1,
    "fit_prior" : True,
}

TRAINING_SETTINGS = {
    "test_size"         : 0.2,
    "random_state"      : 42,
    "cross_val_folds"   : 5,
    "shuffle"           : True,
}


# PART 6 — THREAT CLASSIFICATION (loaded from config/threats.json)

LABEL_MAP = {
    0: "Normal",
    1: "Brute Force",
    2: "SQL Injection",
    3: "Port Scan",
    4: "Malware Upload",
    5: "Privilege Escalation",
    6: "Unauthorized Access",
}

THREAT_CATEGORIES = _threats.get("categories", [])
SEVERITY_MAP = _threats.get("severity_map", {})
SEVERITY_ORDER = _threats.get("severity_order", {})
SEVERITY_WEIGHTS = _threats.get("severity_weights", {})
MITRE_MAP = _threats.get("mitre_map", {})
REMEDIATION_ACTIONS = _threats.get("remediation_actions", {})
INCIDENT_STATES = _threats.get("incident_states", [])
INCIDENT_STATE_TRANSITIONS = _threats.get("incident_state_transitions", {})
BRUTE_FORCE_THRESHOLD = _threats.get("brute_force_threshold", 5)
PORT_SCAN_THRESHOLD = _threats.get("port_scan_threshold", 10)
ALERT_COOLDOWN_SECONDS = _threats.get("alert_cooldown_seconds", 60)


# DASHBOARD UI CONSTANTS (loaded from config/theme.json)

COLORS = _theme.get("colors", {})
SEVERITY_COLORS = _theme.get("severity_colors", {})
SEVERITY_GLOW = _theme.get("severity_glow", {})

_chart = _theme.get("chart", {})
CHART_TEMPLATE = _chart.get("template", "plotly_dark")
CHART_PAPER_BG = COLORS.get("bg_primary", "#0a0e1a")
CHART_PLOT_BG = COLORS.get("bg_secondary", "#0f1629")
CHART_FONT_COLOR = COLORS.get("text_primary", "#e8eaf6")
CHART_FONT_FAMILY = _chart.get("font_family", "Inter, sans-serif")
CHART_GRID_COLOR = _chart.get("grid_color", "#1e2a45")

_map = _theme.get("map", {})
MAP_STYLE = _map.get("style", "carto-darkmatter")
MAP_ZOOM = _map.get("zoom", 1.5)
MAP_CENTER = _map.get("center", {"lat": 20, "lon": 0})
MAP_ATTACK_COLOR = COLORS.get("critical", "#ff4444")
MAP_NORMAL_COLOR = COLORS.get("accent_blue", "#00d4ff")

_dash = _theme.get("dashboard", {})
DASHBOARD_REFRESH_INTERVAL = _dash.get("refresh_interval", 5)
DASHBOARD_MAX_INCIDENTS = _dash.get("max_incidents", 50)
THREAT_MONITOR_PAGE_SIZE = _dash.get("threat_monitor_page_size", 25)
ACTIVITY_FEED_MAX_ITEMS = _dash.get("activity_feed_max_items", 30)
CHART_HISTORY_HOURS = _dash.get("chart_history_hours", 24)

CATEGORY_COLORS = _theme.get("category_colors", {})
STATUS_COLORS = _theme.get("status_colors", {})

_app = _theme.get("app", {})
APP_NAME = _app.get("name", "Cyber Sentinel")
APP_VERSION = _app.get("version", "1.0.0")
APP_TAGLINE = _app.get("tagline", "Autonomous Threat Detection & Response")
ANALYST_NAME = _app.get("analyst_name", "Analyst")
ANALYST_ROLE = _app.get("analyst_role", "Senior Security Analyst")
ANALYST_AVATAR = _app.get("analyst_avatar", "\U0001f6e1\ufe0f")


# GEO REFERENCE DATA (loaded from config/geo_data.json, config/geo_prefixes.json)

SEED_GEO = _geo_data
SEED_GEO_PREFIXES = _geo_prefixes


# BOOTSTRAP DATABASE

from database.schema import initialise_database
initialise_database()

# Auto-train models if they're missing
if not os.path.exists(NB_MODEL_PATH) or not os.path.exists(RF_MODEL_PATH):
    print("[config] Model files not found. Training models...")
    from train_model import train_models
    train_models()
    print("[config] Model training complete.")

