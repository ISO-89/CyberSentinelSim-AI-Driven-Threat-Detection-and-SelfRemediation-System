import re
import pickle
import sys
import spacy
from spacy.matcher import Matcher
from config import (
    NB_MODEL_PATH,
    RF_MODEL_PATH,
    VECTORIZER_PATH,
    LABEL_MAP_PATH,
    METADATA_PATH,
    SEVERITY_MAP,
    MITRE_MAP,
    CONFIDENCE_THRESHOLD,
    SEVERITY_WEIGHTS,
)

# ── NLP Entity Extraction Pipeline ──────────────────────────────────────
nlp = spacy.blank("en")
matcher = Matcher(nlp.vocab)

# Pattern to extract IPs
matcher.add("IP", [[{"SHAPE": "ddd.ddd.ddd.ddd"}]])
# Pattern to extract PIDs (e.g., [1234])
matcher.add("PID", [[{"TEXT": {"REGEX": r"^\[\d{3,5}\]$"}}]])
# Pattern to extract Usernames (words preceded by 'for' or 'user=')
matcher.add("USER", [[{"LOWER": {"IN": ["for", "user="]}}, {"IS_ASCII": True, "OP": "?"}]])

def extract_entities(log_line):
    """Uses spaCy NLP rule-matching to extract IOCs and context from logs."""
    doc = nlp(log_line)
    matches = matcher(doc)
    
    entities = {"ip": None, "user": None, "process": None}
    
    for match_id, start, end in matches:
        span = doc[start:end]
        label = nlp.vocab.strings[match_id]
        text = span.text.strip("[]=") # Clean up brackets/equals
        
        if label == "IP" and not entities["ip"]:
            entities["ip"] = text
        elif label == "USER" and not entities["user"]:
            entities["user"] = text
        elif label == "PID" and not entities["process"]:
            # Grab the word immediately before the PID (e.g., 'sshd' or 'nginx')
            if start > 0:
                entities["process"] = doc[start - 1].text.lower()
                
    # Fallback to simple regex if NLP fails to find IP
    if not entities["ip"]:
        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', log_line)
        if ip_match:
            entities["ip"] = ip_match.group(1)
            
    return entities

def _load_pickle(path):
    try:
        with open(path, "rb") as f:
            return pickle.load(f)
    except (FileNotFoundError, pickle.UnpicklingError, EOFError, ModuleNotFoundError) as e:
        print(f"[analyzer] WARNING: could not load {path} — {e}", file=sys.stderr)
        return None

nb_model  = _load_pickle(NB_MODEL_PATH)
rf_model  = _load_pickle(RF_MODEL_PATH)
vectorizer = _load_pickle(VECTORIZER_PATH)
LABEL_MAP  = _load_pickle(LABEL_MAP_PATH)
metadata   = _load_pickle(METADATA_PATH)

_models_loaded = None not in (nb_model, rf_model, vectorizer, LABEL_MAP)

# (Deleted the old extract_ip function here)

def get_geo(ip):
    from services.geo_service import lookup as geo_lookup
    return geo_lookup(ip)


def analyze(log_line):
    if not _models_loaded:
        raise RuntimeError("ML models not loaded...")
        
    # 1. NLP Entity Extraction (Replaces old Regex)
    entities = extract_entities(log_line)
    ip_address = entities["ip"]
    extracted_user = entities["user"]
    extracted_process = entities["process"]
    
    # 2. ML Classification
    log_tfidf = vectorizer.transform([log_line])

    nb_pred = nb_model.predict(log_tfidf)[0]
    nb_probs = nb_model.predict_proba(log_tfidf)[0]
    nb_conf = float(nb_probs.max())
    nb_cat = LABEL_MAP[nb_pred]

    rf_pred = rf_model.predict(log_tfidf)[0]
    rf_probs = rf_model.predict_proba(log_tfidf)[0]
    rf_conf = float(rf_probs.max())
    rf_cat = LABEL_MAP[rf_pred]

    # 3. Ensemble Logic
    models_agree = nb_cat == rf_cat
    if models_agree:
        category = nb_cat
        confidence = (nb_conf + rf_conf) / 2
    else:
        if nb_conf >= rf_conf:
            category = nb_cat
            confidence = nb_conf
        else:
            category = rf_cat
            confidence = rf_conf

    if category == "Normal" or confidence < CONFIDENCE_THRESHOLD:
        label = "Normal"
    else:
        label = "Suspicious"

    # 4. Enrichment
    severity = SEVERITY_MAP.get(category, "Info")
    severity_weight = SEVERITY_WEIGHTS.get(severity, 0)
    mitre = MITRE_MAP.get(category, MITRE_MAP["Normal"])
    
    # NOTICE: We use the IP from step 1 (NLP), we DO NOT call extract_ip() again here
    geo = get_geo(ip_address)

    return {
        "log_line": log_line,
        "label": label,
        "category": category,
        "confidence": confidence,
        "severity": severity,
        "severity_weight": severity_weight,
        "ip_address": ip_address,
        "country": geo["country"],
        "city": geo["city"],
        "latitude": geo["latitude"],
        "longitude": geo["longitude"],
        "mitre_id": mitre["id"],
        "mitre_name": mitre["name"],
        "mitre_tactic": mitre["tactic"],
        "mitre_url": mitre["url"],
        "nb_category": nb_cat,
        "nb_confidence": round(nb_conf, 4),
        "rf_category": rf_cat,
        "rf_confidence": round(rf_conf, 4),
        "models_agree": models_agree,
        # NEW: NLP Extracted Entities
        "extracted_user": extracted_user,
        "extracted_process": extracted_process,
    }