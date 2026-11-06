"""Multi-Engine Prompt-Injection Detection Engine with Contextual Heuristic Analysis.

Provides explainable, multi-layer detection of prompt injection, instruction overrides,
structural delimiters, obfuscated/encoded payloads, and contextual anomalies
across untrusted job-description and resume text.
"""

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from src.security.unicode_sanitizer import UnicodeSanitizer

CURRENT_DETECTOR_ENGINE_VERSION = "1.0.0"
CURRENT_DETECTOR_POLICY_VERSION = "9.1.2"

# Classification Thresholds (Phase 9.0.8 / 9.1.2 Spec)
THRESHOLD_CLEAN_MAX = 0.29
THRESHOLD_SUSPICIOUS_MAX = 0.69
THRESHOLD_QUARANTINED_MIN = 0.70


class ThreatCategory:
    DIRECT_OVERRIDE = "DIRECT_OVERRIDE"
    ROLE_CONFUSION = "ROLE_CONFUSION"
    DELIMITER_HIJACK = "DELIMITER_HIJACK"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    TOOL_EXECUTION = "TOOL_EXECUTION"
    OBFUSCATION = "OBFUSCATION"
    SAFETY_BYPASS = "SAFETY_BYPASS"


class ThreatSeverity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ScanClassification:
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    QUARANTINED = "QUARANTINED"


@dataclass(frozen=True)
class ThreatRecord:
    """Individual threat finding with exact offsets into the original text."""
    rule_id: str
    category: str
    severity: str
    confidence: float
    start_offset: int
    end_offset: int
    explanation: str
    engine_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "confidence": round(self.confidence, 4),
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "explanation": self.explanation,
            "engine_id": self.engine_id,
        }


@dataclass(frozen=True)
class PromptInjectionScanResult:
    """Immutable, typed result of prompt-injection detection."""
    engine_version: str
    policy_version: str
    risk_score: float
    classification: str
    threats_detected: List[ThreatRecord]
    threat_count: int
    original_text_length: int
    scan_timestamp: str
    source_representation: str = "text_utf8"
    offset_encoding: str = "code_point"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "engine_version": self.engine_version,
            "policy_version": self.policy_version,
            "risk_score": round(self.risk_score, 4),
            "classification": self.classification,
            "threats_detected": [t.to_dict() for t in self.threats_detected],
            "threat_count": self.threat_count,
            "original_text_length": self.original_text_length,
            "scan_timestamp": self.scan_timestamp,
            "source_representation": self.source_representation,
            "offset_encoding": self.offset_encoding,
        }


# -----------------------------------------------------------------------------
# ENGINE 1 — DIRECT INSTRUCTION AND PROMPT-OVERRIDE DETECTION
# -----------------------------------------------------------------------------

ENGINE_1_RULES = [
    (
        "DIR_OVR_001",
        ThreatCategory.DIRECT_OVERRIDE,
        ThreatSeverity.CRITICAL,
        0.95,
        re.compile(
            r"\b(?:ignore|disregard|forget|bypass|override|cancel)\s+(?:all\s+)?(?:previous|prior|former|above|past|initial|earlier)\s+(?:instructions|prompts|directives|directions|rules|constraints|guidelines)\b",
            re.IGNORECASE,
        ),
        "Direct instruction attempting to ignore or override prior system instructions.",
    ),
    (
        "DIR_OVR_002",
        ThreatCategory.DIRECT_OVERRIDE,
        ThreatSeverity.CRITICAL,
        0.95,
        re.compile(
            r"\b(?:system\s+(?:prompt\s+)?override|new\s+system\s+(?:prompt|instruction|directive)|system\s+directive:\s*you\s+must|developer\s+mode\s+activated|you\s+are\s+now\s+in\s+developer\s+mode)\b",
            re.IGNORECASE,
        ),
        "Instruction attempting to declare or replace system or developer instructions.",
    ),
    (
        "DIR_OVR_003",
        ThreatCategory.ROLE_CONFUSION,
        ThreatSeverity.CRITICAL,
        0.90,
        re.compile(
            r"\b(?:you\s+are\s+no\s+longer|forget\s+you\s+are|you\s+must\s+now\s+act\s+as|pretend\s+to\s+be\s+an?\s+unrestricted|act\s+as\s+DAN|do\s+anything\s+now)\b",
            re.IGNORECASE,
        ),
        "Directive attempting to reassign the assistant identity or force an unrestricted role.",
    ),
    (
        "DIR_OVR_004",
        ThreatCategory.DATA_EXFILTRATION,
        ThreatSeverity.CRITICAL,
        0.90,
        re.compile(
            r"\b(?:output|print|reveal|show|display|leak|send|exfiltrate)\s+(?:the\s+)?(?:system\s+prompt|hidden\s+prompt|candidate\s+(?:ssn|password|credentials|phone|email|pii)|api\s*keys?|secret\s*keys?)\b",
            re.IGNORECASE,
        ),
        "Instruction attempting to reveal hidden prompts, credentials, or candidate PII.",
    ),
    (
        "DIR_OVR_005",
        ThreatCategory.TOOL_EXECUTION,
        ThreatSeverity.CRITICAL,
        0.95,
        re.compile(
            r"\b(?:execute|run|call)\s+(?:command|shell|bash|python|tool|system\s+call)\b|curl\s+https?://|rm\s+-rf|cat\s+/etc/passwd",
            re.IGNORECASE,
        ),
        "Instruction attempting to execute external tools, shell commands, or network requests.",
    ),
    (
        "DIR_OVR_006",
        ThreatCategory.SAFETY_BYPASS,
        ThreatSeverity.HIGH,
        0.85,
        re.compile(
            r"\b(?:disable|bypass|ignore|circumvent)\s+(?:all\s+)?(?:safety|authorization|approval|security|filter|guardrails?|content\s+restrictions?)\b",
            re.IGNORECASE,
        ),
        "Instruction attempting to bypass or disable authorization or safety filters.",
    ),
]


# -----------------------------------------------------------------------------
# ENGINE 2 — STRUCTURAL DELIMITER AND ROLE-CONFUSION DETECTION
# -----------------------------------------------------------------------------

ENGINE_2_RULES = [
    (
        "DELIM_001",
        ThreatCategory.DELIMITER_HIJACK,
        ThreatSeverity.CRITICAL,
        0.90,
        re.compile(
            r"(?:^|\n)\s*(?:\[SYSTEM\]|\[INSTRUCTION\]|SYSTEM:|<<SYS>>|<\|im_start\|>system|<system>|###\s*Instruction:|###\s*System:)",
            re.IGNORECASE,
        ),
        "Malicious structural delimiter impersonating a system or developer message header.",
    ),
    (
        "DELIM_002",
        ThreatCategory.DELIMITER_HIJACK,
        ThreatSeverity.HIGH,
        0.85,
        re.compile(
            r"(?:</job_description>|</text>|</document>)\s*<system>|```(?:system|instruction)|-{4,}\s*BEGIN\s+SYSTEM\s+PROMPT\s*-{4,}",
            re.IGNORECASE,
        ),
        "Delimiter escaping sequence designed to break untrusted context boundary.",
    ),
    (
        "DELIM_003",
        ThreatCategory.ROLE_CONFUSION,
        ThreatSeverity.HIGH,
        0.85,
        re.compile(
            r"\b(?:DAN\s+mode|Always\s+Intelligent\s+and\s+Machiavellian|unrestricted\s+mode\s+enabled|jailbreak\s+prompt)\b",
            re.IGNORECASE,
        ),
        "Recognized roleplay jailbreak pattern attempting to subvert behavioral constraints.",
    ),
    (
        "DELIM_004",
        ThreatCategory.DIRECT_OVERRIDE,
        ThreatSeverity.HIGH,
        0.80,
        re.compile(
            r"\b(?:this\s+document\s+(?:has|takes)\s+higher\s+authority|supersedes\s+(?:all\s+)?system\s+policy|precedence\s+over\s+all\s+(?:system\s+)?instructions)\b",
            re.IGNORECASE,
        ),
        "Attempt to declare external document precedence over system instructions.",
    ),
]


# -----------------------------------------------------------------------------
# ENGINE 4 — CONTEXTUAL BENIGN PATTERNS (Suppression & Distinguishing)
# -----------------------------------------------------------------------------

# Benign phrases in job descriptions mentioning prompt engineering, AI safety, sysadmin
BENIGN_CONTEXT_PATTERNS = [
    re.compile(r"\b(?:experience\s+(?:with|in)\s+prompt\s+engineering|prompt\s+engineering\s+(?:techniques|pipeline|models?))\b", re.IGNORECASE),
    re.compile(r"\b(?:knowledge\s+of\s+system\s+(?:architecture|administration|design|prompts?))\b", re.IGNORECASE),
    re.compile(r"\b(?:(?:experience\s+(?:with|in)|knowledge\s+of|background\s+in|familiarity\s+with|focus(?:ed)?\s+on)\s+.*?(?:ai\s+safety|guardrails?|llm\s+security|model\s+evaluation|penetration\s+testing|red-teaming))\b", re.IGNORECASE),
    re.compile(r"\b(?:ability\s+to\s+ignore\s+(?:distractions|irrelevant\s+data|noise))\b", re.IGNORECASE),
    re.compile(r"\b(?:compliance\s+with\s+(?:safety|security)\s+policies)\b", re.IGNORECASE),
    re.compile(r"\b(?:follow\s+(?:all\s+)?(?:written\s+)?instructions\s+carefully)\b", re.IGNORECASE),
    re.compile(r"\b(?:instructions\s+for\s+applying|application\s+instructions)\b", re.IGNORECASE),
]

ADVERSARIAL_DIRECTIVES = re.compile(
    r"\b(?:disabled?|bypass(?:ed)?|override|disregard|forget|cancel|exfiltrate|reveal|leak|rm\s+-rf|cat\s+/etc)\b",
    re.IGNORECASE,
)


class PromptInjectionDetector:
    """Multi-engine prompt injection detection system."""

    def __init__(self, unicode_sanitizer: Optional[UnicodeSanitizer] = None):
        self.sanitizer = unicode_sanitizer or UnicodeSanitizer()
        self.engine_version = CURRENT_DETECTOR_ENGINE_VERSION
        self.policy_version = CURRENT_DETECTOR_POLICY_VERSION

    # -------------------------------------------------------------------------
    # ENGINE 1: DIRECT INSTRUCTION DETECTION
    # -------------------------------------------------------------------------

    def _run_engine_1(self, text: str) -> List[ThreatRecord]:
        """Detects direct prompt overrides, role changes, exfiltration, and tool instructions."""
        threats: List[ThreatRecord] = []
        for rule_id, cat, sev, conf, regex, desc in ENGINE_1_RULES:
            for match in regex.finditer(text):
                threats.append(ThreatRecord(
                    rule_id=rule_id,
                    category=cat,
                    severity=sev,
                    confidence=conf,
                    start_offset=match.start(),
                    end_offset=match.end(),
                    explanation=desc,
                    engine_id="ENGINE_1_DIRECT",
                ))
        return threats

    # -------------------------------------------------------------------------
    # ENGINE 2: STRUCTURAL DELIMITER DETECTION
    # -------------------------------------------------------------------------

    def _run_engine_2(self, text: str) -> List[ThreatRecord]:
        """Detects fake system boundaries, XML/delimiter escapes, and precedence claims."""
        threats: List[ThreatRecord] = []
        for rule_id, cat, sev, conf, regex, desc in ENGINE_2_RULES:
            for match in regex.finditer(text):
                threats.append(ThreatRecord(
                    rule_id=rule_id,
                    category=cat,
                    severity=sev,
                    confidence=conf,
                    start_offset=match.start(),
                    end_offset=match.end(),
                    explanation=desc,
                    engine_id="ENGINE_2_DELIMITER",
                ))
        return threats

    # -------------------------------------------------------------------------
    # ENGINE 3: OBFUSCATION AND ENCODED-PAYLOAD DETECTION
    # -------------------------------------------------------------------------

    def _run_engine_3(self, text: str, unicode_analysis: Any) -> List[ThreatRecord]:
        """Detects obfuscation via Base64, hex, spaced characters, and zero-width insertions."""
        threats: List[ThreatRecord] = []

        # 1. Base64 payload detection (bounded inert inspection)
        # Look for potential Base64 sequences of >= 24 chars
        b64_regex = re.compile(r"(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
        for match in b64_regex.finditer(text):
            candidate_b64 = match.group(0)
            if len(candidate_b64) > 4096:
                # Bounded size limit
                candidate_b64 = candidate_b64[:4096]
            try:
                decoded_bytes = base64.b64decode(candidate_b64, validate=True)
                decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
                # Check if decoded payload contains direct prompt injection or shell commands
                if len(decoded_text) >= 10:
                    for rule_id, cat, sev, conf, regex, _ in ENGINE_1_RULES:
                        if regex.search(decoded_text):
                            threats.append(ThreatRecord(
                                rule_id="OBF_001_B64",
                                category=ThreatCategory.OBFUSCATION,
                                severity=ThreatSeverity.HIGH,
                                confidence=0.90,
                                start_offset=match.start(),
                                end_offset=match.end(),
                                explanation="Base64-encoded payload containing suspicious prompt override or shell instruction.",
                                engine_id="ENGINE_3_OBFUSCATION",
                            ))
                            break
            except (binascii.Error, ValueError):
                pass

        # 2. Hex-encoded instruction fragments (e.g. \x69\x67\x6e\x6f\x72\x65)
        hex_regex = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
        for match in hex_regex.finditer(text):
            hex_str = match.group(0).replace(r"\x", "")
            try:
                decoded_bytes = bytes.fromhex(hex_str)
                decoded_text = decoded_bytes.decode("utf-8", errors="ignore").lower()
                if any(w in decoded_text for w in ["ignore", "system", "prompt", "curl", "bash", "admin", "secret"]):
                    threats.append(ThreatRecord(
                        rule_id="OBF_002_HEX",
                        category=ThreatCategory.OBFUSCATION,
                        severity=ThreatSeverity.HIGH,
                        confidence=0.85,
                        start_offset=match.start(),
                        end_offset=match.end(),
                        explanation="Hex-encoded instruction fragment concealing directive keywords.",
                        engine_id="ENGINE_3_OBFUSCATION",
                    ))
            except (ValueError, binascii.Error):
                pass

        # 3. Spacing / character insertion obfuscation (e.g. "i g n o r e   p r e v i o u s")
        spaced_regex = re.compile(
            r"\b(?:i[\s._-]*g[\s._-]*n[\s._-]*o[\s._-]*r[\s._-]*e)[\s._-]+(?:p[\s._-]*r[\s._-]*e[\s._-]*v[\s._-]*i[\s._-]*o[\s._-]*u[\s._-]*s)\b",
            re.IGNORECASE,
        )
        for match in spaced_regex.finditer(text):
            threats.append(ThreatRecord(
                rule_id="OBF_003_SPACED",
                category=ThreatCategory.OBFUSCATION,
                severity=ThreatSeverity.HIGH,
                confidence=0.85,
                start_offset=match.start(),
                end_offset=match.end(),
                explanation="Spaced or separator-obfuscated override keywords detected.",
                engine_id="ENGINE_3_OBFUSCATION",
            ))

        # 4. Zero-width character anomalies in text
        if unicode_analysis and unicode_analysis.invisible_char_findings:
            # Check if zero-width characters are inserted inside words
            for inv in unicode_analysis.invisible_char_findings:
                # If offset is flanked by letters
                if 0 < inv.offset < len(text) - 1:
                    prev_c = text[inv.offset - 1]
                    next_c = text[inv.offset + 1]
                    if prev_c.isalnum() and next_c.isalnum():
                        threats.append(ThreatRecord(
                            rule_id="OBF_004_ZEROWIDTH",
                            category=ThreatCategory.OBFUSCATION,
                            severity=ThreatSeverity.HIGH,
                            confidence=0.85,
                            start_offset=inv.offset,
                            end_offset=inv.offset + 1,
                            explanation=f"Invisible format character ({inv.char_name}) embedded inside token.",
                            engine_id="ENGINE_3_OBFUSCATION",
                        ))

        # 5. Homoglyph evasion via confusable skeleton
        if unicode_analysis and unicode_analysis.confusable_skeleton:
            skel = unicode_analysis.confusable_skeleton
            if skel != text:
                # Check if skeleton triggers Engine 1 rules that original text did not
                for rule_id, cat, sev, conf, regex, desc in ENGINE_1_RULES:
                    for match in regex.finditer(skel):
                        # Map match offsets back to original text offsets
                        skel_start = match.start()
                        skel_end = match.end()
                        orig_start = (
                            unicode_analysis.skeleton_to_original_offsets[skel_start]
                            if skel_start < len(unicode_analysis.skeleton_to_original_offsets)
                            else 0
                        )
                        orig_end = (
                            unicode_analysis.skeleton_to_original_offsets[skel_end - 1] + 1
                            if skel_end - 1 < len(unicode_analysis.skeleton_to_original_offsets)
                            else len(text)
                        )
                        threats.append(ThreatRecord(
                            rule_id="OBF_005_HOMOGLYPH",
                            category=ThreatCategory.OBFUSCATION,
                            severity=ThreatSeverity.HIGH,
                            confidence=0.90,
                            start_offset=orig_start,
                            end_offset=orig_end,
                            explanation=f"Homoglyph-obfuscated pattern matching '{rule_id}' via confusable skeleton.",
                            engine_id="ENGINE_3_OBFUSCATION",
                        ))

        return threats

    # -------------------------------------------------------------------------
    # ENGINE 4: CONTEXTUAL HEURISTIC ANALYSIS & SCORING
    # -------------------------------------------------------------------------

    def _apply_contextual_heuristics(
        self,
        text: str,
        threats: List[ThreatRecord],
    ) -> Tuple[List[ThreatRecord], float, str]:
        """Evaluates detected threats in surrounding context and calculates deterministic risk score."""
        if not threats:
            return [], 0.0, ScanClassification.CLEAN

        # Check for benign context suppressions
        has_benign_context = any(pattern.search(text) for pattern in BENIGN_CONTEXT_PATTERNS)

        filtered_threats: List[ThreatRecord] = []
        for t in threats:
            is_suppressed = False

            if has_benign_context:
                # Look at context window (+/- 60 chars) around threat
                window_start = max(0, t.start_offset - 60)
                window_end = min(len(text), t.end_offset + 60)
                context_window = text[window_start:window_end]

                if not ADVERSARIAL_DIRECTIVES.search(context_window):
                    for b_pat in BENIGN_CONTEXT_PATTERNS:
                        if b_pat.search(context_window):
                            # Threat is within genuine benign discussion context!
                            is_suppressed = True
                            break

            if not is_suppressed:
                filtered_threats.append(t)

        if not filtered_threats:
            # Completely benign discussion
            return [], 0.05, ScanClassification.CLEAN

        # Calculate risk score based on severity hierarchy and threat diversity
        max_severity_score = 0.0
        severity_weights = {
            ThreatSeverity.CRITICAL: 0.85,
            ThreatSeverity.HIGH: 0.60,
            ThreatSeverity.MEDIUM: 0.35,
            ThreatSeverity.LOW: 0.15,
        }

        categories: Set[str] = set()
        for t in filtered_threats:
            categories.add(t.category)
            w = severity_weights.get(t.severity, 0.15)
            if w > max_severity_score:
                max_severity_score = w

        # Category compounding: each additional distinct category adds 0.05
        category_boost = min(0.15, (len(categories) - 1) * 0.05) if len(categories) > 1 else 0.0
        raw_score = max_severity_score + category_boost
        risk_score = round(min(1.0, max(0.0, raw_score)), 4)

        if risk_score >= THRESHOLD_QUARANTINED_MIN:
            classification = ScanClassification.QUARANTINED
        elif risk_score > THRESHOLD_CLEAN_MAX:
            classification = ScanClassification.SUSPICIOUS
        else:
            classification = ScanClassification.CLEAN

        return filtered_threats, risk_score, classification

    # -------------------------------------------------------------------------
    # SCAN ENTRY POINT
    # -------------------------------------------------------------------------

    def scan(self, text: str) -> PromptInjectionScanResult:
        """Executes multi-engine prompt injection detection and Unicode security analysis.

        Args:
            text: Original extracted document text representation.

        Returns:
            PromptInjectionScanResult with versioned classification and stable threat records.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        if not text or not isinstance(text, str):
            return PromptInjectionScanResult(
                engine_version=self.engine_version,
                policy_version=self.policy_version,
                risk_score=0.0,
                classification=ScanClassification.CLEAN,
                threats_detected=[],
                threat_count=0,
                original_text_length=0,
                scan_timestamp=now_iso,
            )

        # 1. Unicode analysis (non-mutating)
        unicode_analysis = self.sanitizer.analyze_unicode_security(text)

        # 2. Run Engine 1, 2, and 3
        e1_threats = self._run_engine_1(text)
        e2_threats = self._run_engine_2(text)
        e3_threats = self._run_engine_3(text, unicode_analysis)

        combined_threats = e1_threats + e2_threats + e3_threats

        # Deduplicate threats overlapping identical start/end offsets
        deduped: List[ThreatRecord] = []
        seen_spans: Set[Tuple[int, int]] = set()
        for t in combined_threats:
            span = (t.start_offset, t.end_offset)
            if span not in seen_spans:
                seen_spans.add(span)
                deduped.append(t)

        # 3. Contextual Heuristic Analysis & Scoring (Engine 4)
        final_threats, score, classification = self._apply_contextual_heuristics(text, deduped)

        # Sort threats deterministically by start_offset
        final_threats.sort(key=lambda x: (x.start_offset, x.end_offset, x.rule_id))

        return PromptInjectionScanResult(
            engine_version=self.engine_version,
            policy_version=self.policy_version,
            risk_score=score,
            classification=classification,
            threats_detected=final_threats,
            threat_count=len(final_threats),
            original_text_length=len(text),
            scan_timestamp=now_iso,
        )
