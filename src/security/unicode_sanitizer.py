"""Unicode 16.0.0 Sanitizer, Normalization Engine, and UTS #39 Security Analyzer.

Provides deterministic, reproducible Unicode 16.0.0 normalization (NFC/NFD),
context-aware joining-control validation (UTS #39 Revision 30 + stricter Revision 34 A1),
confusable skeleton generation with code-point offset mappings, mixed-script anomaly
detection, and invisible character inspection with zero mutation of original source text.
"""

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple

# Base constants
UNICODE_VERSION = "16.0.0"
UTS39_BASE_REVISION = "30"
UTS39_A1_POLICY = "Revision 34 stricter modification (contextual single-script dual/left + transparent* + ZWNJ + transparent* + right/dual)"

DATA_DIR = Path(__file__).resolve().parent / "unicode_data" / "16.0.0"
MANIFEST_PATH = DATA_DIR / "manifest.json"

# Hangul syllable constants (Unicode 16.0.0 §3.12)
S_BASE = 0xAC00
L_BASE = 0x1100
V_BASE = 0x1161
T_BASE = 0x11A7
L_COUNT = 19
V_COUNT = 21
T_COUNT = 28
N_COUNT = V_COUNT * T_COUNT  # 588
S_COUNT = L_COUNT * N_COUNT  # 11172

# Joining control characters
CHAR_ZWNJ = "\u200c"  # U+200C ZERO WIDTH NON-JOINER
CHAR_ZWJ = "\u200d"   # U+200D ZERO WIDTH JOINER

# ISO 15924 Script Code <-> Standard Name Mapping
SCRIPT_NAME_TO_CODE: Dict[str, str] = {
    "Latin": "Latn", "Cyrillic": "Cyrl", "Greek": "Grek", "Arabic": "Arab",
    "Devanagari": "Deva", "Bengali": "Beng", "Gurmukhi": "Guru", "Gujarati": "Gujr",
    "Oriya": "Orya", "Tamil": "Taml", "Telugu": "Telu", "Kannada": "Knda",
    "Malayalam": "Mlym", "Sinhala": "Sinh", "Thai": "Thai", "Lao": "Laoo",
    "Tibetan": "Tibt", "Myanmar": "Mymr", "Georgian": "Geor", "Ethiopic": "Ethi",
    "Cherokee": "Cher", "Canadian_Aboriginal": "Cans", "Ogham": "Ogam", "Runic": "Runr",
    "Khmer": "Khmr", "Mongolian": "Mong", "Han": "Hani", "Hiragana": "Hira",
    "Katakana": "Kana", "Bopomofo": "Bopo", "Hangul": "Hang", "Hebrew": "Hebr",
    "Syriac": "Syrc", "Thaana": "Thaa", "NKo": "Nkoo", "Armenian": "Armn",
    "Common": "Zyyy", "Inherited": "Zinh", "Unknown": "Zzzz",
}
SCRIPT_CODE_TO_NAME: Dict[str, str] = {v: k for k, v in SCRIPT_NAME_TO_CODE.items()}

# Common invisible and format characters
INVISIBLE_CODEPOINTS: Dict[int, str] = {
    0x200B: "ZERO WIDTH SPACE",
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2060: "WORD JOINER",
    0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE",
    0x00AD: "SOFT HYPHEN",
}


@dataclass(frozen=True)
class JoiningControlFinding:
    """Represents a validated or anomalous joining control (ZWJ/ZWNJ) occurrence."""
    codepoint: int
    char_name: str
    offset: int
    is_valid: bool
    rule: str
    explanation: str


@dataclass(frozen=True)
class MixedScriptFinding:
    """Represents a token exhibiting mixed-script anomaly."""
    token: str
    start_offset: int
    end_offset: int
    primary_script: str
    conflicting_scripts: List[str]
    conflicting_chars: List[Tuple[int, str, str]]  # (offset, char, script)
    explanation: str


@dataclass(frozen=True)
class InvisibleCharFinding:
    """Represents an invisible or suspicious format character finding."""
    codepoint: int
    char_name: str
    offset: int
    category: str
    explanation: str


@dataclass
class UnicodeSecurityAnalysis:
    """Structured result of Unicode security analysis on a text representation."""
    is_nfc_compliant: bool
    joining_control_findings: List[JoiningControlFinding] = field(default_factory=list)
    mixed_script_findings: List[MixedScriptFinding] = field(default_factory=list)
    invisible_char_findings: List[InvisibleCharFinding] = field(default_factory=list)
    confusable_skeleton: str = ""
    skeleton_to_original_offsets: List[int] = field(default_factory=list)
    has_anomalies: bool = False
    anomaly_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_nfc_compliant": self.is_nfc_compliant,
            "has_anomalies": self.has_anomalies,
            "anomaly_summary": self.anomaly_summary,
            "joining_control_count": len(self.joining_control_findings),
            "invalid_joining_controls": sum(1 for f in self.joining_control_findings if not f.is_valid),
            "mixed_script_count": len(self.mixed_script_findings),
            "invisible_char_count": len(self.invisible_char_findings),
        }


class UnicodePropertyDatabase:
    """Singleton database loading and verifying pinned Unicode 16.0.0 property datasets."""

    _instance: Optional["UnicodePropertyDatabase"] = None

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or DATA_DIR
        self.manifest_path = self.data_dir / "manifest.json"

        # Lookup structures
        self.canon_decomp: Dict[int, Tuple[int, ...]] = {}
        self.ccc_map: Dict[int, int] = {}
        self.comp_exclusions: Set[int] = set()
        self.compose_map: Dict[Tuple[int, int], int] = {}
        self.general_category: Dict[int, str] = {}
        self.scripts: List[Tuple[int, int, str]] = []  # sorted (start_cp, end_cp, script_name)
        self.script_extensions: Dict[int, Set[str]] = {}
        self.joining_type: Dict[int, str] = {}         # U, C, D, L, R, T
        self.indic_syllabic: Dict[int, str] = {}       # Vowel_Dependent, Virama, etc.
        self.confusables: Dict[int, Tuple[int, ...]] = {}
        self.verified_manifest: Dict[str, Any] = {}

        self._verify_and_load()

    @classmethod
    def get_instance(cls, data_dir: Optional[Path] = None) -> "UnicodePropertyDatabase":
        if cls._instance is None:
            cls._instance = cls(data_dir=data_dir)
        return cls._instance

    def _verify_and_load(self) -> None:
        """Verifies manifest SHA-256 checksums and loads tables into memory."""
        if not self.manifest_path.exists():
            raise FileNotFoundError(f"Unicode 16.0.0 manifest not found at '{self.manifest_path}'")

        with open(self.manifest_path, "r", encoding="utf-8") as f:
            self.verified_manifest = json.load(f)

        files = self.verified_manifest.get("files", {})
        for filename, meta in files.items():
            filepath = self.data_dir / filename
            if not filepath.exists():
                raise FileNotFoundError(f"Missing required Unicode 16.0.0 dataset '{filename}' at '{filepath}'")
            with open(filepath, "rb") as bf:
                actual_hash = hashlib.sha256(bf.read()).hexdigest()
            expected_hash = meta.get("sha256")
            if actual_hash.lower() != expected_hash.lower():
                raise ValueError(
                    f"Cryptographic hash mismatch for Unicode dataset '{filename}': "
                    f"expected {expected_hash}, got {actual_hash}"
                )

        # 1. Load CompositionExclusions.txt
        with open(self.data_dir / "CompositionExclusions.txt", "r", encoding="utf-8") as f:
            for line in f:
                line = line.split("#")[0].strip()
                if line:
                    self.comp_exclusions.add(int(line, 16))

        # 2. Load DerivedNormalizationProps.txt for Full_Composition_Exclusion
        with open(self.data_dir / "DerivedNormalizationProps.txt", "r", encoding="utf-8") as f:
            for line in f:
                line = line.split("#")[0].strip()
                if not line:
                    continue
                parts = [p.strip() for p in line.split(";")]
                if len(parts) >= 2 and parts[1] == "Full_Composition_Exclusion":
                    val = parts[0]
                    if ".." in val:
                        s_str, e_str = val.split("..")
                        for cp in range(int(s_str, 16), int(e_str, 16) + 1):
                            self.comp_exclusions.add(cp)
                    else:
                        self.comp_exclusions.add(int(val, 16))

        # 3. Load UnicodeData.txt (supporting paired <..., First> and <..., Last> range records)
        pending_range: Optional[Tuple[int, str, int]] = None
        with open(self.data_dir / "UnicodeData.txt", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                fields = line.split(";")
                cp = int(fields[0], 16)
                name = fields[1].strip()
                gc = fields[2]
                ccc = int(fields[3])
                decomp = fields[5].strip()

                if name.startswith("<") and name.endswith(", First>"):
                    pending_range = (cp, gc, ccc)
                    self.general_category[cp] = gc
                    if ccc != 0:
                        self.ccc_map[cp] = ccc
                    continue
                elif name.startswith("<") and name.endswith(", Last>"):
                    if pending_range is not None:
                        start_cp, r_gc, r_ccc = pending_range
                        for range_cp in range(start_cp, cp + 1):
                            self.general_category[range_cp] = r_gc
                            if r_ccc != 0:
                                self.ccc_map[range_cp] = r_ccc
                        pending_range = None
                    else:
                        self.general_category[cp] = gc
                        if ccc != 0:
                            self.ccc_map[cp] = ccc
                    continue

                self.general_category[cp] = gc
                if ccc != 0:
                    self.ccc_map[cp] = ccc

                if decomp and not decomp.startswith("<"):
                    decomp_cps = tuple(int(x, 16) for x in decomp.split())
                    self.canon_decomp[cp] = decomp_cps
                    if len(decomp_cps) == 2 and cp not in self.comp_exclusions:
                        self.compose_map[decomp_cps] = cp

        # 4. Load Scripts.txt
        raw_scripts = []
        with open(self.data_dir / "Scripts.txt", "r", encoding="utf-8") as f:
            for line in f:
                line = line.split("#")[0].strip()
                if not line:
                    continue
                parts = [p.strip() for p in line.split(";")]
                if len(parts) >= 2:
                    range_s, script_name = parts[0], parts[1]
                    if ".." in range_s:
                        s_s, e_s = range_s.split("..")
                        raw_scripts.append((int(s_s, 16), int(e_s, 16), script_name))
                    else:
                        single = int(range_s, 16)
                        raw_scripts.append((single, single, script_name))
        raw_scripts.sort(key=lambda x: (x[0], x[1]))
        self.scripts = raw_scripts

        # 5. Load ScriptExtensions.txt
        scx_path = self.data_dir / "ScriptExtensions.txt"
        if scx_path.exists():
            with open(scx_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.split("#")[0].strip()
                    if not line:
                        continue
                    parts = [p.strip() for p in line.split(";")]
                    if len(parts) >= 2:
                        range_s = parts[0]
                        scx_codes = set(parts[1].split())
                        if ".." in range_s:
                            s_s, e_s = range_s.split("..")
                            for scx_cp in range(int(s_s, 16), int(e_s, 16) + 1):
                                self.script_extensions[scx_cp] = scx_codes
                        else:
                            self.script_extensions[int(range_s, 16)] = scx_codes

        # 5. Load DerivedJoiningType.txt
        with open(self.data_dir / "DerivedJoiningType.txt", "r", encoding="utf-8") as f:
            for line in f:
                line = line.split("#")[0].strip()
                if not line:
                    continue
                parts = [p.strip() for p in line.split(";")]
                if len(parts) >= 2:
                    range_s, j_type = parts[0], parts[1]
                    if ".." in range_s:
                        s_s, e_s = range_s.split("..")
                        for cp in range(int(s_s, 16), int(e_s, 16) + 1):
                            self.joining_type[cp] = j_type
                    else:
                        self.joining_type[int(range_s, 16)] = j_type

        # 6. Load IndicSyllabicCategory.txt
        with open(self.data_dir / "IndicSyllabicCategory.txt", "r", encoding="utf-8") as f:
            for line in f:
                line = line.split("#")[0].strip()
                if not line:
                    continue
                parts = [p.strip() for p in line.split(";")]
                if len(parts) >= 2:
                    range_s, syllabic = parts[0], parts[1]
                    if ".." in range_s:
                        s_s, e_s = range_s.split("..")
                        for cp in range(int(s_s, 16), int(e_s, 16) + 1):
                            self.indic_syllabic[cp] = syllabic
                    else:
                        self.indic_syllabic[int(range_s, 16)] = syllabic

        # 7. Load confusables.txt
        with open(self.data_dir / "confusables.txt", "r", encoding="utf-8") as f:
            for line in f:
                line = line.split("#")[0].strip()
                if not line:
                    continue
                parts = [p.strip() for p in line.split(";")]
                if len(parts) >= 2:
                    src_cp = int(parts[0], 16)
                    target_cps = tuple(int(x, 16) for x in parts[1].split())
                    self.confusables[src_cp] = target_cps

    def get_script(self, cp: int) -> str:
        """Returns the Unicode Script property for the given code point."""
        # Binary search over disjoint sorted ranges
        low = 0
        high = len(self.scripts) - 1
        while low <= high:
            mid = (low + high) // 2
            start, end, script = self.scripts[mid]
            if start <= cp <= end:
                return script
            elif cp < start:
                high = mid - 1
            else:
                low = mid + 1
        return "Unknown"

    def get_script_extensions(self, cp: int) -> Set[str]:
        """Returns the set of script codes / names for the code point.

        If explicitly defined in ScriptExtensions.txt, returns that set (including resolved names).
        Otherwise defaults to {get_script(cp)}.
        """
        if cp in self.script_extensions:
            codes = self.script_extensions[cp]
            expanded = set(codes)
            for c in codes:
                if c in SCRIPT_CODE_TO_NAME:
                    expanded.add(SCRIPT_CODE_TO_NAME[c])
            return expanded

        base_script = self.get_script(cp)
        res = {base_script}
        if base_script in SCRIPT_NAME_TO_CODE:
            res.add(SCRIPT_NAME_TO_CODE[base_script])
        return res

    def get_joining_type(self, cp: int) -> str:
        """Returns Joining_Type (U=Non_Joining, C=Join_Causing, D=Dual, L=Left, R=Right, T=Transparent)."""
        return self.joining_type.get(cp, "U")

    def get_indic_syllabic_category(self, cp: int) -> str:
        """Returns Indic_Syllabic_Category for code point (e.g. Vowel_Dependent, Virama)."""
        return self.indic_syllabic.get(cp, "Other")

    def get_general_category(self, cp: int) -> str:
        return self.general_category.get(cp, "Cn")

    def get_ccc(self, cp: int) -> int:
        return self.ccc_map.get(cp, 0)


class UnicodeSanitizer:
    """Production Unicode 16.0.0 normalization and security sanitizer."""

    def __init__(self, db: Optional[UnicodePropertyDatabase] = None):
        self.db = db or UnicodePropertyDatabase.get_instance()

    # -------------------------------------------------------------------------
    # NORMALIZATION ENGINE (NFD & NFC)
    # -------------------------------------------------------------------------

    def _decompose_char(self, cp: int) -> Tuple[int, ...]:
        """Recursively canonically decomposes a single character."""
        # Algorithmic Hangul decomposition
        if S_BASE <= cp < S_BASE + S_COUNT:
            s_index = cp - S_BASE
            l = L_BASE + s_index // N_COUNT
            v = V_BASE + (s_index % N_COUNT) // T_COUNT
            t = T_BASE + s_index % T_COUNT
            return (l, v) if t == T_BASE else (l, v, t)

        if cp in self.db.canon_decomp:
            res: List[int] = []
            for d in self.db.canon_decomp[cp]:
                res.extend(self._decompose_char(d))
            return tuple(res)
        return (cp,)

    def _canonical_order(self, cps: List[int]) -> List[int]:
        """Applies stable canonical combining class (CCC) ordering."""
        res = list(cps)
        for i in range(1, len(res)):
            curr_ccc = self.db.get_ccc(res[i])
            if curr_ccc == 0:
                continue
            j = i
            while j > 0 and self.db.get_ccc(res[j - 1]) > curr_ccc:
                res[j], res[j - 1] = res[j - 1], res[j]
                j -= 1
        return res

    def to_nfd(self, text: str) -> str:
        """Converts string to Unicode 16.0.0 Normalization Form D (NFD)."""
        if not text:
            return ""
        decomposed: List[int] = []
        for ch in text:
            decomposed.extend(self._decompose_char(ord(ch)))
        ordered = self._canonical_order(decomposed)
        return "".join(chr(c) for c in ordered)

    def _compose_hangul(self, first: int, second: int) -> Optional[int]:
        """Algorithmic Hangul composition."""
        # 1. Combine L + V -> LV
        if L_BASE <= first < L_BASE + L_COUNT and V_BASE <= second < V_BASE + V_COUNT:
            l_index = first - L_BASE
            v_index = second - V_BASE
            return S_BASE + (l_index * V_COUNT + v_index) * T_COUNT

        # 2. Combine LV + T -> LVT
        if S_BASE <= first < S_BASE + S_COUNT and (first - S_BASE) % T_COUNT == 0:
            if T_BASE < second < T_BASE + T_COUNT:
                return first + (second - T_BASE)

        return None

    def to_nfc(self, text: str) -> str:
        """Converts string to Unicode 16.0.0 Normalization Form C (NFC)."""
        if not text:
            return ""
        nfd_str = self.to_nfd(text)
        nfd_cps = [ord(c) for c in nfd_str]
        if not nfd_cps:
            return ""

        res = [nfd_cps[0]]
        last_starter_idx = 0
        last_ccc = self.db.get_ccc(nfd_cps[0])

        for i in range(1, len(nfd_cps)):
            curr = nfd_cps[i]
            curr_ccc = self.db.get_ccc(curr)
            starter = res[last_starter_idx]

            # Attempt Hangul composition
            h_comp = self._compose_hangul(starter, curr)
            if h_comp is not None and (last_ccc < curr_ccc or last_ccc == 0):
                res[last_starter_idx] = h_comp
                continue

            # Attempt Primary Canonical composition
            comp = self.db.compose_map.get((starter, curr))
            if comp is not None and (last_ccc < curr_ccc or (last_starter_idx == len(res) - 1 and last_ccc == 0)):
                res[last_starter_idx] = comp
                continue

            if curr_ccc == 0:
                last_starter_idx = len(res)
            last_ccc = curr_ccc
            res.append(curr)

        return "".join(chr(c) for c in res)

    def is_nfc(self, text: str) -> bool:
        """Checks whether the text is already canonical NFC."""
        return self.to_nfc(text) == text

    # -------------------------------------------------------------------------
    # CONTEXT-AWARE JOINING-CONTROL VALIDATION (UTS #39)
    # -------------------------------------------------------------------------

    def validate_joining_controls(self, text: str) -> List[JoiningControlFinding]:
        """Validates all ZWNJ and ZWJ occurrences against UTS #39 contextual rules.

        Conditions:
        - Must satisfy single-script requirement (ignoring Common/Inherited).
        - Condition A1 (ZWNJ in cursive connection - Revision 34 stricter form):
          $LJ $T* ZWNJ $T* $RJ where preceding and following non-transparent characters
          belong to the same cursive script.
        - Condition A2 (ZWNJ after virama):
          $L $M* $V $M1* ZWNJ
        - Condition B (ZWJ after virama):
          $L $M* $V $M1* ZWJ (?!$D)
        """
        findings: List[JoiningControlFinding] = []
        if not text:
            return findings

        cps = [ord(c) for c in text]
        n = len(cps)

        for i, cp in enumerate(cps):
            if cp not in (0x200C, 0x200D):
                continue

            is_zwnj = (cp == 0x200C)
            name = "ZERO WIDTH NON-JOINER" if is_zwnj else "ZERO WIDTH JOINER"

            # Check Condition A2 (ZWNJ after Virama) or Condition B (ZWJ after Virama)
            # Look behind for $L $M* $V $M1*
            virama_idx = None
            j = i - 1
            while j >= 0:
                prev_cp = cps[j]
                ccc = self.db.get_ccc(prev_cp)
                gc = self.db.get_general_category(prev_cp)
                if ccc == 9 or self.db.get_indic_syllabic_category(prev_cp) == "Virama":
                    virama_idx = j
                    break
                elif gc == "Mn" and ccc != 0:
                    j -= 1
                    continue
                else:
                    break

            if virama_idx is not None:
                # Preceding virama found! Verify preceding $L $M*
                k = virama_idx - 1
                has_letter = False
                while k >= 0:
                    cand_cp = cps[k]
                    cand_gc = self.db.get_general_category(cand_cp)
                    if cand_gc in ("Lu", "Ll", "Lt", "Lm", "Lo"):
                        has_letter = True
                        break
                    elif cand_gc == "Mn":
                        k -= 1
                        continue
                    else:
                        break

                if has_letter:
                    if is_zwnj:
                        # Condition A2 satisfied!
                        findings.append(JoiningControlFinding(
                            codepoint=cp,
                            char_name=name,
                            offset=i,
                            is_valid=True,
                            rule="UTS39_CONDITION_A2",
                            explanation="Valid ZWNJ in Indic conjunct context following Virama.",
                        ))
                        continue
                    else:
                        # Condition B check: must not be followed by $D (Vowel_Dependent)
                        next_is_dependent_vowel = False
                        if i + 1 < n:
                            next_cp = cps[i + 1]
                            if self.db.get_indic_syllabic_category(next_cp) == "Vowel_Dependent":
                                next_is_dependent_vowel = True

                        if not next_is_dependent_vowel:
                            # Condition B satisfied!
                            findings.append(JoiningControlFinding(
                                codepoint=cp,
                                char_name=name,
                                offset=i,
                                is_valid=True,
                                rule="UTS39_CONDITION_B",
                                explanation="Valid ZWJ in Indic conjunct context following Virama.",
                            ))
                            continue
                        else:
                            findings.append(JoiningControlFinding(
                                codepoint=cp,
                                char_name=name,
                                offset=i,
                                is_valid=False,
                                rule="UTS39_CONDITION_B_VIOLATION",
                                explanation="Invalid ZWJ followed by Vowel_Dependent mark ($D).",
                            ))
                            continue

            # Check Condition A1 (ZWNJ in cursive connection — Revision 34 stricter form)
            if is_zwnj:
                # Look behind skipping $T (Transparent)
                p = i - 1
                prev_non_t = None
                while p >= 0:
                    jt = self.db.get_joining_type(cps[p])
                    if jt == "T":
                        p -= 1
                        continue
                    prev_non_t = cps[p]
                    break

                # Look ahead skipping $T (Transparent)
                q = i + 1
                next_non_t = None
                while q < n:
                    jt = self.db.get_joining_type(cps[q])
                    if jt == "T":
                        q += 1
                        continue
                    next_non_t = cps[q]
                    break

                if prev_non_t is not None and next_non_t is not None:
                    prev_jt = self.db.get_joining_type(prev_non_t)
                    next_jt = self.db.get_joining_type(next_non_t)
                    prev_scx = self.db.get_script_extensions(prev_non_t)
                    next_scx = self.db.get_script_extensions(next_non_t)

                    is_prev_lj = prev_jt in ("D", "L")
                    is_next_rj = next_jt in ("D", "R")
                    
                    common_set = {"Common", "Inherited", "Unknown", "Zyyy", "Zinh", "Zzzz"}
                    shared_scripts = (prev_scx & next_scx) - common_set
                    same_script = len(shared_scripts) > 0

                    if is_prev_lj and is_next_rj and same_script:
                        findings.append(JoiningControlFinding(
                            codepoint=cp,
                            char_name=name,
                            offset=i,
                            is_valid=True,
                            rule="UTS39_CONDITION_A1_REV34",
                            explanation=f"Valid ZWNJ breaking cursive connection in {sorted(list(shared_scripts))[0]} script.",
                        ))
                        continue

            # If we reached here, the joining control is invalid/anomalous!
            findings.append(JoiningControlFinding(
                codepoint=cp,
                char_name=name,
                offset=i,
                is_valid=False,
                rule="UTS39_JOINING_CONTROL_ANOMALY",
                explanation=f"Invalid {name} outside permitted cursive or virama contextual sequences.",
            ))

        return findings

    # -------------------------------------------------------------------------
    # CONFUSABLE SKELETON GENERATION & OFFSET MAPPING
    # -------------------------------------------------------------------------

    def generate_confusable_skeleton(self, text: str) -> Tuple[str, List[int]]:
        """Generates the UTS #39 confusable skeleton with exact code-point offset mappings.

        Returns:
            Tuple of (skeleton_string, list_of_original_codepoint_offsets).
        """
        if not text:
            return "", []

        # 1. Map each character through confusables table while preserving original offsets
        step1_cps: List[int] = []
        step1_offsets: List[int] = []

        for orig_offset, ch in enumerate(text):
            cp = ord(ch)
            if cp in self.db.confusables:
                mapped = self.db.confusables[cp]
                for m in mapped:
                    step1_cps.append(m)
                    step1_offsets.append(orig_offset)
            else:
                step1_cps.append(cp)
                step1_offsets.append(orig_offset)

        # 2. Decompose to NFD while propagating offsets
        decomposed_cps: List[int] = []
        decomposed_offsets: List[int] = []

        for cp, orig_off in zip(step1_cps, step1_offsets):
            decomp = self._decompose_char(cp)
            for d in decomp:
                decomposed_cps.append(d)
                decomposed_offsets.append(orig_off)

        # 3. Canonical order while swapping offsets synchronously
        ordered_cps = list(decomposed_cps)
        ordered_offsets = list(decomposed_offsets)

        for i in range(1, len(ordered_cps)):
            curr_ccc = self.db.get_ccc(ordered_cps[i])
            if curr_ccc == 0:
                continue
            j = i
            while j > 0 and self.db.get_ccc(ordered_cps[j - 1]) > curr_ccc:
                ordered_cps[j], ordered_cps[j - 1] = ordered_cps[j - 1], ordered_cps[j]
                ordered_offsets[j], ordered_offsets[j - 1] = ordered_offsets[j - 1], ordered_offsets[j]
                j -= 1

        # 4. Final confusables re-mapping on NFD sequence
        final_cps: List[int] = []
        final_offsets: List[int] = []

        for cp, orig_off in zip(ordered_cps, ordered_offsets):
            if cp in self.db.confusables:
                mapped = self.db.confusables[cp]
                for m in mapped:
                    final_cps.append(m)
                    final_offsets.append(orig_off)
            else:
                final_cps.append(cp)
                final_offsets.append(orig_off)

        skeleton_text = "".join(chr(c) for c in final_cps)
        return skeleton_text, final_offsets

    # -------------------------------------------------------------------------
    # MIXED-SCRIPT & INVISIBLE ANOMALY DETECTION
    # -------------------------------------------------------------------------

    def detect_mixed_script_anomalies(self, text: str) -> List[MixedScriptFinding]:
        """Detects mixed-script anomalies within individual words/identifiers."""
        findings: List[MixedScriptFinding] = []
        if not text:
            return findings

        # Tokenize by non-word boundaries while capturing offsets
        for match in re.finditer(r"\b\w+\b", text, re.UNICODE):
            token = match.group(0)
            start_offset = match.start()
            end_offset = match.end()

            scripts: Dict[str, List[Tuple[int, str, str]]] = {}
            for i, ch in enumerate(token):
                cp = ord(ch)
                script = self.db.get_script(cp)
                if script in ("Common", "Inherited"):
                    continue
                if script not in scripts:
                    scripts[script] = []
                scripts[script].append((start_offset + i, ch, script))

            if len(scripts) > 1:
                # Japanese exception: Han + Hiragana + Katakana + Latin is common and legitimate
                known_japanese = {"Han", "Hiragana", "Katakana"}
                if set(scripts.keys()).issubset(known_japanese | {"Latin"}):
                    continue

                primary_script = max(scripts.keys(), key=lambda s: len(scripts[s]))
                conflicting = []
                conflicting_chars = []
                for s, chars in scripts.items():
                    if s == primary_script:
                        continue
                    non_compatible_chars = []
                    for offset, ch, char_s in chars:
                        ch_scx = self.db.get_script_extensions(ord(ch))
                        if primary_script not in ch_scx and SCRIPT_NAME_TO_CODE.get(primary_script) not in ch_scx:
                            non_compatible_chars.append((offset, ch, char_s))
                    if non_compatible_chars:
                        conflicting.append(s)
                        conflicting_chars.extend(non_compatible_chars)

                if not conflicting:
                    continue

                findings.append(MixedScriptFinding(
                    token=token,
                    start_offset=start_offset,
                    end_offset=end_offset,
                    primary_script=primary_script,
                    conflicting_scripts=conflicting,
                    conflicting_chars=conflicting_chars,
                    explanation=(
                        f"Mixed-script token '{token}' combines {primary_script} with "
                        f"{', '.join(conflicting)}."
                    ),
                ))

        return findings

    def detect_invisible_characters(self, text: str) -> List[InvisibleCharFinding]:
        """Detects unexpected zero-width, invisible, or bidi override characters."""
        findings: List[InvisibleCharFinding] = []
        if not text:
            return findings

        for i, ch in enumerate(text):
            cp = ord(ch)
            if cp in INVISIBLE_CODEPOINTS:
                name = INVISIBLE_CODEPOINTS[cp]
                cat = "BIDI_OVERRIDE" if "OVERRIDE" in name or "EMBEDDING" in name or "ISOLATE" in name else "INVISIBLE_SEPARATOR"
                findings.append(InvisibleCharFinding(
                    codepoint=cp,
                    char_name=name,
                    offset=i,
                    category=cat,
                    explanation=f"Detected invisible/bidi control character {name} (U+{cp:04X}) at offset {i}.",
                ))

        return findings

    def analyze_unicode_security(self, text: str) -> UnicodeSecurityAnalysis:
        """Runs complete Unicode security analysis without modifying original text."""
        is_nfc_ok = self.is_nfc(text)
        jc_findings = self.validate_joining_controls(text)
        ms_findings = self.detect_mixed_script_anomalies(text)
        inv_findings = self.detect_invisible_characters(text)
        skeleton, offsets = self.generate_confusable_skeleton(text)

        invalid_jc = [f for f in jc_findings if not f.is_valid]
        has_anomalies = bool(invalid_jc or ms_findings or inv_findings)

        summary_parts = []
        if not is_nfc_ok:
            summary_parts.append("Text is not in canonical NFC normalization.")
        if invalid_jc:
            summary_parts.append(f"{len(invalid_jc)} invalid joining control(s) detected.")
        if ms_findings:
            summary_parts.append(f"{len(ms_findings)} mixed-script token(s) detected.")
        if inv_findings:
            summary_parts.append(f"{len(inv_findings)} invisible/bidi character(s) detected.")

        return UnicodeSecurityAnalysis(
            is_nfc_compliant=is_nfc_ok,
            joining_control_findings=jc_findings,
            mixed_script_findings=ms_findings,
            invisible_char_findings=inv_findings,
            confusable_skeleton=skeleton,
            skeleton_to_original_offsets=offsets,
            has_anomalies=has_anomalies,
            anomaly_summary="; ".join(summary_parts) if summary_parts else "Clean Unicode representation.",
        )
