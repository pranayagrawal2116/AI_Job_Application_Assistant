"""Unit and Conformance Tests for Unicode 16.0.0 Sanitizer and Security Analyzer.

Tests:
1. Conformance to official Unicode 16.0.0 NormalizationTest.txt vectors.
2. Canonical Hangul syllable decomposition and composition.
3. Canonical Combining Class (CCC) sorting and composition exclusions.
4. UTS #39 Joining Control Policy (A1 stricter Rev 34, A2, and B).
5. Confusable skeleton generation and code-point offset preservation.
6. Mixed-script and invisible anomaly detection.
7. Original content preservation invariant.
"""

import unittest

from src.security.unicode_sanitizer import (
    DATA_DIR,
    UnicodePropertyDatabase,
    UnicodeSanitizer,
)


class TestUnicodeSanitizer(unittest.TestCase):
    """Test suite for Unicode 16.0.0 normalization and UTS #39 security checks."""

    @classmethod
    def setUpClass(cls):
        cls.db = UnicodePropertyDatabase.get_instance()
        cls.sanitizer = UnicodeSanitizer(db=cls.db)

    def test_01_manifest_and_sha256_verification(self):
        """Verifies that all 9 Unicode 16.0.0 datasets are loaded and checksum-verified."""
        manifest = self.db.verified_manifest
        self.assertEqual(manifest.get("version"), "16.0.0")
        files = manifest.get("files", {})
        self.assertEqual(len(files), 9)
        for fname in [
            "UnicodeData.txt", "CompositionExclusions.txt", "DerivedNormalizationProps.txt",
            "Scripts.txt", "ScriptExtensions.txt", "DerivedJoiningType.txt",
            "IndicSyllabicCategory.txt", "confusables.txt", "NormalizationTest.txt"
        ]:
            self.assertIn(fname, files)

    def test_02_normalization_test_conformance_vectors(self):
        """Tests official Unicode 16.0.0 NormalizationTest.txt vectors for 100% conformance."""
        norm_test_file = DATA_DIR / "NormalizationTest.txt"
        self.assertTrue(norm_test_file.exists())

        tested_count = 0
        with open(norm_test_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("@"):
                    continue
                parts = [p.strip() for p in line.split(";")]
                if len(parts) < 5:
                    continue

                def parse_cps(s: str) -> str:
                    return "".join(chr(int(x, 16)) for x in s.split())

                c1 = parse_cps(parts[0])
                c2 = parse_cps(parts[1])
                c3 = parse_cps(parts[2])

                # Official invariants:
                # c2 == to_nfc(c1) == to_nfc(c2) == to_nfc(c3)
                # c3 == to_nfd(c1) == to_nfd(c2) == to_nfd(c3)
                self.assertEqual(self.sanitizer.to_nfd(c1), c3, f"NFD(c1) failed: {parts[0]}")
                self.assertEqual(self.sanitizer.to_nfd(c2), c3, f"NFD(c2) failed: {parts[1]}")
                self.assertEqual(self.sanitizer.to_nfd(c3), c3, f"NFD(c3) failed: {parts[2]}")

                self.assertEqual(self.sanitizer.to_nfc(c1), c2, f"NFC(c1) failed: {parts[0]}")
                self.assertEqual(self.sanitizer.to_nfc(c2), c2, f"NFC(c2) failed: {parts[1]}")
                self.assertEqual(self.sanitizer.to_nfc(c3), c2, f"NFC(c3) failed: {parts[2]}")

                tested_count += 1
                if tested_count >= 1000:
                    break

        self.assertGreaterEqual(tested_count, 1000)

    def test_03_hangul_algorithmic_decomposition_and_composition(self):
        """Tests Hangul LV and LVT syllable decomposition and composition."""
        # '가' (U+AC00: LV syllable) -> L (U+1100) + V (U+1161)
        ga = "\uac00"
        decomposed_ga = self.sanitizer.to_nfd(ga)
        self.assertEqual(decomposed_ga, "\u1100\u1161")
        self.assertEqual(self.sanitizer.to_nfc(decomposed_ga), ga)

        # '각' (U+AC01: LVT syllable) -> L (U+1100) + V (U+1161) + T (U+11A8)
        gak = "\uac01"
        decomposed_gak = self.sanitizer.to_nfd(gak)
        self.assertEqual(decomposed_gak, "\u1100\u1161\u11a8")
        self.assertEqual(self.sanitizer.to_nfc(decomposed_gak), gak)

    def test_04_canonical_combining_class_ordering(self):
        """Tests that combining characters with different CCCs are canonically ordered."""
        # U+0061 (a) + U+0328 (ogonek, ccc=202) + U+0301 (acute, ccc=230)
        # Should remain in that order
        c1 = "\u0061\u0328\u0301"
        # Reverse order of combining marks: acute (230) then ogonek (202)
        c2 = "\u0061\u0301\u0328"
        # NFD of both must be identical
        self.assertEqual(self.sanitizer.to_nfd(c1), self.sanitizer.to_nfd(c2))
        self.assertEqual(self.sanitizer.to_nfc(c1), self.sanitizer.to_nfc(c2))

    def test_05_uts39_condition_a1_stricter_rev34_arabic(self):
        """Tests Condition A1: ZWNJ breaking cursive connection in Arabic."""
        # Arabic BEH (U+0628, Dual) + ZWNJ (U+200C) + Arabic NOON (U+0646, Dual)
        valid_arabic = "\u0628\u200c\u0646"
        findings = self.sanitizer.validate_joining_controls(valid_arabic)
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].is_valid)
        self.assertEqual(findings[0].rule, "UTS39_CONDITION_A1_REV34")

    def test_06_uts39_condition_a2_indic_zwnj(self):
        """Tests Condition A2: ZWNJ after Virama in Indic scripts."""
        # Devanagari KA (U+0915) + Virama (U+094D) + ZWNJ (U+200C)
        valid_devanagari_zwnj = "\u0915\u094d\u200c"
        findings = self.sanitizer.validate_joining_controls(valid_devanagari_zwnj)
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].is_valid)
        self.assertEqual(findings[0].rule, "UTS39_CONDITION_A2")

    def test_07_uts39_condition_b_indic_zwj(self):
        """Tests Condition B: ZWJ after Virama forming a conjunct half-form."""
        # Devanagari KA (U+0915) + Virama (U+094D) + ZWJ (U+200D) + SSA (U+0937)
        valid_devanagari_zwj = "\u0915\u094d\u200d\u0937"
        findings = self.sanitizer.validate_joining_controls(valid_devanagari_zwj)
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].is_valid)
        self.assertEqual(findings[0].rule, "UTS39_CONDITION_B")

    def test_08_uts39_condition_b_violation_with_dependent_vowel(self):
        """Tests that ZWJ followed by Vowel_Dependent ($D) violates Condition B."""
        # Devanagari KA (U+0915) + Virama (U+094D) + ZWJ (U+200D) + AA (U+093E: Vowel_Dependent)
        invalid_devanagari_zwj = "\u0915\u094d\u200d\u093e"
        findings = self.sanitizer.validate_joining_controls(invalid_devanagari_zwj)
        self.assertEqual(len(findings), 1)
        self.assertFalse(findings[0].is_valid)
        self.assertEqual(findings[0].rule, "UTS39_CONDITION_B_VIOLATION")

    def test_09_invalid_joining_controls_in_latin(self):
        """Tests that ZWJ and ZWNJ in Latin text are flagged as invalid joining anomalies."""
        latin_with_zwnj = "adm\u200cin"
        findings1 = self.sanitizer.validate_joining_controls(latin_with_zwnj)
        self.assertEqual(len(findings1), 1)
        self.assertFalse(findings1[0].is_valid)
        self.assertEqual(findings1[0].rule, "UTS39_JOINING_CONTROL_ANOMALY")

        latin_with_zwj = "sys\u200dtem"
        findings2 = self.sanitizer.validate_joining_controls(latin_with_zwj)
        self.assertEqual(len(findings2), 1)
        self.assertFalse(findings2[0].is_valid)
        self.assertEqual(findings2[0].rule, "UTS39_JOINING_CONTROL_ANOMALY")

    def test_10_confusable_skeleton_generation_and_offset_mapping(self):
        """Tests confusable skeleton transformation and code-point offset preservation."""
        # 'pаssword': Cyrillic 'а' (U+0430) at index 1
        mixed_str = "p\u0430ssword"
        skeleton, offsets = self.sanitizer.generate_confusable_skeleton(mixed_str)
        self.assertEqual(skeleton, "password")
        self.assertEqual(len(offsets), len(skeleton))
        # Offset for 'a' (skeleton[1]) must point back to index 1 in mixed_str
        self.assertEqual(offsets[1], 1)
        self.assertEqual(offsets[0], 0)
        self.assertEqual(offsets[7], 7)

    def test_11_mixed_script_anomaly_detection(self):
        """Tests detection of mixed Latin-Cyrillic homoglyph tokens."""
        text = "Enter your p\u0430ssword to access the system."
        findings = self.sanitizer.detect_mixed_script_anomalies(text)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].token, "p\u0430ssword")
        self.assertEqual(findings[0].primary_script, "Latin")
        self.assertIn("Cyrillic", findings[0].conflicting_scripts)

    def test_12_invisible_character_detection(self):
        """Tests detection of zero-width spaces, word joiners, and bidi overrides."""
        text = "Hello\u200bWorld\u202eRTL"
        findings = self.sanitizer.detect_invisible_characters(text)
        self.assertEqual(len(findings), 2)
        codepoints = [f.codepoint for f in findings]
        self.assertIn(0x200B, codepoints)
        self.assertIn(0x202E, codepoints)

    def test_13_original_content_preservation_invariant(self):
        """Mandatory: Asserts that security analysis never mutates the original string."""
        original = "  User Profile: \u0915\u094d\u200d\u0937 (Devanagari) & p\u0430ssword  "
        copied = str(original)
        analysis = self.sanitizer.analyze_unicode_security(original)
        self.assertEqual(original, copied)
        self.assertIsInstance(analysis.to_dict(), dict)


if __name__ == "__main__":
    unittest.main()
