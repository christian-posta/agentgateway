#!/usr/bin/env python3
"""
AAuth Cross-Implementation Validator

This script validates AAuth implementations by:
1. Running test vectors through the Python reference implementation
2. Generating expected outputs for comparison
3. Comparing outputs from different implementations

Usage:
    # Generate reference outputs from Python implementation
    python aauth_validator.py generate --output reference_outputs.json
    
    # Validate another implementation's outputs
    python aauth_validator.py validate --reference reference_outputs.json --candidate candidate_outputs.json
    
    # Run comparison between Python and external implementation via subprocess
    python aauth_validator.py compare --external-cmd "cargo run --bin aauth-test"

Requirements:
    - Python AAuth library in PYTHONPATH
    - cryptography library
    - Test vectors JSON file (aauth-test-vectors.json)
"""

import argparse
import base64
import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Try to import the Python AAuth library
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: cryptography library not available, some tests will be skipped")


@dataclass
class TestResult:
    """Result of a single test case."""
    test_id: str
    test_type: str
    passed: bool
    expected: Any
    actual: Any
    error: Optional[str] = None


@dataclass
class ValidationReport:
    """Complete validation report."""
    implementation: str
    version: str
    total_tests: int
    passed: int
    failed: int
    skipped: int
    results: List[TestResult]


class AAuthValidator:
    """Cross-implementation validator for AAuth."""
    
    def __init__(self, test_vectors_path: str = "aauth-test-vectors.json"):
        self.test_vectors = self._load_test_vectors(test_vectors_path)
        self.test_keys = self._load_test_keys()
    
    def _load_test_vectors(self, path: str) -> Dict:
        """Load test vectors from JSON file."""
        with open(path, 'r') as f:
            return json.load(f)
    
    def _load_test_keys(self) -> Dict:
        """Load and parse test keys."""
        keys = {}
        if not CRYPTO_AVAILABLE:
            return keys
        
        ed25519_data = self.test_vectors["test_keys"]["ed25519"]
        
        # Parse from JWK
        x_b64 = ed25519_data["jwk"]["x"]
        d_b64 = ed25519_data["jwk"]["d"]
        
        # Add padding for base64url decode
        x_padded = x_b64 + '=' * (4 - len(x_b64) % 4)
        d_padded = d_b64 + '=' * (4 - len(d_b64) % 4)
        
        public_bytes = base64.urlsafe_b64decode(x_padded)
        private_bytes = base64.urlsafe_b64decode(d_padded)
        
        keys["ed25519"] = {
            "public_key": Ed25519PublicKey.from_public_bytes(public_bytes),
            "private_key": Ed25519PrivateKey.from_private_bytes(private_bytes),
            "public_bytes": public_bytes,
            "private_bytes": private_bytes,
        }
        
        return keys
    
    # =========================================================================
    # Core Computation Functions (Reference Implementation)
    # =========================================================================
    
    def compute_content_digest(self, body: bytes, algorithm: str = "sha-256") -> str:
        """Compute Content-Digest header value per RFC 9530."""
        if algorithm == "sha-256":
            digest = hashlib.sha256(body).digest()
            digest_b64 = base64.b64encode(digest).decode('ascii')
            return f"sha-256=:{digest_b64}:"
        elif algorithm == "sha-512":
            digest = hashlib.sha512(body).digest()
            digest_b64 = base64.b64encode(digest).decode('ascii')
            return f"sha-512=:{digest_b64}:"
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def compute_jwk_thumbprint(self, jwk: Dict) -> str:
        """Compute JWK Thumbprint per RFC 7638."""
        kty = jwk.get("kty")
        
        # Build canonical JSON based on key type
        if kty == "OKP":
            canonical = {
                "crv": jwk["crv"],
                "kty": kty,
                "x": jwk["x"]
            }
        elif kty == "EC":
            canonical = {
                "crv": jwk["crv"],
                "kty": kty,
                "x": jwk["x"],
                "y": jwk["y"]
            }
        elif kty == "RSA":
            canonical = {
                "e": jwk["e"],
                "kty": kty,
                "n": jwk["n"]
            }
        else:
            raise ValueError(f"Unsupported key type: {kty}")
        
        # Serialize to canonical JSON (sorted keys, no whitespace)
        canonical_json = json.dumps(canonical, separators=(',', ':'), sort_keys=True)
        
        # SHA-256 hash
        hash_bytes = hashlib.sha256(canonical_json.encode('utf-8')).digest()
        
        # Base64url encode without padding
        thumbprint = base64.urlsafe_b64encode(hash_bytes).decode('utf-8').rstrip('=')
        
        return thumbprint
    
    def build_signature_key_header(self, scheme: str, label: str, **params) -> str:
        """Build Signature-Key header value."""
        if scheme == "hwk":
            kty = params.get("kty", "OKP")
            crv = params.get("crv", "Ed25519")
            x = params.get("x", "")
            return f'{label}=(scheme=hwk kty="{kty}" crv="{crv}" x="{x}")'
        elif scheme == "jwks":
            agent_id = params.get("id", "")
            kid = params.get("kid", "key-1")
            parts = [f'scheme=jwks', f'id="{agent_id}"', f'kid="{kid}"']
            if "well-known" in params:
                parts.append(f'well-known="{params["well-known"]}"')
            return f'{label}=({" ".join(parts)})'
        elif scheme == "jwt":
            jwt = params.get("jwt", "")
            return f'{label}=(scheme=jwt jwt="{jwt}")'
        else:
            raise ValueError(f"Unknown scheme: {scheme}")
    
    def build_signature_base(
        self,
        method: str,
        authority: str,
        path: str,
        query: Optional[str],
        headers: Dict[str, str],
        covered_components: List[str],
        signature_params: Dict
    ) -> str:
        """Build signature base string per RFC 9421."""
        lines = []
        
        for component in covered_components:
            if component == "@method":
                value = method
            elif component == "@authority":
                value = authority
            elif component == "@path":
                value = path
            elif component == "@query":
                # Query MUST include leading '?' per RFC 9421
                value = f"?{query}" if query else "?"
            elif component == "signature-key":
                value = headers.get("Signature-Key", headers.get("signature-key", ""))
            else:
                # Regular header (case-insensitive lookup)
                value = None
                for k, v in headers.items():
                    if k.lower() == component.lower():
                        value = v
                        break
                if value is None:
                    raise ValueError(f"Header not found: {component}")
            
            lines.append(f'"{component}": {value}')
        
        # Build @signature-params line
        components_str = " ".join(f'"{c}"' for c in covered_components)
        params_str = f"({components_str})"
        
        if "created" in signature_params:
            params_str += f";created={signature_params['created']}"
        if "keyid" in signature_params:
            params_str += f';keyid="{signature_params["keyid"]}"'
        if "nonce" in signature_params:
            params_str += f';nonce="{signature_params["nonce"]}"'
        
        lines.append(f'"@signature-params": {params_str}')
        
        return "\n".join(lines)
    
    def sign_ed25519(self, data: bytes, private_key: Ed25519PrivateKey) -> bytes:
        """Sign data with Ed25519."""
        return private_key.sign(data)
    
    def verify_ed25519(self, data: bytes, signature: bytes, public_key: Ed25519PublicKey) -> bool:
        """Verify Ed25519 signature."""
        try:
            public_key.verify(signature, data)
            return True
        except Exception:
            return False
    
    # =========================================================================
    # Test Runners
    # =========================================================================
    
    def run_content_digest_tests(self) -> List[TestResult]:
        """Run Content-Digest computation tests."""
        results = []
        
        for test in self.test_vectors.get("content_digest_tests", []):
            test_id = test["id"]
            body = test["body_string"].encode('utf-8')
            expected = test["expected_digest"]
            
            # Determine algorithm from expected
            if expected.startswith("sha-256"):
                algorithm = "sha-256"
            elif expected.startswith("sha-512"):
                algorithm = "sha-512"
            else:
                results.append(TestResult(
                    test_id=test_id,
                    test_type="content_digest",
                    passed=False,
                    expected=expected,
                    actual=None,
                    error="Unknown algorithm"
                ))
                continue
            
            try:
                actual = self.compute_content_digest(body, algorithm)
                passed = actual == expected
                results.append(TestResult(
                    test_id=test_id,
                    test_type="content_digest",
                    passed=passed,
                    expected=expected,
                    actual=actual,
                    error=None if passed else "Digest mismatch"
                ))
            except Exception as e:
                results.append(TestResult(
                    test_id=test_id,
                    test_type="content_digest",
                    passed=False,
                    expected=expected,
                    actual=None,
                    error=str(e)
                ))
        
        return results
    
    def run_jwk_thumbprint_tests(self) -> List[TestResult]:
        """Run JWK Thumbprint computation tests."""
        results = []
        
        for test in self.test_vectors.get("jwk_thumbprint_tests", []):
            test_id = test["id"]
            jwk = test["jwk"]
            expected = test.get("expected_thumbprint")
            expected_canonical = test.get("canonical_json")
            
            try:
                actual = self.compute_jwk_thumbprint(jwk)
                
                # Also verify canonical JSON if provided
                kty = jwk.get("kty")
                if kty == "OKP":
                    canonical = {"crv": jwk["crv"], "kty": kty, "x": jwk["x"]}
                elif kty == "EC":
                    canonical = {"crv": jwk["crv"], "kty": kty, "x": jwk["x"], "y": jwk["y"]}
                else:
                    canonical = {}
                
                actual_canonical = json.dumps(canonical, separators=(',', ':'), sort_keys=True)
                
                if expected:
                    passed = actual == expected
                else:
                    passed = True  # Just verify it runs
                
                if expected_canonical:
                    passed = passed and (actual_canonical == expected_canonical)
                
                results.append(TestResult(
                    test_id=test_id,
                    test_type="jwk_thumbprint",
                    passed=passed,
                    expected={"thumbprint": expected, "canonical": expected_canonical},
                    actual={"thumbprint": actual, "canonical": actual_canonical},
                    error=None if passed else "Thumbprint mismatch"
                ))
            except Exception as e:
                results.append(TestResult(
                    test_id=test_id,
                    test_type="jwk_thumbprint",
                    passed=False,
                    expected=expected,
                    actual=None,
                    error=str(e)
                ))
        
        return results
    
    def run_signature_base_tests(self) -> List[TestResult]:
        """Run signature base construction tests."""
        results = []
        
        for test in self.test_vectors.get("signature_base_tests", []):
            test_id = test["id"]
            request = test["request"]
            covered = test["covered_components"]
            sig_params = test["signature_params"]
            expected_base = test.get("expected_signature_base")
            
            # Build headers dict including Signature-Key if provided
            headers = dict(request.get("headers", {}))
            if "signature_key_header" in test:
                headers["Signature-Key"] = test["signature_key_header"]
            
            try:
                actual = self.build_signature_base(
                    method=request["method"],
                    authority=request["authority"],
                    path=request["path"],
                    query=request.get("query"),
                    headers=headers,
                    covered_components=covered,
                    signature_params=sig_params
                )
                
                if expected_base:
                    passed = actual == expected_base
                else:
                    passed = True  # Just verify it runs
                
                results.append(TestResult(
                    test_id=test_id,
                    test_type="signature_base",
                    passed=passed,
                    expected=expected_base,
                    actual=actual,
                    error=None if passed else "Signature base mismatch"
                ))
            except Exception as e:
                results.append(TestResult(
                    test_id=test_id,
                    test_type="signature_base",
                    passed=False,
                    expected=expected_base,
                    actual=None,
                    error=str(e)
                ))
        
        return results
    
    def run_signature_tests(self) -> List[TestResult]:
        """Run Ed25519 signature tests."""
        results = []
        
        if not CRYPTO_AVAILABLE:
            return results
        
        # Test RFC 9421 B.2.6 specifically (has known signature)
        for test in self.test_vectors.get("signature_base_tests", []):
            if test["id"] != "sigbase-rfc9421-b26":
                continue
            
            test_id = test["id"] + "-sign"
            expected_sig = test.get("expected_signature")
            
            if not expected_sig:
                continue
            
            request = test["request"]
            covered = test["covered_components"]
            sig_params = test["signature_params"]
            
            headers = dict(request.get("headers", {}))
            
            try:
                sig_base = self.build_signature_base(
                    method=request["method"],
                    authority=request["authority"],
                    path=request["path"],
                    query=request.get("query"),
                    headers=headers,
                    covered_components=covered,
                    signature_params=sig_params
                )
                
                # Sign with Ed25519
                key = self.test_keys["ed25519"]["private_key"]
                signature = self.sign_ed25519(sig_base.encode('utf-8'), key)
                sig_b64 = base64.b64encode(signature).decode('ascii')
                
                # Verify signature
                public_key = self.test_keys["ed25519"]["public_key"]
                verified = self.verify_ed25519(sig_base.encode('utf-8'), signature, public_key)
                
                # Extract expected signature bytes and verify
                # Format: sig-b26=:base64:
                expected_b64 = expected_sig.split(':')[1]
                expected_bytes = base64.b64decode(expected_b64)
                expected_verified = self.verify_ed25519(
                    sig_base.encode('utf-8'), 
                    expected_bytes, 
                    public_key
                )
                
                results.append(TestResult(
                    test_id=test_id,
                    test_type="signature",
                    passed=verified and expected_verified,
                    expected={
                        "signature": expected_sig,
                        "verifies": True
                    },
                    actual={
                        "signature": f"sig=:{sig_b64}:",
                        "our_verifies": verified,
                        "expected_verifies": expected_verified
                    },
                    error=None
                ))
            except Exception as e:
                results.append(TestResult(
                    test_id=test_id,
                    test_type="signature",
                    passed=False,
                    expected=expected_sig,
                    actual=None,
                    error=str(e)
                ))
        
        return results
    
    def run_all_tests(self) -> ValidationReport:
        """Run all test categories."""
        all_results = []
        
        all_results.extend(self.run_content_digest_tests())
        all_results.extend(self.run_jwk_thumbprint_tests())
        all_results.extend(self.run_signature_base_tests())
        all_results.extend(self.run_signature_tests())
        
        passed = sum(1 for r in all_results if r.passed)
        failed = sum(1 for r in all_results if not r.passed and r.error != "skipped")
        skipped = sum(1 for r in all_results if r.error == "skipped")
        
        return ValidationReport(
            implementation="python-reference",
            version="1.0.0",
            total_tests=len(all_results),
            passed=passed,
            failed=failed,
            skipped=skipped,
            results=all_results
        )
    
    # =========================================================================
    # Output Generation
    # =========================================================================
    
    def generate_reference_outputs(self) -> Dict:
        """Generate reference outputs for cross-implementation comparison."""
        outputs = {
            "implementation": "python-reference",
            "version": "1.0.0",
            "content_digests": {},
            "jwk_thumbprints": {},
            "signature_bases": {},
            "signatures": {}
        }
        
        # Content digests
        for test in self.test_vectors.get("content_digest_tests", []):
            body = test["body_string"].encode('utf-8')
            outputs["content_digests"][test["id"]] = {
                "sha256": self.compute_content_digest(body, "sha-256"),
                "sha512": self.compute_content_digest(body, "sha-512"),
            }
        
        # JWK thumbprints
        for test in self.test_vectors.get("jwk_thumbprint_tests", []):
            jwk = test["jwk"]
            kty = jwk.get("kty")
            if kty == "OKP":
                canonical = {"crv": jwk["crv"], "kty": kty, "x": jwk["x"]}
            elif kty == "EC":
                canonical = {"crv": jwk["crv"], "kty": kty, "x": jwk["x"], "y": jwk["y"]}
            else:
                continue
            
            outputs["jwk_thumbprints"][test["id"]] = {
                "canonical_json": json.dumps(canonical, separators=(',', ':'), sort_keys=True),
                "thumbprint": self.compute_jwk_thumbprint(jwk)
            }
        
        # Signature bases
        for test in self.test_vectors.get("signature_base_tests", []):
            request = test["request"]
            covered = test["covered_components"]
            sig_params = test["signature_params"]
            
            headers = dict(request.get("headers", {}))
            if "signature_key_header" in test:
                headers["Signature-Key"] = test["signature_key_header"]
            
            try:
                sig_base = self.build_signature_base(
                    method=request["method"],
                    authority=request["authority"],
                    path=request["path"],
                    query=request.get("query"),
                    headers=headers,
                    covered_components=covered,
                    signature_params=sig_params
                )
                
                outputs["signature_bases"][test["id"]] = {
                    "signature_base": sig_base,
                    "signature_base_hex": sig_base.encode('utf-8').hex()
                }
            except Exception as e:
                outputs["signature_bases"][test["id"]] = {"error": str(e)}
        
        return outputs
    
    def compare_outputs(self, reference: Dict, candidate: Dict) -> ValidationReport:
        """Compare candidate outputs against reference."""
        results = []
        
        # Compare content digests
        for test_id, ref_data in reference.get("content_digests", {}).items():
            cand_data = candidate.get("content_digests", {}).get(test_id, {})
            
            for algo in ["sha256", "sha512"]:
                expected = ref_data.get(algo)
                actual = cand_data.get(algo)
                passed = expected == actual
                
                results.append(TestResult(
                    test_id=f"{test_id}-{algo}",
                    test_type="content_digest",
                    passed=passed,
                    expected=expected,
                    actual=actual,
                    error=None if passed else "Digest mismatch"
                ))
        
        # Compare JWK thumbprints
        for test_id, ref_data in reference.get("jwk_thumbprints", {}).items():
            cand_data = candidate.get("jwk_thumbprints", {}).get(test_id, {})
            
            expected = ref_data.get("thumbprint")
            actual = cand_data.get("thumbprint")
            passed = expected == actual
            
            results.append(TestResult(
                test_id=test_id,
                test_type="jwk_thumbprint",
                passed=passed,
                expected=expected,
                actual=actual,
                error=None if passed else "Thumbprint mismatch"
            ))
        
        # Compare signature bases (byte-for-byte)
        for test_id, ref_data in reference.get("signature_bases", {}).items():
            cand_data = candidate.get("signature_bases", {}).get(test_id, {})
            
            expected_hex = ref_data.get("signature_base_hex")
            actual_hex = cand_data.get("signature_base_hex")
            passed = expected_hex == actual_hex
            
            results.append(TestResult(
                test_id=test_id,
                test_type="signature_base",
                passed=passed,
                expected=ref_data.get("signature_base"),
                actual=cand_data.get("signature_base"),
                error=None if passed else "Signature base mismatch (compare hex for byte diff)"
            ))
        
        passed_count = sum(1 for r in results if r.passed)
        failed_count = len(results) - passed_count
        
        return ValidationReport(
            implementation=candidate.get("implementation", "unknown"),
            version=candidate.get("version", "unknown"),
            total_tests=len(results),
            passed=passed_count,
            failed=failed_count,
            skipped=0,
            results=results
        )


def main():
    parser = argparse.ArgumentParser(description="AAuth Cross-Implementation Validator")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Generate command
    gen_parser = subparsers.add_parser("generate", help="Generate reference outputs")
    gen_parser.add_argument("--vectors", default="aauth-test-vectors.json",
                          help="Path to test vectors JSON")
    gen_parser.add_argument("--output", default="reference_outputs.json",
                          help="Output file for reference data")
    
    # Validate command
    val_parser = subparsers.add_parser("validate", help="Validate candidate outputs")
    val_parser.add_argument("--vectors", default="aauth-test-vectors.json",
                          help="Path to test vectors JSON")
    val_parser.add_argument("--reference", required=True, help="Reference outputs JSON")
    val_parser.add_argument("--candidate", required=True, help="Candidate outputs JSON")
    val_parser.add_argument("--output", help="Output file for validation report")
    
    # Test command (run internal tests)
    test_parser = subparsers.add_parser("test", help="Run internal validation tests")
    test_parser.add_argument("--vectors", default="aauth-test-vectors.json",
                           help="Path to test vectors JSON")
    test_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.command == "generate":
        validator = AAuthValidator(args.vectors)
        outputs = validator.generate_reference_outputs()
        
        with open(args.output, 'w') as f:
            json.dump(outputs, f, indent=2)
        
        print(f"Generated reference outputs: {args.output}")
        print(f"  Content digests: {len(outputs['content_digests'])}")
        print(f"  JWK thumbprints: {len(outputs['jwk_thumbprints'])}")
        print(f"  Signature bases: {len(outputs['signature_bases'])}")
    
    elif args.command == "validate":
        validator = AAuthValidator(args.vectors)
        
        with open(args.reference, 'r') as f:
            reference = json.load(f)
        
        with open(args.candidate, 'r') as f:
            candidate = json.load(f)
        
        report = validator.compare_outputs(reference, candidate)
        
        print(f"\nValidation Report")
        print(f"================")
        print(f"Implementation: {report.implementation}")
        print(f"Total tests: {report.total_tests}")
        print(f"Passed: {report.passed}")
        print(f"Failed: {report.failed}")
        
        if report.failed > 0:
            print(f"\nFailed tests:")
            for result in report.results:
                if not result.passed:
                    print(f"  - {result.test_id}: {result.error}")
                    print(f"    Expected: {result.expected}")
                    print(f"    Actual:   {result.actual}")
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(asdict(report), f, indent=2)
        
        sys.exit(0 if report.failed == 0 else 1)
    
    elif args.command == "test":
        validator = AAuthValidator(args.vectors)
        report = validator.run_all_tests()
        
        print(f"\nInternal Test Report")
        print(f"====================")
        print(f"Total tests: {report.total_tests}")
        print(f"Passed: {report.passed}")
        print(f"Failed: {report.failed}")
        print(f"Skipped: {report.skipped}")
        
        if args.verbose or report.failed > 0:
            for result in report.results:
                status = "✓" if result.passed else "✗"
                print(f"  {status} {result.test_id}")
                if not result.passed and args.verbose:
                    print(f"    Error: {result.error}")
                    if result.expected != result.actual:
                        print(f"    Expected: {result.expected}")
                        print(f"    Actual:   {result.actual}")
        
        sys.exit(0 if report.failed == 0 else 1)


if __name__ == "__main__":
    main()
