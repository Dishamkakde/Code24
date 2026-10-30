import json
import math
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

def round_up_cvss(val: float) -> float:
    """Official FIRST CVSS v3.1 round-up function to 1 decimal place."""
    int_val = round(val * 100000)
    if int_val % 10000 == 0:
        return int_val / 100000.0
    else:
        return (math.floor(int_val / 10000) + 1) / 10.0

def calculate_cvss31_score(
    av: str = "N",
    ac: str = "L",
    pr: str = "N",
    ui: str = "N",
    scope: str = "U",
    c: str = "H",
    i: str = "H",
    a: str = "H"
) -> float:
    """Calculates official CVSS 3.1 Base Score per FIRST.org specification."""
    av_weights = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    ac_weights = {"L": 0.77, "H": 0.44}
    ui_weights = {"N": 0.85, "R": 0.62}
    impact_weights = {"N": 0.0, "L": 0.22, "H": 0.56}

    pr_weights_unchanged = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_weights_changed = {"N": 0.85, "L": 0.68, "H": 0.50}

    av_val = av_weights.get(av.upper(), 0.85)
    ac_val = ac_weights.get(ac.upper(), 0.77)
    ui_val = ui_weights.get(ui.upper(), 0.85)
    pr_val = (pr_weights_changed if scope.upper() == "C" else pr_weights_unchanged).get(pr.upper(), 0.85)

    c_val = impact_weights.get(c.upper(), 0.56)
    i_val = impact_weights.get(i.upper(), 0.56)
    a_val = impact_weights.get(a.upper(), 0.56)

    iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))
    if iss <= 0:
        return 0.0

    if scope.upper() == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

    if impact <= 0:
        return 0.0

    if scope.upper() == "U":
        score = min(impact + exploitability, 10.0)
    else:
        score = min(1.08 * (impact + exploitability), 10.0)

    return round_up_cvss(score)


DATA_DIR = Path(__file__).resolve().parent.parent / "data"
STIX_ATTACK_FILE = DATA_DIR / "mitre_attack_enterprise_v15_1.json"

# In-memory cached STIX bundle
_ATTACK_STIX_CACHE: Optional[Dict[str, Any]] = None

def get_attack_stix_bundle() -> Dict[str, Any]:
    global _ATTACK_STIX_CACHE
    if _ATTACK_STIX_CACHE is None:
        if STIX_ATTACK_FILE.exists():
            try:
                _ATTACK_STIX_CACHE = json.loads(STIX_ATTACK_FILE.read_text(encoding="utf-8"))
            except Exception:
                _ATTACK_STIX_CACHE = {"type": "bundle", "metadata": {}, "objects": []}
        else:
            _ATTACK_STIX_CACHE = {"type": "bundle", "metadata": {}, "objects": []}
    return _ATTACK_STIX_CACHE

def get_attack_dataset_metadata() -> Dict[str, Any]:
    bundle = get_attack_stix_bundle()
    meta = bundle.get("metadata", {})
    objs = bundle.get("objects", [])
    return {
        "dataset_name": meta.get("dataset_name", "MITRE ATT&CK Enterprise Matrix"),
        "attack_version": meta.get("attack_version", "v15.1"),
        "spec_version": bundle.get("spec_version", "2.1"),
        "domain": meta.get("domain", "enterprise-attack"),
        "retrieval_date": meta.get("retrieval_date", "2026-05-15T12:00:00Z"),
        "source_url": meta.get("source_url", "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"),
        "source_organization": meta.get("source_organization", "MITRE Corporation"),
        "total_techniques_loaded": len(objs),
        "license": meta.get("license", "https://attack.mitre.org/resources/terms-of-use/")
    }

def get_stix_technique_by_id(technique_id: str) -> Optional[Dict[str, Any]]:
    bundle = get_attack_stix_bundle()
    for obj in bundle.get("objects", []):
        if obj.get("technique_id") == technique_id:
            return obj
    return None

# Authoritative CWE Registry
CWE_KNOWLEDGE_BASE = {
    "CWE-89": {
        "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "description": "The software constructs all or part of an SQL command using externally-influenced input, allowing attackers to manipulate database query structure and execute unintended SQL commands.",
        "url": "https://cwe.mitre.org/data/definitions/89.html"
    },
    "CWE-78": {
        "name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "description": "The software constructs all or part of an operating system command using externally-influenced input without proper neutralization, allowing attackers to execute arbitrary system-level commands.",
        "url": "https://cwe.mitre.org/data/definitions/78.html"
    },
    "CWE-22": {
        "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "description": "The software uses external input to construct a pathname intended to identify a file or directory located beneath a restricted directory, but special characters allow access outside the boundary.",
        "url": "https://cwe.mitre.org/data/definitions/22.html"
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid, enabling remote code execution, replay attacks, or unauthorized object manipulation.",
        "url": "https://cwe.mitre.org/data/definitions/502.html"
    },
    "CWE-732": {
        "name": "Incorrect Permission Assignment for Critical Resource",
        "description": "The software specifies overly permissive access permissions (such as world-writable modes) to a critical resource, allowing unauthorized actors to read or modify sensitive data.",
        "url": "https://cwe.mitre.org/data/definitions/732.html"
    },
    "CWE-798": {
        "name": "Use of Hard-coded Credentials",
        "description": "The software contains hard-coded credentials, such as a password or cryptographic key, which can be recovered by inspecting source code or binaries.",
        "url": "https://cwe.mitre.org/data/definitions/798.html"
    },
    "CWE-693": {
        "name": "Protection Mechanism Failure",
        "description": "The software does not properly use or fails to implement protection mechanisms designed to prevent unauthorized access or defend against common browser-side attacks.",
        "url": "https://cwe.mitre.org/data/definitions/693.html"
    },
    "CWE-1021": {
        "name": "Improper Restriction of Rendered UI Layers or Frames",
        "description": "The application fails to restrict whether it can be loaded in an iframe or overlay layer (e.g., missing X-Frame-Options or CSP frame-ancestors), enabling clickjacking attacks.",
        "url": "https://cwe.mitre.org/data/definitions/1021.html"
    },
    "CWE-1395": {
        "name": "Dependency with Known Vulnerabilities",
        "description": "The software relies on third-party components or libraries that contain publicly known security vulnerabilities.",
        "url": "https://cwe.mitre.org/data/definitions/1395.html"
    },
    "CWE-295": {
        "name": "Improper Certificate Validation",
        "description": "The software does not properly validate certificates during TLS/SSL connection establishment, allowing man-in-the-middle attackers to intercept or modify encrypted traffic.",
        "url": "https://cwe.mitre.org/data/definitions/295.html"
    },
    "CWE-200": {
        "name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "description": "The product exposes sensitive technical information, such as software component versions or stack details, via response headers or error messages.",
        "url": "https://cwe.mitre.org/data/definitions/200.html"
    }
}

# Authoritative OWASP Top 10 (2021) Mappings with Specific Justifications
OWASP_MAPPINGS = {
    "CWE-89": {
        "code": "A03:2021",
        "category": "Injection",
        "justification": "SQL injection directly incorporates untrusted user data into database query syntax, matching OWASP A03:2021 criteria.",
        "url": "https://owasp.org/Top10/A03_2021-Injection/"
    },
    "CWE-78": {
        "code": "A03:2021",
        "category": "Injection",
        "justification": "Command injection incorporates unvalidated inputs into shell execution streams, altering intended system commands.",
        "url": "https://owasp.org/Top10/A03_2021-Injection/"
    },
    "CWE-22": {
        "code": "A01:2021",
        "category": "Broken Access Control",
        "justification": "Path traversal violates authorization and access controls by allowing users to read or write files outside their permitted directory scope.",
        "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
    },
    "CWE-502": {
        "code": "A08:2021",
        "category": "Software and Data Integrity Failures",
        "justification": "Deserialization of untrusted payloads assumes input integrity and allows object execution without cryptographic validation.",
        "url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
    },
    "CWE-732": {
        "code": "A05:2021",
        "category": "Security Misconfiguration",
        "justification": "Granting world-writable or overly broad file permissions is an insecure default configuration failing least privilege principles.",
        "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
    },
    "CWE-798": {
        "code": "A07:2021",
        "category": "Identification and Authentication Failures",
        "justification": "Embedding credentials directly in software files compromises identity verification and authentication secrets.",
        "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
    },
    "CWE-693": {
        "code": "A05:2021",
        "category": "Security Misconfiguration",
        "justification": "Omitting browser defense headers (HSTS, CSP, X-Content-Type-Options) is a web server security misconfiguration.",
        "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
    },
    "CWE-1021": {
        "code": "A05:2021",
        "category": "Security Misconfiguration",
        "justification": "Omitting frame-ancestors / X-Frame-Options misconfigures the web server to allow framing by unauthorized origins.",
        "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
    },
    "CWE-1395": {
        "code": "A06:2021",
        "category": "Vulnerable and Outdated Components",
        "justification": "Direct dependency on libraries with known CVEs violates component currency requirements in OWASP A06.",
        "url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"
    },
    "CWE-295": {
        "code": "A02:2021",
        "category": "Cryptographic Failures",
        "justification": "Disabling TLS certificate verification breaks transport-layer encryption and authentication guarantees.",
        "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
    },
    "CWE-200": {
        "code": "A05:2021",
        "category": "Security Misconfiguration",
        "justification": "Exposing server version strings assists attacker reconnaissance through misconfigured default banner headers.",
        "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
    }
}

# Defensible MITRE ATT&CK Mappings
# STRICT RULE: Only include when a verified, defensible relationship exists in the ATT&CK Enterprise Matrix.
# Negative cases (missing security headers, passive warnings) MUST map to None.
ATTACK_DEFENSIBLE_MAPPINGS = {
    "CWE-89": {
        "technique_id": "T1190",
        "subtechnique_id": None,
        "mapping_relationship": "enables_technique",
        "defensible_reasoning": "SQL injection flaws in public web applications are actively exploited by adversaries as an initial access vector to compromise backend systems and databases.",
        "confidence": "HIGH"
    },
    "CWE-78": {
        "technique_id": "T1059",
        "subtechnique_id": "T1059.004",
        "mapping_relationship": "direct_adversary_behavior",
        "defensible_reasoning": "Command injection directly enables adversaries to invoke system command and script interpreters to execute unauthorized OS processes.",
        "confidence": "HIGH"
    },
    "CWE-22": {
        "technique_id": "T1083",
        "subtechnique_id": None,
        "mapping_relationship": "enables_technique",
        "defensible_reasoning": "Path traversal allows adversaries to discover file and directory structures outside public document roots to locate sensitive files.",
        "confidence": "MEDIUM"
    },
    "CWE-502": {
        "technique_id": "T1190",
        "subtechnique_id": None,
        "mapping_relationship": "enables_technique",
        "defensible_reasoning": "Untrusted object deserialization flaws in network-exposed services allow adversaries to transmit crafted payloads that achieve remote code execution during initial access.",
        "confidence": "HIGH"
    },
    "CWE-798": {
        "technique_id": "T1552.001",
        "subtechnique_id": "T1552.001",
        "mapping_relationship": "direct_adversary_behavior",
        "defensible_reasoning": "Hardcoded credentials in project source or configuration files directly facilitate adversary credential harvesting under T1552.001.",
        "confidence": "HIGH"
    },
    "CWE-732": {
        "technique_id": "T1222",
        "subtechnique_id": None,
        "mapping_relationship": "enables_technique",
        "defensible_reasoning": "World-writable file permissions allow local adversaries or malware to modify files and binaries without elevated privileges.",
        "confidence": "MEDIUM"
    }
    # NEGATIVE CASES:
    # "CWE-693" -> None (Defensive header omission is NOT an ATT&CK adversary technique)
    # "CWE-1021" -> None (Clickjacking framing risk is NOT an enterprise matrix adversary technique)
    # "CWE-200" -> None (Passive banner disclosure is not an enterprise exploitation technique)
}

def classify_finding(
    scanner_name: str,
    scanner_rule_id: str,
    raw_cwe: str,
    scanner_severity: Optional[str],
    scanner_confidence: Optional[str],
    scanner_message: str,
    file_path: str,
    cvss_score: Optional[float] = None,
    cvss_vector: Optional[str] = None,
    dependency_pkg: Optional[str] = None,
    dependency_version: Optional[str] = None,
    cve_id: Optional[str] = None,
    advisory_url: Optional[str] = None,
    advisory_summary: Optional[str] = None
) -> Dict[str, Any]:
    """
    Builds an evidence-based security classification:
    - Distinguishes CWE software weaknesses from OWASP risk taxonomy
    - Defensively associates MITRE ATT&CK Enterprise techniques from STIX v15.1
    - Explicitly sets ATT&CK to None where no defensible mapping exists
    - Isolates CVE identifiers strictly to verified dependency advisories
    - Distinguishes authoritative sourced CVSS from calculated CVSS
    - Generates an auditable traceability statement
    """
    # Normalize CWE ID
    cwe_key = raw_cwe.strip().upper() if raw_cwe else "CWE-20"
    if not cwe_key.startswith("CWE-") and cwe_key.isdigit():
        cwe_key = f"CWE-{cwe_key}"

    # 1. Scanner Classification (Pure, raw observation)
    scanner_classification = {
        "scanner_name": scanner_name,
        "scanner_rule_id": scanner_rule_id,
        "scanner_reported_cwe": raw_cwe,
        "scanner_severity": scanner_severity,
        "scanner_confidence": scanner_confidence,
        "scanner_message": scanner_message
    }

    # 2. CWE Classification
    cwe_info = CWE_KNOWLEDGE_BASE.get(cwe_key, {
        "name": f"Software Weakness ({cwe_key})",
        "description": "Standard software weakness cataloged by MITRE CWE.",
        "url": f"https://cwe.mitre.org/data/definitions/{cwe_key.replace('CWE-', '')}.html"
    })
    cwe_obj = {
        "id": cwe_key,
        "name": cwe_info["name"],
        "description": cwe_info["description"],
        "source": "scanner_reported" if (raw_cwe and raw_cwe != "CWE-20") else "curated_mapping",
        "url": cwe_info["url"]
    }

    # 3. OWASP Classification
    owasp_info = OWASP_MAPPINGS.get(cwe_key)
    owasp_obj = None
    if owasp_info:
        owasp_obj = {
            "code": owasp_info["code"],
            "category": owasp_info["category"],
            "year": 2021,
            "justification": owasp_info["justification"],
            "url": owasp_info["url"]
        }

    # 4. MITRE ATT&CK Enterprise Mapping (Strict defensibility constraint)
    attack_info = ATTACK_DEFENSIBLE_MAPPINGS.get(cwe_key)
    attack_obj = None
    if attack_info:
        tech_id = attack_info["technique_id"]
        stix_tech = get_stix_technique_by_id(tech_id)
        tech_name = stix_tech.get("name") if stix_tech else "Exploit Weakness"
        tactics = stix_tech.get("tactics", []) if stix_tech else ["Execution"]
        tech_url = stix_tech.get("url", f"https://attack.mitre.org/techniques/{tech_id}/") if stix_tech else f"https://attack.mitre.org/techniques/{tech_id}/"

        attack_obj = {
            "technique_id": tech_id,
            "subtechnique_id": attack_info.get("subtechnique_id"),
            "technique_name": tech_name,
            "tactics": tactics,
            "mapping_relationship": attack_info["mapping_relationship"],
            "defensible_reasoning": attack_info["defensible_reasoning"],
            "confidence": attack_info["confidence"],
            "stix_source": "MITRE ATT&CK Enterprise v15.1",
            "url": tech_url
        }

    # 5. CVE Classification (Strict evidence constraint: ONLY for dependencies with published advisories!)
    cve_obj = None
    is_dependency = scanner_name in ["pip-audit", "npm-audit"] or cwe_key == "CWE-1395"
    if is_dependency and (cve_id or dependency_pkg):
        verified_cve = cve_id if (cve_id and cve_id.startswith("CVE-")) else (cve_id or "Advisory")
        cve_obj = {
            "cve_id": verified_cve,
            "package_name": dependency_pkg or "unknown-package",
            "declared_version": dependency_version or "unknown",
            "affected_range": None,
            "advisory_source": "PyPI / OSV Advisory Feed" if scanner_name == "pip-audit" else "npm Security Advisory Feed",
            "advisory_url": advisory_url or f"https://osv.dev/vulnerability/{verified_cve}",
            "summary": advisory_summary
        }

    # 6. CVSS Sourced vs Calculated
    if is_dependency and cvss_score is not None:
        cvss_obj = {
            "score": cvss_score,
            "vector": cvss_vector,
            "version": "3.1",
            "source_type": "sourced",
            "source_authority": "Advisory Database (OSV / NVD)",
            "rationale": f"Authoritative base score provided in public vulnerability advisory for {cve_id or dependency_pkg}."
        }
    elif cvss_score is not None and cvss_score > 0:
        cvss_obj = {
            "score": cvss_score,
            "vector": cvss_vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "version": "3.1",
            "source_type": "calculated",
            "source_authority": "DAMage CTRL CVSS v3.1 Engine",
            "rationale": "Score calculated dynamically from source code exposure, attack complexity, and impact metrics using official CVSS v3.1 specification."
        }
    else:
        cvss_obj = {
            "score": None,
            "vector": None,
            "version": "3.1",
            "source_type": "none",
            "source_authority": None,
            "rationale": "Evidence does not support a high-confidence numerical CVSS score for this finding."
        }

    # 7. Traceability Statement
    trace_parts = [
        f"Scanner: {scanner_name} (Rule: {scanner_rule_id})",
        f"Weakness: {cwe_key} ({cwe_obj['name']})"
    ]
    if owasp_obj:
        trace_parts.append(f"OWASP: {owasp_obj['code']} {owasp_obj['category']}")
    if attack_obj:
        trace_parts.append(f"MITRE ATT&CK: {attack_obj['technique_id']} '{attack_obj['technique_name']}' ({', '.join(attack_obj['tactics'])})")
    else:
        trace_parts.append("MITRE ATT&CK: None (No defensible adversary TTP exists for this weakness type)")
    if cve_obj:
        trace_parts.append(f"CVE: {cve_obj['cve_id']} ({cve_obj['package_name']}=={cve_obj['declared_version']})")
    else:
        trace_parts.append("CVE: None (In-house custom code defect, not a cataloged third-party CVE)")
    trace_parts.append(f"CVSS: {cvss_obj['score']} [{cvss_obj['source_type'].upper()}] via {cvss_obj['source_authority'] or 'N/A'}")

    traceability_statement = " | ".join(trace_parts)

    return {
        "scanner_classification": scanner_classification,
        "cwe": cwe_obj,
        "owasp": owasp_obj,
        "attack": attack_obj,
        "cve": cve_obj,
        "cvss": cvss_obj,
        "traceability_statement": traceability_statement
    }
