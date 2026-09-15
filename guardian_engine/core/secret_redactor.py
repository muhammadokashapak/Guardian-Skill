import re
from typing import Tuple, List, Dict

class SecretRedactor:
    PATTERNS: List[Tuple[str, re.Pattern]] = [
        ("AWS_ACCESS_KEY", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
        ("AWS_SECRET_KEY", re.compile(r"(?i)(?:aws_secret_access_key|aws_secret)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?")),
        ("GITHUB_TOKEN", re.compile(r"\b(gh_?[pousr]_[A-Za-z0-9_]{16,255})\b")),
        ("SLACK_TOKEN", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,80})\b")),
        ("SLACK_WEBHOOK", re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+")),
        ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
        ("JWT_TOKEN", re.compile(r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b")),
        ("GENERIC_SECRET", re.compile(r"(?i)(?:secret|token|password|passwd|api_key|apikey)\s*[:=]\s*['\"]([A-Za-z0-9_\-\.\$\#\@\!\%]{8,128})['\"]")),
    ]

    @classmethod
    def redact(cls, text: str) -> Tuple[str, List[Dict[str, str]]]:
        redacted = text
        findings = []

        for name, pattern in cls.PATTERNS:
            for match in pattern.finditer(text):
                full_match = match.group(0)
                # If group 1 exists, redact only group 1, otherwise redact full match
                secret_part = match.group(1) if match.groups() else full_match
                if len(secret_part) >= 6:
                    findings.append({
                        "type": name,
                        "placeholder": f"[REDACTED_{name}]"
                    })
                    redacted = redacted.replace(secret_part, f"[REDACTED_{name}]")

        return redacted, findings

    @classmethod
    def contains_secret(cls, text: str) -> bool:
        for _, pattern in cls.PATTERNS:
            if pattern.search(text):
                return True
        return False
