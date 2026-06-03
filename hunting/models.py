"""
hunting/models.py — Finding and Report dataclasses
"""
from dataclasses import dataclass, field, asdict
from typing import List, Optional
from datetime import datetime


@dataclass
class Finding:
    check_id:    int
    check_name:  str
    severity:    str          # HIGH | MEDIUM | LOW | INFO
    description: str
    evidence:    List[str] = field(default_factory=list)
    skipped:     bool = False
    skip_reason: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class Report:
    vm:        str
    host:      str
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    findings:  List[Finding] = field(default_factory=list)
    error:     Optional[str] = None

    @property
    def high_count(self):
        return sum(1 for f in self.findings if f.severity == "HIGH" and f.evidence)

    @property
    def medium_count(self):
        return sum(1 for f in self.findings if f.severity == "MEDIUM" and f.evidence)

    @property
    def low_count(self):
        return sum(1 for f in self.findings if f.severity == "LOW" and f.evidence)

    @property
    def info_count(self):
        return sum(1 for f in self.findings if f.severity == "INFO" and f.evidence)

    def to_dict(self):
        return {
            "vm":        self.vm,
            "host":      self.host,
            "timestamp": self.timestamp,
            "error":     self.error,
            "summary": {
                "HIGH":   self.high_count,
                "MEDIUM": self.medium_count,
                "LOW":    self.low_count,
                "INFO":   self.info_count,
            },
            "findings": [f.to_dict() for f in self.findings],
        }
