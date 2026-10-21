from dataclasses import asdict, dataclass, field

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Finding:
    """One observation about the target.

    weight  -- contribution to the threat risk score (0..1, combined probabilistically)
    penalty -- points removed from the security posture score (0..100)
    A finding can carry either, both, or neither (purely informational).
    """

    id: str
    title: str
    severity: str = "info"
    weight: float = 0.0
    penalty: int = 0
    evidence: str = ""
    recommendation: str = ""
    category: str = ""

    @property
    def axis(self):
        if self.weight > 0:
            return "threat"
        if self.penalty > 0:
            return "posture"
        return "info"

    def to_dict(self):
        d = asdict(self)
        d["axis"] = self.axis
        return d


@dataclass
class Section:
    """What a single check returns: display data plus findings."""

    data: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)

    def flag(self, id, title, severity="info", weight=0.0, penalty=0, evidence="", fix=""):
        self.findings.append(
            Finding(id=id, title=title, severity=severity, weight=weight, penalty=penalty,
                    evidence=str(evidence)[:600], recommendation=fix)
        )
