"""Public free-proxy harvesting, validation, and evidence-graded classification.

Read docs/PROXY_HARVESTER.md before operating this. The short version: public
free-proxy sources yield disposable, unvetted, short-lived open proxies. This
package validates them honestly and labels them conservatively. It does not, and
cannot, produce a verified residential proxy pool from unauthenticated public
data -- see the "Constraint analysis" section of that document.
"""

from .models import (
    ANONYMOUS,
    ELITE,
    TRANSPARENT,
    Classification,
    ProxyCandidate,
    ValidationResult,
    WorkingProxy,
)
from .sources import Source, default_sources, load_config, select_language, sources_from_config
from .stealth import StealthConfig, StealthRotator
from .store import HarvestStore
from .validate import ValidationConfig, ValidationReport, validate_all
from .cycle import CycleConfig, ProxyHarvester
from .export import export_working_set

__all__ = [
    "ANONYMOUS",
    "ELITE",
    "TRANSPARENT",
    "Classification",
    "CycleConfig",
    "HarvestStore",
    "ProxyCandidate",
    "ProxyHarvester",
    "Source",
    "StealthConfig",
    "StealthRotator",
    "ValidationConfig",
    "ValidationReport",
    "ValidationResult",
    "WorkingProxy",
    "default_sources",
    "export_working_set",
    "load_config",
    "select_language",
    "sources_from_config",
    "validate_all",
]
