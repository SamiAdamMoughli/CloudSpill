"""Enrichment plugins — optional post-processing for scan results."""

from cloudspill.enrichers.base import Enricher
from cloudspill.enrichers.types import EnrichedFinding

__all__ = ["Enricher", "EnrichedFinding"]