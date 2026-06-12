"""Enrichment plugins — optional post-processing for scan results."""

from cloudspill.enrichers.base import Enricher
from cloudspill.enrichers.parser import parse_llm_response, strip_think_tags
from cloudspill.enrichers.types import EnrichedFinding

__all__ = ["Enricher", "EnrichedFinding", "parse_llm_response", "strip_think_tags"]