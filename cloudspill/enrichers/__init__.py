"""Enrichment plugins — optional post-processing for scan results."""

from cloudspill.enrichers.base import Enricher

__all__ = ["Enricher"]

# NOTE: Public API: get_enricher(config)