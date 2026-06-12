"""Planned: a response cache for LLM enrichment.

Not implemented yet — this module is an intentional placeholder, not dead code.

TODO: Cache LLM responses keyed by (provider, model, prompt_mode, finding
fingerprint) so re-scans of unchanged findings skip the network round-trip and
the token cost. AIEnricher would consult the cache before calling the provider
and write through on success. A simple on-disk JSON store under a user cache dir
(e.g. ~/.cache/cloudspill/) is enough for v1; mirror the keying style of
enrichers.prompts.PromptLoader's in-memory cache.
"""

from __future__ import annotations
