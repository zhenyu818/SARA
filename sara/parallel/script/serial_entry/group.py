"""Expose the qualified SARA function unchanged for a new measurement driver.

This is a function-object alias, with no wrapper, replacement core, result
transformation or additional cache. The driver owns the original context,
private constructor scopes, bindings, persistence and cleanup.
"""

from script.method_group.sara_group import evaluate_own_inputs

__all__ = ('evaluate_own_inputs',)
