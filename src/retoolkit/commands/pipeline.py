"""Pipeline commands facade.

Exposes the linear resumable pipeline (plan / run / resume / restart) as a
commands-layer bridge over :mod:`retoolkit.core.pipeline`.

CLI argument parsing and dispatch live in ``cli.py``: ``build_parser()``
registers the ``pipeline`` subcommand with its four sub-actions, and the
``_cmd_pipeline_plan`` / ``_cmd_pipeline_run`` handlers delegate straight to
:func:`retoolkit.core.pipeline.plan` and :func:`retoolkit.core.pipeline.run_pipeline`.
This module exists as the import surface for programmatic and test use.
"""

from retoolkit.core.pipeline import plan, run_pipeline

__all__ = ["plan", "run_pipeline"]
