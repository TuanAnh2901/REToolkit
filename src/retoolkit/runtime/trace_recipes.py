from .trace_models import TraceRecipe
def recipe_for_targets(target_ids, *, duration_seconds=30, capture=("call-count",), sample_every=1):
    return TraceRecipe(tuple(target_ids), duration_seconds, tuple(capture), sample_every)
