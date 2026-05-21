from scope.core import (
    CoverageEntry,
    CoverageTracker,
    Enumerator,
    ErrorRecord,
    ModuleEnvelope,
    map_bounded,
    write_envelope,
)


def test_task_4_public_api_exports():
    assert Enumerator is not None
    assert CoverageTracker is not None
    assert write_envelope is not None
    assert CoverageEntry is not None
    assert ErrorRecord is not None
    assert ModuleEnvelope is not None
    assert map_bounded is not None
