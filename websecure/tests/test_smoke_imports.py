def test_imports():
    import websecure.core.http as http
    import websecure.core.phases as phases
    import websecure.core.reporting as reporting
    assert hasattr(http, 'HttpClient')
    assert hasattr(phases, 'phase_offensive')
    assert hasattr(reporting, 'finalize_reports')
