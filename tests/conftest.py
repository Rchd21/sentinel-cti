from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def certfr_sample() -> bytes:
    return (FIXTURES / "certfr_avis_sample.xml").read_bytes()
