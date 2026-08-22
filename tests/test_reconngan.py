import httpx
import json
from reconngan import grade_meets_threshold
from reconngan import write_json_report
from reconngan import (
    normalize_url,
    validate_hsts,
)
import pytest
from reconngan import (
    build_report_data,
)
from reconngan import analyze_headers
from reconngan import fetch_url
from reconngan import (
    Finding,
    calculate_grade,
    calculate_score,
    normalize_url,
    validate_hsts,
    validate_x_content_type_options,
    validate_x_frame_options,
)
from reconngan import validate_x_content_type_options
from reconngan import validate_x_frame_options

@pytest.mark.parametrize(
    "actual, minimum, expected",
    [
        ("A", "A", True),
        ("A", "B", True),
        ("B", "B", True),
        ("B", "A", False),
        ("C", "B", False),
        ("C", "C", True),
        ("D", "C", False),
        ("F", "D", False),
        ("F", "F", True),
    ],
)
def test_grade_meets_threshold(
    actual,
    minimum,
    expected,
):
    assert (
        grade_meets_threshold(
            actual,
            minimum,
        )
        is expected
    )
