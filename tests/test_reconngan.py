import httpx
import json
from recoongan import grade_meets_threshold
from recoongan import write_json_report
from recoongan import (
    normalize_url,
    validate_hsts,
)
import pytest
from recoongan import (
    build_report_data,
)
from recoongan import analyze_headers
from recoongan import fetch_url
from recoongan import (
    Finding,
    calculate_grade,
    calculate_score,
    normalize_url,
    validate_hsts,
    validate_x_content_type_options,
    validate_x_frame_options,
)
from recoongan import validate_x_content_type_options
from recoongan import validate_x_frame_options

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
