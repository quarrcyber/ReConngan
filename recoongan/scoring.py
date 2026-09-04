from .models import Finding


GRADE_RANK = {
    "F": 0,
    "D": 1,
    "C": 2,
    "B": 3,
    "A": 4,
}


def calculate_score(
    findings: list[Finding]
) -> float:

    score = 0.0

    for finding in findings:

        if finding.status == "OK":
            score += finding.weight

        elif finding.status == "WEAK":
            score += finding.weight * 0.5

    return score


def calculate_grade(
    score: float
) -> str:

    if score >= 90:
        return "A"

    if score >= 80:
        return "B"

    if score >= 70:
        return "C"

    if score >= 60:
        return "D"

    return "F"


def grade_meets_threshold(
    actual_grade: str,
    minimum_grade: str,
) -> bool:

    return (
        GRADE_RANK[actual_grade]
        >= GRADE_RANK[minimum_grade]
    )
