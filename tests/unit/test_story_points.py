"""Effort in story points (the team's scale), labelled as a generic estimate - not measured hours."""

from scripts.subscription_analysis.guidance import (
    cost_summary,
    effort_label,
    implementation_analysis,
    story_points,
    total_effort_label,
)


def test_effort_is_planned_at_the_smallest_point_covering_its_upper_estimate():
    assert story_points([0.1, 0.25])["points"] == 1
    assert story_points([2, 8])["points"] == 2
    assert story_points([4, 16])["points"] == 5          # 12h is not enough, 20h is
    assert story_points([40, 84])["points"] == 21
    assert story_points([100, 200])["points"] == 55       # the scale has no 34
    big = story_points([300, 400])
    assert big["points"] == 89 and big["more"]
    assert story_points(None) is None and story_points([]) is None


def test_labels_say_it_is_a_generic_estimate():
    assert effort_label([1, 4]) == "1 SP (4h / 0.5 days / 0.03 sprints) (generic estimate)"
    assert effort_label([4, 12]) == "3 SP (12h / 1.5 days / 0.10 sprints) (generic estimate)"
    assert effort_label([300, 400]) == "89+ SP (356h+ / 44.5 days / 4.45 sprints) (generic estimate)"
    assert effort_label(None) == ""
    # several changes: each planned on the scale, points added up
    assert total_effort_label([[1, 4], [4, 12], None]) == "4 SP (16h / 2 days / 0.13 sprints) (generic estimate)"


def test_cost_summary_and_implementation_carry_story_points():
    impl = implementation_analysis({"finding_type": "unattached_managed_disk", "estimated_monthly_savings_usd": 20})
    assert impl["story_points"] >= 1 and impl["effort_estimate"].endswith("(generic estimate)")
    assert "SP (" in cost_summary(impl) and " h" not in cost_summary(impl)
