import unittest
from pathlib import Path

from ctf_generator.models import ResponseSpec, ScenarioSpec, TriggerSpec
from ctf_generator.scenario import (
    AttackerMove,
    NullEnvironmentController,
    ReplayEventSource,
    ScenarioState,
    ScriptedAttacker,
    ScriptedDefender,
    SimEvent,
    SimEventBus,
    evaluate_condition,
    run_scenario,
    seed_to_int,
)


class SeedToIntTests(unittest.TestCase):
    def test_deterministic_same_seed(self) -> None:
        self.assertEqual(seed_to_int("alpha"), seed_to_int("alpha"))

    def test_different_seeds_differ(self) -> None:
        self.assertNotEqual(seed_to_int("alpha"), seed_to_int("beta"))

    def test_returns_int(self) -> None:
        self.assertIsInstance(seed_to_int("anything"), int)


class SimEventBusTests(unittest.TestCase):
    def test_publish_and_all(self) -> None:
        bus = SimEventBus()
        e1 = SimEvent(tick=0, source="attacker", kind="recon")
        e2 = SimEvent(tick=1, source="defender", kind="rotate_credential")
        bus.publish(e1)
        bus.publish(e2)
        self.assertEqual(bus.all(), [e1, e2])

    def test_at_tick_filters(self) -> None:
        bus = SimEventBus()
        e1 = SimEvent(tick=0, source="attacker", kind="recon")
        e2 = SimEvent(tick=1, source="defender", kind="rotate_credential")
        bus.publish(e1)
        bus.publish(e2)
        self.assertEqual(bus.at_tick(1), [e2])

    def test_since_tick(self) -> None:
        bus = SimEventBus()
        e1 = SimEvent(tick=0, source="attacker", kind="recon")
        e2 = SimEvent(tick=1, source="defender", kind="rotate_credential")
        bus.publish(e1)
        bus.publish(e2)
        self.assertEqual(bus.since_tick(0), [e2])

    def test_to_mapping(self) -> None:
        event = SimEvent(tick=2, source="attacker", kind="steal", target="api", payload={"a": "b"})
        self.assertEqual(
            event.to_mapping(),
            {"tick": 2, "source": "attacker", "kind": "steal", "target": "api", "payload": {"a": "b"}},
        )


class ConditionDslTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = ScenarioState()

    def test_empty_condition_is_true(self) -> None:
        self.assertTrue(evaluate_condition("", 5, [], self.state))

    def test_time_plus(self) -> None:
        self.assertFalse(evaluate_condition("time:+3s", 2, [], self.state))
        self.assertTrue(evaluate_condition("time:+3s", 3, [], self.state))

    def test_time_operators(self) -> None:
        self.assertTrue(evaluate_condition("time:==4", 4, [], self.state))
        self.assertTrue(evaluate_condition("time:<5", 4, [], self.state))
        self.assertFalse(evaluate_condition("time:>5", 4, [], self.state))
        self.assertTrue(evaluate_condition("time:<=4", 4, [], self.state))

    def test_event_kind_only(self) -> None:
        events = [SimEvent(tick=0, source="attacker", kind="steal_credential")]
        self.assertTrue(evaluate_condition("event:steal_credential", 0, events, self.state))
        self.assertFalse(evaluate_condition("event:other", 0, events, self.state))

    def test_event_source_and_kind(self) -> None:
        events = [SimEvent(tick=0, source="attacker", kind="steal_credential")]
        self.assertTrue(
            evaluate_condition("event:attacker:steal_credential", 0, events, self.state)
        )
        self.assertFalse(
            evaluate_condition("event:defender:steal_credential", 0, events, self.state)
        )

    def test_checkpoint(self) -> None:
        self.state.checkpoints.add("recon")
        self.assertTrue(evaluate_condition("checkpoint:recon", 0, [], self.state))
        self.assertFalse(evaluate_condition("checkpoint:exploit", 0, [], self.state))

    def test_state_equality(self) -> None:
        self.state.flags["cred:api-token"] = "stolen"
        self.assertTrue(
            evaluate_condition("state:cred:api-token=stolen", 0, [], self.state)
        )
        self.assertFalse(
            evaluate_condition("state:cred:api-token=rotated", 0, [], self.state)
        )

    def test_state_inequality(self) -> None:
        self.state.flags["cred:api-token"] = "rotated"
        self.assertTrue(
            evaluate_condition("state:cred:api-token!=stolen", 0, [], self.state)
        )

    def test_count(self) -> None:
        events = [
            SimEvent(tick=0, source="environment", kind="inject_noise"),
            SimEvent(tick=1, source="environment", kind="inject_noise"),
            SimEvent(tick=2, source="environment", kind="inject_noise"),
        ]
        self.assertTrue(evaluate_condition("count:inject_noise>=3", 2, events, self.state))
        self.assertFalse(evaluate_condition("count:inject_noise>=4", 2, events, self.state))

    def test_combined_and(self) -> None:
        self.state.flags["cred:api-token"] = "stolen"
        self.assertTrue(
            evaluate_condition("time:+0s && state:cred:api-token=stolen", 1, [], self.state)
        )
        self.assertFalse(
            evaluate_condition("time:+5s && state:cred:api-token=stolen", 1, [], self.state)
        )

    def test_unknown_clause_raises(self) -> None:
        with self.assertRaises(ValueError):
            evaluate_condition("bogus:thing", 0, [], self.state)


class NullEnvironmentControllerTests(unittest.TestCase):
    def test_records_without_raising(self) -> None:
        controller = NullEnvironmentController()
        event = controller.rotate_credential("api-token", {"reason": "theft"})
        self.assertEqual(event.source, "environment")
        self.assertEqual(event.kind, "rotate_credential")
        self.assertEqual(event.target, "api-token")
        self.assertEqual(controller.recorded, [("rotate_credential", "api-token", {"reason": "theft"})])

    def test_all_four_actions(self) -> None:
        controller = NullEnvironmentController()
        controller.rotate_credential("t1", {})
        controller.patch_route("t2", {})
        controller.quarantine_host("t3", {})
        controller.inject_noise("t4", {})
        self.assertEqual(len(controller.recorded), 4)
        self.assertEqual(
            [action for action, _, _ in controller.recorded],
            ["rotate_credential", "patch_route", "quarantine_host", "inject_noise"],
        )


class ReplayEventSourceTests(unittest.TestCase):
    def test_poll_returns_scripted_events(self) -> None:
        scripted = SimEvent(tick=0, source="sensor", kind="scan_detected", target="perimeter")
        source = ReplayEventSource({0: [scripted]})
        self.assertEqual(source.poll(0), [scripted])

    def test_poll_unknown_tick_empty(self) -> None:
        source = ReplayEventSource({0: [SimEvent(tick=0, source="sensor", kind="scan_detected")]})
        self.assertEqual(source.poll(5), [])

    def test_deterministic_across_instances(self) -> None:
        script = {0: [SimEvent(tick=0, source="sensor", kind="scan_detected", target="perimeter")]}
        source_a = ReplayEventSource(script)
        source_b = ReplayEventSource(script)
        self.assertEqual(source_a.poll(0), source_b.poll(0))


def _build_scripted_run():
    """A defender that rotates a stolen credential mid-run, disrupting an
    attacker whose final move depends on that credential still being valid.
    """
    attacker_moves = [
        AttackerMove(
            tick=0,
            response=ResponseSpec(
                response_id="recon",
                description="Recon the target",
                action="recon",
                payload={"target": "api", "checkpoint": "recon"},
            ),
        ),
        AttackerMove(
            tick=1,
            response=ResponseSpec(
                response_id="steal",
                description="Steal the API credential",
                action="steal_credential",
                payload={
                    "target": "api-token",
                    "checkpoint": "steal_credential",
                    "sets": "cred:api-token=stolen",
                },
            ),
        ),
        AttackerMove(
            tick=2,
            response=ResponseSpec(
                response_id="exploit",
                description="Use the stolen credential to exfiltrate the flag",
                action="exploit_credential",
                payload={"target": "api-token", "checkpoint": "exploit"},
            ),
            precondition="state:cred:api-token=stolen",
        ),
    ]
    attacker = ScriptedAttacker(attacker_moves)

    trigger = TriggerSpec(
        trigger_id="detect-theft",
        description="Detect credential theft",
        condition="event:attacker:steal_credential",
    )
    defender_response = ResponseSpec(
        response_id="rotate",
        description="Rotate the stolen credential",
        action="rotate_credential",
        payload={"target": "api-token"},
    )
    defender = ScriptedDefender(
        triggers=[trigger], trigger_responses={"detect-theft": [defender_response]}
    )

    spec = ScenarioSpec(enabled=True, triggers=[trigger], responses=[defender_response])

    environment = NullEnvironmentController()
    exogenous = SimEvent(tick=0, source="sensor", kind="scan_detected", target="perimeter")
    events = ReplayEventSource({0: [exogenous]})

    report = run_scenario(
        challenge_path=Path("fixtures/fake-challenge"),
        environment=environment,
        events=events,
        defender=defender,
        attacker=attacker,
        spec=spec,
        max_ticks=3,
    )
    return report, environment


class RunScenarioIntegrationTests(unittest.TestCase):
    def test_ticks_run(self) -> None:
        report, _ = _build_scripted_run()
        self.assertEqual(report.ticks_run, 3)

    def test_trigger_fires_exactly_once(self) -> None:
        report, _ = _build_scripted_run()
        self.assertEqual(report.triggers_fired, ["detect-theft"])

    def test_defender_rotated_the_credential(self) -> None:
        report, environment = _build_scripted_run()
        self.assertEqual(
            environment.recorded, [("rotate_credential", "api-token", {"target": "api-token", "trigger_id": "detect-theft"})]
        )

    def test_attacker_final_move_blocked(self) -> None:
        report, _ = _build_scripted_run()
        self.assertEqual(report.attacker_blocked, ["exploit-blocked"])
        self.assertTrue(report.defender_disrupted_attacker)

    def test_attacker_never_reached_final_checkpoint(self) -> None:
        report, _ = _build_scripted_run()
        assert report.final_state is not None
        self.assertEqual(report.final_state.checkpoints, {"recon", "steal_credential"})
        self.assertNotIn("exploit", report.final_state.checkpoints)

    def test_credential_flag_ends_rotated_not_stolen(self) -> None:
        report, _ = _build_scripted_run()
        assert report.final_state is not None
        self.assertEqual(report.final_state.flags["cred:api-token"], "rotated")

    def test_exogenous_event_present_in_timeline(self) -> None:
        report, _ = _build_scripted_run()
        kinds = [event.kind for event in report.timeline]
        self.assertIn("scan_detected", kinds)

    def test_timeline_order_attacker_before_defender_same_tick(self) -> None:
        # The defender's rotate_credential is applied via the environment
        # controller, so it is tagged source="environment" (the actor that
        # performs it), not "defender" -- but it must still be published
        # after the attacker's steal_credential within the same tick, since
        # the defender reacts to what the attacker just did.
        report, _ = _build_scripted_run()
        tick1_events = [event for event in report.timeline if event.tick == 1]
        kinds = [event.kind for event in tick1_events]
        self.assertEqual(kinds.index("steal_credential") < kinds.index("rotate_credential"), True)

    def test_deterministic_repeated_runs_are_equal(self) -> None:
        report_a, _ = _build_scripted_run()
        report_b, _ = _build_scripted_run()
        self.assertEqual(
            [event.to_mapping() for event in report_a.timeline],
            [event.to_mapping() for event in report_b.timeline],
        )
        self.assertEqual(report_a.triggers_fired, report_b.triggers_fired)
        self.assertEqual(report_a.attacker_blocked, report_b.attacker_blocked)
        self.assertEqual(report_a.ticks_run, report_b.ticks_run)
        assert report_a.final_state is not None and report_b.final_state is not None
        self.assertEqual(report_a.final_state.flags, report_b.final_state.flags)
        self.assertEqual(report_a.final_state.checkpoints, report_b.final_state.checkpoints)


class DefaultDefenderFromSpecTests(unittest.TestCase):
    def test_omitted_defender_built_from_spec(self) -> None:
        trigger = TriggerSpec(
            trigger_id="always",
            description="Always fires immediately",
            condition="time:+0s",
        )
        response = ResponseSpec(
            response_id="noise",
            description="Inject some noise",
            action="inject_noise",
            payload={"target": "logs"},
        )
        spec = ScenarioSpec(enabled=True, triggers=[trigger], responses=[response])
        environment = NullEnvironmentController()
        events = ReplayEventSource({})

        report = run_scenario(
            challenge_path=Path("fixtures/fake-challenge"),
            environment=environment,
            events=events,
            spec=spec,
            max_ticks=1,
        )
        self.assertEqual(report.triggers_fired, ["always"])
        self.assertEqual(environment.recorded[0][0], "inject_noise")

    def test_disabled_spec_yields_no_default_defender(self) -> None:
        trigger = TriggerSpec(trigger_id="x", condition="time:+0s")
        response = ResponseSpec(response_id="y", action="inject_noise", payload={"target": "logs"})
        spec = ScenarioSpec(enabled=False, triggers=[trigger], responses=[response])
        environment = NullEnvironmentController()
        events = ReplayEventSource({})

        report = run_scenario(
            challenge_path=Path("fixtures/fake-challenge"),
            environment=environment,
            events=events,
            spec=spec,
            max_ticks=1,
        )
        self.assertEqual(report.triggers_fired, [])
        self.assertEqual(environment.recorded, [])

    def test_no_agents_no_spec_runs_ticks_with_empty_timeline(self) -> None:
        environment = NullEnvironmentController()
        events = ReplayEventSource({})
        report = run_scenario(
            challenge_path=Path("fixtures/fake-challenge"),
            environment=environment,
            events=events,
            max_ticks=2,
        )
        self.assertEqual(report.ticks_run, 2)
        self.assertEqual(report.timeline, [])


if __name__ == "__main__":
    unittest.main()
