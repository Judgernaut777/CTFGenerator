"""Pure unit tests for ContainerPolicy -> docker-flag translation (no docker).

Covers the security-critical mapping in
:func:`ctf_generator.infrastructure.runtime.docker_backend.policy_to_run_flags`
and the host-gap logic in :class:`DockerHostProbe`, so the flag enforcement is
verified even on a host with no docker at all.
"""

from __future__ import annotations

import unittest

from ctf_generator.domain.execution.runtime import ContainerPolicy
from ctf_generator.infrastructure.runtime.docker_backend import (
    ACKNOWLEDGEABLE_GAPS,
    DockerHostProbe,
    UnsupportedRuntimeError,
    policy_to_run_flags,
)


def _probe(**overrides) -> DockerHostProbe:
    base = dict(
        server_version="20.10.24",
        architecture="x86_64",
        rootless=True,
        userns_remap=False,
        cgroup_version="2",
        seccomp_enabled=True,
        apparmor_available=True,
        selinux_available=False,
    )
    base.update(overrides)
    return DockerHostProbe(**base)


class FlagTranslationTests(unittest.TestCase):
    def test_every_hardening_field_maps_to_a_flag(self) -> None:
        policy = ContainerPolicy(
            memory_mb=128, cpu_millis=1500, pids_limit=64, tmpfs_mb=32
        )
        flags = policy_to_run_flags(policy, _probe(), non_root_uid=65534)
        joined = " ".join(flags)
        # Non-root user
        self.assertIn("--user", flags)
        self.assertIn("65534:65534", flags)
        # All caps dropped
        self.assertIn("--cap-drop=ALL", flags)
        # no-new-privileges
        self.assertIn("no-new-privileges", flags)
        # read-only rootfs + size-capped, non-exec tmpfs
        self.assertIn("--read-only", flags)
        self.assertIn("/tmp:rw,size=32m,mode=1770,noexec,nosuid,nodev", flags)
        # resource envelope: memory + swap disabled (equal) + cpus + pids
        self.assertIn("128m", flags)
        self.assertEqual(flags.count("128m"), 2)  # --memory and --memory-swap
        self.assertIn("--pids-limit", flags)
        self.assertIn("64", flags)
        self.assertIn("--cpus", flags)
        self.assertIn("1.500", flags)
        # private ipc (no host ipc)
        self.assertIn("--ipc", flags)
        self.assertIn("private", flags)
        # apparmor applied where supported
        self.assertIn("apparmor=docker-default", joined)

    def test_never_emits_host_namespace_or_privileged_flags(self) -> None:
        flags = policy_to_run_flags(ContainerPolicy(memory_mb=64, cpu_millis=250), _probe())
        joined = " ".join(flags)
        for forbidden in (
            "--privileged",
            "--pid=host",
            "--ipc=host",
            "--uts=host",
            "--network=host",
            "seccomp=unconfined",
            "--cap-add",
        ):
            self.assertNotIn(forbidden, joined)

    def test_seccomp_disabled_is_a_hard_refusal(self) -> None:
        with self.assertRaises(UnsupportedRuntimeError):
            policy_to_run_flags(
                ContainerPolicy(memory_mb=64, cpu_millis=250), _probe(seccomp_enabled=False)
            )

    def test_named_custom_seccomp_profile_refused_without_registry(self) -> None:
        policy = ContainerPolicy(
            memory_mb=64, cpu_millis=250, seccomp_profile="my-strict-profile"
        )
        with self.assertRaises(UnsupportedRuntimeError):
            policy_to_run_flags(policy, _probe())

    def test_apparmor_default_on_host_without_apparmor_is_not_applied(self) -> None:
        # runtime-default apparmor on a host lacking AppArmor is a gated outer
        # layer, not a hard refusal: no apparmor flag is emitted.
        flags = policy_to_run_flags(
            ContainerPolicy(memory_mb=64, cpu_millis=250), _probe(apparmor_available=False)
        )
        self.assertNotIn("apparmor", " ".join(flags))

    def test_named_apparmor_profile_without_apparmor_is_refused(self) -> None:
        policy = ContainerPolicy(
            memory_mb=64, cpu_millis=250, apparmor_profile="ctfgen-strict"
        )
        with self.assertRaises(UnsupportedRuntimeError):
            policy_to_run_flags(policy, _probe(apparmor_available=False))


class HostGapTests(unittest.TestCase):
    def test_rootful_host_reports_rootless_and_userns_gaps(self) -> None:
        policy = ContainerPolicy(memory_mb=64, cpu_millis=250)
        gaps = _probe(rootless=False, userns_remap=False).missing_gaps(policy)
        self.assertIn("rootless", gaps)
        self.assertIn("user_namespace", gaps)
        self.assertTrue(gaps <= ACKNOWLEDGEABLE_GAPS)

    def test_userns_remap_covers_the_user_namespace_gap(self) -> None:
        policy = ContainerPolicy(memory_mb=64, cpu_millis=250)
        gaps = _probe(rootless=False, userns_remap=True).missing_gaps(policy)
        self.assertIn("rootless", gaps)
        self.assertNotIn("user_namespace", gaps)

    def test_rootless_host_has_no_gaps(self) -> None:
        policy = ContainerPolicy(memory_mb=64, cpu_millis=250)
        gaps = _probe(rootless=True, apparmor_available=True).missing_gaps(policy)
        self.assertEqual(gaps, frozenset())

    def test_apparmor_missing_is_a_reported_gap(self) -> None:
        policy = ContainerPolicy(memory_mb=64, cpu_millis=250)
        gaps = _probe(rootless=True, apparmor_available=False).missing_gaps(policy)
        self.assertIn("apparmor", gaps)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
