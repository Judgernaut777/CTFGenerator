# Getting started

CTFGenerator is an AI-resistant CTF platform: a deterministic generator core
plus a self-hosted competition platform (see the [README](../README.md) for the
product overview). Find your role below and follow the linked doc.

## Operator / deployer

You are standing up and running a deployment.

1. [docs/HOSTING.md](HOSTING.md) — deploy the supported platform (control plane,
   PostgreSQL, isolated workers) behind a TLS reverse proxy. §0 is the supported
   path; §1 onward is the legacy single-process `ctfgen serve` demo.
2. [docs/operations/configuration.md](operations/configuration.md) — the
   `CTFGEN_*` environment reference: which process needs which vars, and the
   secrets-stay-in-the-env rule.

## Challenge author

You are writing a new challenge family.

- [docs/CHALLENGE_SDK.md](CHALLENGE_SDK.md) — the supported, semver-stable
  authoring surface (`ctf_generator.sdk`): register a family through the plugin
  boundary and render deterministic bundles.

## Contestant

You are competing in an event.

- [docs/web/contestant-portal.md](web/contestant-portal.md) — the
  contestant-facing web portal at `/app`: your competitions, the published
  challenge catalog, flag submission, and your team's submission history.

## CLI user

You are operating a running deployment from a terminal or CI.

- [docs/supported-cli.md](supported-cli.md) — the supported platform CLI
  (`ctfgen <area> <verb>`), an HTTP client over `/api/v1` with a scoped session
  token, and its boundary against the legacy generator commands.

---

For the generator core itself (`ctfgen create|spec|validate|score|...`,
CVE-driven generation, the live-adversarial engine, and the three signals of
AI-resistance), the [README](../README.md) is the reference.
</content>
