"""Operator CLI entry points for the control plane (interfaces layer).

Two entry points live here:

* :mod:`ctf_generator.interfaces.cli.admin` -- ``ctfgen-admin``, the direct-DB
  bootstrap that seeds the first admin BEFORE the API can authenticate anyone.
* :mod:`ctf_generator.interfaces.cli.entry` -- ``ctfgen``, a dispatcher that
  routes platform areas (``auth``, ...) to the HTTP :mod:`.platform` CLI and
  delegates every legacy generator command to :func:`ctf_generator.cli.main`.

The platform CLI (:mod:`.client`, :mod:`.config`, :mod:`.output`, :mod:`.errors`,
:mod:`.platform`) talks to the platform HTTP API over the network with a session
bearer token; it holds NO business logic and never touches the database.
"""
