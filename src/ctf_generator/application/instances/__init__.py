"""Instance-lifecycle application services (M8 slice 1b).

``InstanceLifecycleService`` owns the request/observe/transition/stop/reset/
delete/expire flows and wires the quota reservation (``reservation_id ==
instance_id``, renew-while-live, release-on-stop/expire/archive) to idempotent
corrective job enqueues. ``InstanceReconciler`` is the durable, crash-safe,
generation-fenced pass that converges the observed world onto desired state.

Neither module imports Docker or executes challenge code (the control plane
never runs a container): corrective work is expressed as ``JobQueue`` jobs a
worker claims with scoped credentials in slice 2. Payloads carry references
only -- never flags, tokens, or credentials.
"""
