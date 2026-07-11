"""Worker layer: the isolated Execution-Plane processes that build/launch/
validate/solve generated challenges. Communicate with the control plane only
through explicit job and job-result contracts; never modify competition-domain
state directly (see docs/adr/001-control-plane-execution-plane-boundary.md).
"""
