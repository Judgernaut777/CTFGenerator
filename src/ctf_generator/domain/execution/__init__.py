"""Execution-plane identity domain: worker registration, trust, and short-lived
scoped credentials. Pure stdlib value types; concrete storage lives in
infrastructure. (Named ``execution`` -- not ``workers`` -- to avoid colliding
with the future top-level ``ctf_generator.workers`` executable package.)"""
