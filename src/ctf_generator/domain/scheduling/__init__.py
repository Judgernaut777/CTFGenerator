"""Scheduling & quota domain: capacity accounting and capability-aware worker
selection for the execution plane (M8). Pure stdlib value types; the concrete
counter store and scheduler live in infrastructure. Quota reservation is
race-safe by construction (one row-locked counter per pooled dimension); the
scheduler ranks dispatch-eligible workers without ever executing challenge
code."""
