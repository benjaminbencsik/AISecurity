"""RedSwarm — human-in-the-loop orchestration framework for authorized pentest work.

Everything an agent does passes through three gates:
  1. ScopeGuard   — the target must be explicitly in scope.
  2. ApprovalQueue — active actions wait for an operator's yes.
  3. AuditLog      — every event is recorded in a tamper-evident chain.

The framework ships no attack logic. It is a workbench: you plug in your own
sub-agent modules and your own PoCs, and the gates keep them inside the rules
of engagement.
"""

__version__ = "0.1.0"
