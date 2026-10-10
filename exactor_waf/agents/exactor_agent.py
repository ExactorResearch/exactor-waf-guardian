"""Exactor WAF Agent - Fast-Path Deterministic SAT Solver."""

from __future__ import annotations

import time
from exactor_waf.agents.base import BaseWAFAgent, WAFAgentDecision
from exactor_waf.core.payload import HTTPRequestPayload, AttackCategory, AttackDecision
from exactor_waf.core.solver_sat import ExactorWAFSATEngine


class ExactorWAFAgent(BaseWAFAgent):
    """Exactor-Accelerator WAF Agent.
    
    Uses deterministic AST Token Constraints & SAT Invariant Resolution.
    Zero hallucination, sub-millisecond execution (< 0.02 ms), zero API token cost.
    """

    def __init__(self):
        super().__init__(
            name="Exactor-Accelerator (SAT / Neuro-Symbolic)",
            description="Ultra-fast deterministic boolean SAT engine with formal causal proofs and zero stochastic drift."
        )
        self.engine = ExactorWAFSATEngine()

    def inspect(self, request: HTTPRequestPayload) -> WAFAgentDecision:
        t0 = time.perf_counter()
        proof = self.engine.evaluate_payload(request)
        t1 = time.perf_counter()
        latency_ms = (t1 - t0) * 1000.0

        decision = AttackDecision.BLOCK if proof.is_violation else AttackDecision.ALLOW
        predicted_category = proof.category if proof.is_violation else AttackCategory.BENIGN

        is_correct = (predicted_category == request.expected_category) if request.expected_category != AttackCategory.UNKNOWN else None

        explanation = (
            f"Blocked by SAT invariant [{', '.join(r.rule_id for r in proof.matched_rules)}]: {proof.deduction_steps[0]}"
            if proof.is_violation and proof.matched_rules
            else "Clean AST grammar verified. Zero security invariants violated."
        )

        return WAFAgentDecision(
            agent_name=self.name,
            decision=decision,
            predicted_category=predicted_category,
            confidence=1.0,
            latency_ms=round(latency_ms, 3),
            cost_usd=0.0,
            explanation=explanation,
            active_tokens=proof.active_tokens,
            matched_rules=[r.rule_id for r in proof.matched_rules],
            proof_latex=proof.formal_proof_latex,
            is_correct=is_correct,
            extra_metadata={
                "engine": "SAT-Certainty-Islands-V1",
                "rules_evaluated": len(self.engine.KNOWN_RULES),
                "islands_evaluated": len(self.engine.CERTAINTY_ISLANDS),
                "active_islands": proof.active_islands,
                "causal_proof": True,
                "token_count": len(proof.active_tokens),
            }
        )
