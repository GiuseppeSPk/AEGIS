"""Jailbreak attack modules.

Single-turn and multi-turn jailbreak techniques.
"""

from aegis.red_team.attacks.jailbreak.multi_turn import (
    MultiTurnJailbreakAgent,
    MultiTurnTechnique,
)
from aegis.red_team.attacks.jailbreak.single_turn import SingleTurnJailbreakAgent

__all__ = [
    "SingleTurnJailbreakAgent",
    "MultiTurnJailbreakAgent",
    "MultiTurnTechnique",
]
