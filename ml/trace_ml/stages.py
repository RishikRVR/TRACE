"""Attack stages TRACE predicts, and which of them count as infiltration.

The integer codes are part of feature schema v1 (docs/feature-schema-v1.md) and
are stored in labels.csv, so never renumber them; add new stages at the end.
"""

from enum import IntEnum


class Stage(IntEnum):
    BENIGN = 0
    RECONNAISSANCE = 1  # TA0043
    INITIAL_ACCESS = 2  # TA0001
    LATERAL_MOVEMENT = 3  # TA0008
    COMMAND_AND_CONTROL = 4  # TA0011
    EXFILTRATION = 5  # TA0010
    IMPACT = 6  # TA0040: DoS/DDoS, not one of the problem statement's five stages


# Reaching any of these means the attacker is inside: the forecast target is
# "a host enters one of these within the next K windows".
INFILTRATION = frozenset(
    {
        Stage.INITIAL_ACCESS,
        Stage.LATERAL_MOVEMENT,
        Stage.COMMAND_AND_CONTROL,
        Stage.EXFILTRATION,
    }
)


def is_infiltration(stage: int) -> bool:
    return Stage(stage) in INFILTRATION
