from collections import Counter
from math import log2


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum((count / len(value)) * log2(count / len(value))
                for count in Counter(value).values())
