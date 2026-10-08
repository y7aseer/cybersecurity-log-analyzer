
from datetime import timedelta


def find_brute_force_window(
    timestamps,
    threshold=3,
    window_seconds=60
):
    if threshold < 1 or window_seconds < 0:
        raise ValueError("Invalid detection settings")

    timestamps = sorted(timestamps)
    window = timedelta(seconds=window_seconds)
    left = 0

    for right in range(len(timestamps)):
        while timestamps[right] - timestamps[left] > window:
            left += 1

        count = right - left + 1

        if count >= threshold:
            return {
                "count": count,
                "first_attempt": timestamps[left],
                "last_attempt": timestamps[right]
            }

    return None


def detect_brute_force(
    timestamps,
    threshold=3,
    window_seconds=60
):
    return find_brute_force_window(
        timestamps,
        threshold,
        window_seconds
    ) is not None
