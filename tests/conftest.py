from pathlib import Path

import pytest

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
DAY1, DAY2 = "2026-11-02", "2026-11-03"

# Every secret value that appears in the sample configs. None may leave a report.
SAMPLE_SECRETS = [
    "$9$hZ4xOq2nT0yQ1k",
    "$9$8kLmN2pQrS3tUv",
    "$9$Qw3eRt5yUi7oP9",
    "0822455D0A16544541",
    "Xk7mon-RO",
    "$6$rX9.k2Lm",
    "$6$pL4.n8Rt",
    "$6$Zq8.w2Ex",
    "dcmon-r0",
    "nms-ro-7f3k",
]


def sample(day: str, device: str) -> str:
    folder = SAMPLES / "configs" / day
    for ext in (".cfg", ".rsc"):
        p = folder / f"{device}{ext}"
        if p.exists():
            return p.read_text(encoding="utf-8")
    raise FileNotFoundError(device)


@pytest.fixture
def samples_dir() -> Path:
    return SAMPLES
