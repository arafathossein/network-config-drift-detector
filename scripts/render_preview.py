"""Render docs/preview.png from the demo report (needs: pip install playwright && playwright install chromium)."""

import subprocess
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

root = Path(__file__).resolve().parents[1]
out = Path(tempfile.mkdtemp())
subprocess.run([sys.executable, "-m", "config_drift.cli", "demo", "--out", str(out)], check=True, cwd=root)
report = next(out.glob("drift-*.html"))

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1100, "height": 1400}, device_scale_factor=2, color_scheme="light")
    page.goto(report.as_uri())
    # Show the table and the Cisco card, which has the widest mix of findings.
    page.evaluate("""() => {
        const cards = [...document.querySelectorAll('section.card')];
        cards.forEach(c => { if (!c.textContent.includes('core-sw-01')) c.remove(); });
    }""")
    page.screenshot(path=str(root / "docs" / "preview.png"), clip={"x": 0, "y": 0, "width": 1100, "height": 1400})
    browser.close()
print("wrote docs/preview.png")
