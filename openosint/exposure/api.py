"""The supported library API of the exposure engine.

Import from here, not from the submodules: names in `__all__` are kept stable across releases,
everything else under `openosint.exposure` may change.

    report = await run_exposure("example.com", lookalikes=True, public_only=True)
    html = render_html(report, "en")
"""

from openosint.exposure.domains import registrable_domain
from openosint.exposure.models import DomainNotRegistered, ExposureReport
from openosint.exposure.report import render_html
from openosint.exposure.runner import normalize_domain, run_exposure

__all__ = [
    "DomainNotRegistered",
    "ExposureReport",
    "normalize_domain",
    "registrable_domain",
    "render_html",
    "run_exposure",
]
