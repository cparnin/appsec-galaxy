"""Paths to AppSec Galaxy resources (configs, images, outputs).

In a source checkout (src/ layout), resources live at the repo root, two
levels above this package. When the package is pip-installed, that path
lands inside the Python installation where no repo resources exist and
scan outputs would be written next to site-packages, invisible to CI
steps that read `outputs/` from the working directory (SARIF upload,
artifact upload, the fail-on-critical gate, the Action's count outputs).
Fall back to the working directory in that case; the GitHub Action and
the self-scan both run from a full source checkout, so the bundled
configs resolve there too.
"""

from pathlib import Path


def _resolve_resource_root(checkout_root: Path) -> Path:
    """The repo root in a source checkout; the working directory when the
    package is pip-installed (no pyproject.toml two levels up)."""
    if (checkout_root / "pyproject.toml").is_file():
        return checkout_root
    return Path.cwd()


PACKAGE_DIR = Path(__file__).resolve().parent
CHECKOUT_ROOT = _resolve_resource_root(PACKAGE_DIR.parent.parent)
CONFIGS_DIR = CHECKOUT_ROOT / "configs"
IMAGES_DIR = CHECKOUT_ROOT / "images"
OUTPUTS_DIR = CHECKOUT_ROOT / "outputs"
