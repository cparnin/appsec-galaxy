"""Paths to AppSec Galaxy resources in a source checkout."""

from pathlib import Path


PACKAGE_DIR = Path(__file__).resolve().parent
CHECKOUT_ROOT = PACKAGE_DIR.parent.parent
CONFIGS_DIR = CHECKOUT_ROOT / "configs"
IMAGES_DIR = CHECKOUT_ROOT / "images"
OUTPUTS_DIR = CHECKOUT_ROOT / "outputs"
