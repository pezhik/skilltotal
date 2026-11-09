"""Every entry of the trojanized-image list (skilltotal/known_artifacts.py) is well formed.

The list is data that may be regenerated outside a code change, so its shape is pinned here: an
entry that would match more than one exact image, or an official image, never reaches a release.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from skilltotal.known_artifacts import KNOWN_TROJANIZED_IMAGES
from skilltotal.scanners.artifact_provenance import parse_image

MODULE = Path(__file__).resolve().parents[1] / "skilltotal" / "known_artifacts.py"
IMAGE = re.compile(
    r"[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?/[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?")
CITATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9 .,&()-]{1,100}, \d{4}-\d{2}-\d{2}")
OFFICIAL_NAMESPACES = {"library", "docker", "_"}


def test_the_list_is_not_empty():
    assert KNOWN_TROJANIZED_IMAGES


@pytest.mark.parametrize("image", sorted(KNOWN_TROJANIZED_IMAGES))
def test_each_entry_is_one_exact_docker_hub_image(image):
    assert IMAGE.fullmatch(image), image
    namespace, name = image.split("/")
    assert namespace not in OFFICIAL_NAMESPACES
    # The scanner reads the same name back: what is listed is what it compares.
    assert parse_image(image) == ("", namespace, name, "")


@pytest.mark.parametrize("image", sorted(KNOWN_TROJANIZED_IMAGES))
def test_each_entry_cites_its_publishers_and_a_date(image):
    assert CITATION.fullmatch(KNOWN_TROJANIZED_IMAGES[image]), KNOWN_TROJANIZED_IMAGES[image]


def test_the_module_is_data_only_and_sorted():
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    body = [n for n in tree.body
            if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant))]
    assert len(body) == 1 and isinstance(body[0], ast.AnnAssign)
    value = body[0].value
    assert isinstance(value, ast.Dict)
    assert all(isinstance(k, ast.Constant) and isinstance(v, ast.Constant)
               for k, v in zip(value.keys, value.values, strict=True))
    keys = [k.value for k in value.keys]
    assert keys == sorted(keys) and len(keys) == len(set(keys))
