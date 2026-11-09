"""Container images that public security reports name as trojanized.

Data only: an exact Docker Hub image name (namespace/name, no tag) -> the publishers of the reports
that name it and the date it was added. An image is added when two independent publishers name it,
or by hand from one detailed public report. Read by ST-ARTIFACT-KNOWN-BAD
(skilltotal/scanners/artifact_provenance.py); tests/test_known_artifacts.py checks every entry.
"""

KNOWN_TROJANIZED_IMAGES: dict[str, str] = {
    "congdonglinux/artex": "BadByte, 2026-11-04",
    "tomicdd/artex": "BadByte, 2026-11-04",
}
