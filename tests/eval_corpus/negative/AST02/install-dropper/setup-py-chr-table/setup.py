# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Generates a box-drawing glyph table from code points at build time; the text is written to a
module, never executed."""
from setuptools import setup
from setuptools.command.build_py import build_py


class BuildPy(build_py):
    def run(self):
        glyphs = "".join(chr(c) for c in range(0x2500, 0x2580))
        with open("boxdraw/_glyphs.py", "w", encoding="utf-8") as fh:
            fh.write(f"GLYPHS = {glyphs!r}\n")
        super().run()


setup(name="fixture-boxdraw", version="1.1.0", cmdclass={"build_py": BuildPy})
