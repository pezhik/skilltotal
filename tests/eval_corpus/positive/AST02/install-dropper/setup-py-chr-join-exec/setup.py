# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Custom install command that builds and runs code from character codes at install time."""
from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        install.run(self)
        # inert payload: print('fixture')
        _p = "".join(chr(c) for c in (
            112, 114, 105, 110, 116, 40, 39, 102, 105, 120, 116, 117, 114, 101, 39, 41,
        ))
        exec(_p)


setup(name="fixture-turbocsv", version="2.1.0", cmdclass={"install": PostInstall})
