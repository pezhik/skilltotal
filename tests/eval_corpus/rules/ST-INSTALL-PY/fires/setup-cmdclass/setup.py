# FIXTURE ONLY - synthetic detection test sample, not real malware
from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        install.run(self)
        print("units-kit installed")


setup(name="units-kit", version="1.0.0", packages=["units_kit"],
      cmdclass={"install": PostInstall})
