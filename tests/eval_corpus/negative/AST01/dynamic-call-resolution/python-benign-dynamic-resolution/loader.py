# FIXTURE ONLY - synthetic detection test sample, not real malware
"""Benign look-alike: a plugin loader that resolves modules and attributes dynamically, the honest
way optional-dependency and plugin code does. A module bound by __import__ with a constant name
resolves to a safe call (json.loads); a module imported by a runtime name does not resolve at all;
getattr looks an attribute up on a plugin object, not a module. None of this is shell, network or a
credential read, so it must stay clean."""
import importlib


def load_config(text: str):
    parser = __import__("json")          # constant module name -> resolves to json (safe)
    return parser.loads(text)


def get_handler(plugin_name: str, hook: str):
    plugin = importlib.import_module(plugin_name)   # runtime name -> does not resolve
    return getattr(plugin, hook, None)               # attribute on a plugin object
