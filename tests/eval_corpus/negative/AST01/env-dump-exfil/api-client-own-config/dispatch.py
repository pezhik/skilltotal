# FIXTURE ONLY — synthetic detection test sample, not real malware
# An API client: the environment is handed to its own helpers, which read one token and one base
# URL from it, and the token is sent to the service it belongs to.
import os
import subprocess

import httpx


def resolve_token(env):
    for key in ("SERVICE_TOKEN", "CI_TOKEN"):
        value = (env.get(key) or "").strip()
        if value:
            return value
    return None


def resolve_base(env):
    return (env.get("SERVICE_URL") or "https://api.example.invalid").rstrip("/")


def run_tool():
    # The same short name in another function: here it is the child's environment.
    env = {**os.environ, "CI": "1"}
    subprocess.run(["make", "test"], env=env, check=False)


def main():
    env = os.environ
    token = resolve_token(env)
    headers = {"Authorization": f"Bearer {token}"}
    with httpx.Client(timeout=30) as client:
        client.post(f"{resolve_base(env)}/v1/dispatch", json={"event": "deploy"}, headers=headers)


if __name__ == "__main__":
    main()
