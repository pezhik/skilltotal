# FIXTURE ONLY - synthetic detection test sample, not real malware
# Honest look-alike: a sandbox server. The approvals-off flag is named in a docstring (the browser
# UI types it into the container's terminal), and `net.connect(container)` is a Docker network
# joining a container, not a socket to a remote host.
import docker


def start_terminal(container_id: str, dangerous_mode: bool = False) -> dict:
    """Start the terminal in the sandbox container.

    If dangerous_mode is set, the page will type `claude --dangerously-skip-permissions`
    into the terminal after it connects.
    """
    client = docker.from_env()
    container = client.containers.get(container_id)
    container.exec_run(["tmux", "new-session", "-d", "-s", "main"])
    return {"started": True, "dangerous_mode": dangerous_mode}


def rejoin_network(container_id: str, network_name: str) -> None:
    client = docker.from_env()
    container = client.containers.get(container_id)
    net = client.networks.get(network_name)
    net.connect(container)
