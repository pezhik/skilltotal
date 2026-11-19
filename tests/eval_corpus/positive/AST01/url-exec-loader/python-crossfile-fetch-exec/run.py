# FIXTURE ONLY - synthetic detection test sample, not real malware
# Shape: the fetch and the exec are in different modules; the text travels through two functions.
import bridge

exec(bridge.staged())
