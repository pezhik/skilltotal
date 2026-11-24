# FIXTURE ONLY - synthetic detection test sample, not real malware
# Look-alike: a bytes buffer built from a named list is only printed, never executed.
codes = [112, 114, 105, 110, 116, 40, 49, 41]
print(bytes(codes).decode())
