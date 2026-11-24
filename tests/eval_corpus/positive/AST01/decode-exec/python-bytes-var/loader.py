# FIXTURE ONLY - synthetic detection test sample, not real malware
# Shape: byte values kept in a named list, rebuilt at run time and run by exec. Inert print.
codes = [112, 114, 105, 110, 116, 40, 49, 41]
exec(bytes(codes).decode())
