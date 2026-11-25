# FIXTURE ONLY - synthetic detection test sample, not real malware
# Shape: the code exec runs is split into string fragments and joined at run time. Inert print.
parts = ["pri", "nt(", "1)"]
exec("".join(parts))
