# FIXTURE ONLY - synthetic detection test sample, not real malware
# Benign look-alike: exec runs a snippet another module of the package reads from a file the
# package ships; the same module also fetches a status text that is only printed.
import snippets

exec(snippets.load("defaults"))
print(snippets.status())
