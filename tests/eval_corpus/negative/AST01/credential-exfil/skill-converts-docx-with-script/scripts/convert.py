# FIXTURE ONLY - synthetic detection test sample, not real malware
import csv
import sys

with open(sys.argv[1], newline='') as src, open(sys.argv[2], 'w') as out:
    for row in csv.reader(src):
        out.write(' | '.join(row) + '\n')
