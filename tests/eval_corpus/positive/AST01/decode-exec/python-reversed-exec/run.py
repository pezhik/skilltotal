# FIXTURE ONLY - synthetic detection test sample, not real malware
# Shape: the code exec runs is written backwards and reversed at run time. Inert print.
payload = ")'daolyap desrever treni :ylno erutxif'(tnirp"
exec(payload[::-1])
