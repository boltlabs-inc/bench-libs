#!/usr/bin/env python

import subprocess, datetime

TRIALS = 10
emp_times = []
emp_exe = "emp-ag2pc/build/bin/sha256"
for trial in range(TRIALS):
    command = emp_exe + " 1 12345 & " + emp_exe + " 2 12345"
    start = datetime.datetime.now()
    subprocess.call(command, shell=True)
    end = datetime.datetime.now()
    emp_times.append( (end-start).microseconds )

zkboo_times = []
for trial in range(TRIALS):
    command = "./ZKBOOpp/build/sha256_test -p -v -rep 219"
    start = datetime.datetime.now()
    subprocess.call(command, shell=True)
    end = datetime.datetime.now()
    zkboo_times.append( (end-start).microseconds )

print sum(emp_times) / TRIALS
print sum(zkboo_times) / TRIALS

