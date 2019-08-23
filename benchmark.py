#!/usr/bin/env python

import subprocess, datetime, os
TRIALS = 10

devnull = open(os.devnull, 'w')
def run_single_test(command):
    start = datetime.datetime.now()
    subprocess.call(command, shell=True, stdout=devnull)
    end = datetime.datetime.now()
    return (end-start).microseconds 
    
def test_overall_runtime():
    print "testing emp..."
    emp_times = []
    emp_exe = "emp-ag2pc/build/bin/sha256"
    command = emp_exe + " 1 12345 & " + emp_exe + " 2 12345"
    emp_times = [run_single_test(command) for _ in range(TRIALS)]

    print "testing zkboo"
    command = "./ZKBOOpp/build/sha256_test -p -v -rep 219"
    zkboo_times = [run_single_test(command) for _ in range(TRIALS)]

    print "emp overall time: ", sum(emp_times) / TRIALS
    print "zkboo overall time: ", sum(zkboo_times) / TRIALS


# emp ag2pc has 4 relevant phases:
# one-time setup (communication channels), function independent pp, function dependent pp, online
# here we compute averages for each phase for each party
# hypothesis: they'll be the sme except for online
def test_emp_breakdown_time():
    
    emp_exe = "./emp-ag2pc/build/bin/sha256"

    logs = []
    for _ in range(TRIALS):
        log1 = subprocess.Popen([emp_exe, '1', '12345'], stdout=subprocess.PIPE)
        out2 = subprocess.check_output([emp_exe, '2', '12345'])
        out1 = log1.stdout.read()
        logs.extend((out1, out2))

    split_logs = [l.split('\n') for l in logs]
    # heinous one-liner: parses output from single_execution.h
    numbers = [[[int(s) for s in lines[i].split() if s.isdigit()] for lines in split_logs] for i in range(2,6)]


    total_p1 = 0
    total_p2 = 0
    for (label, data) in zip(['one time', 'independent', 'dependent', 'online'], numbers):
        print label
        # not robust if some fail
        p1_avg = sum([time for player, time in data if player == 1]) / TRIALS
        print '\tP1:', p1_avg
        p2_avg = sum([time for player, time in data if player == 2]) / TRIALS
        print '\tP2:', p2_avg

        total_p1 += p1_avg
        total_p2 += p2_avg

    print "overall emp p1:", total_p1
    print "overall emp p2:", total_p2


if __name__ == "__main__":
    test_overall_runtime()
    test_emp_breakdown_time()



    

