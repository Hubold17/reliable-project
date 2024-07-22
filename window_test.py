import subprocess
import os
import time
from multiprocessing import Process
import sys


def no_answer_process(log_file, reliable_no_answer_filename, rno_port, rel_port, window_size):
    try:
        command = "%s -w %d %d localhost:%d" % (reliable_no_answer_filename, window_size, rno_port, rel_port)
        subprocess.run(command, shell=True, stderr=log_file)
        print("Ran command: %s" % command)
    except Exception as e:
        print(e)
        exit(1)


def student_process(reliable_filename, rno_port, rel_port, window_size):
    try:
        command = "%s -w %d %d localhost:%d" % (reliable_filename, window_size, rel_port, rno_port)
        subprocess.run(command, shell=True, input=b'x' * 512 * window_size, stderr=open(os.devnull, 'w'))
        print("Ran command: %s" % command)
    except Exception as e:
        print(e)
        exit(1)


def main(window_size, reliable_filename, reliable_no_answer_filename):

    log_file = open('no_answer_log.tmp', 'w+')

    # Create the two processes
    p1 = Process(target=no_answer_process, args=(log_file, reliable_no_answer_filename, 10000, 20000, window_size))
    p2 = Process(target=student_process, args=(reliable_filename, 10000, 20000, window_size))

    # Start, let run, and terminate the two processes
    p1.start()
    time.sleep(2)
    p2.start()
    time.sleep(3)
    p1.terminate()
    p2.terminate()
    subprocess.run(["killall", reliable_filename])
    subprocess.run(["killall", reliable_no_answer_filename])

    log_file.close()

    # We go through the output to all sequence numbers and check if it corrected
    with open('no_answer_log.tmp', 'r') as read_log_file:

        found_seq = set()
        for line in read_log_file:
            if 'seq' in line:
                seq_no = int(line.split('seq =')[1], 16)  # Base-16 int parsing
                found_seq.add(seq_no)
        print("Sequence numbers found: %s" % found_seq)

        correct = True
        for i in range(1, window_size + 1):
            if i not in found_seq:
                correct = False
                print("Missing sequence number: %d" % i)

        if len(found_seq) != window_size:
            correct = False
            print("Insufficient or too many sequence numbers (%d (observed) vs. %d (expected))"
                  % (len(found_seq), window_size))
        else:
            print("All sequence numbers are correct.")

        if correct:
            print("Window test outcome: passed")
        else:
            print("Window test outcome: failure")

    # Remove temporary log file
    os.remove("no_answer_log.tmp")


if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) != 3:
        print("Usage: python window_test.py <window size> <reliable executable> <reliable_no_answer executable>")
        exit(1)
    else:
        main(int(args[0]), str(args[1]), str(args[2]))
