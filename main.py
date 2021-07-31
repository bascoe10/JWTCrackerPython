from threading import Thread, Lock
import hmac
import hashlib
import base64
import sys
from math import ceil


DICTIONARY = None
MAX_THREADS = 20
FOUND = False
# MUTEX = Lock()


def load_dictionary():
    global DICTIONARY
    with open('./rockyou.txt', errors='ignore') as f:
        DICTIONARY = f.readlines()


def bruteforce(token, start_i, end_i):
    global FOUND
    header, body, sig = token.split('.')
    for i in range(start_i, end_i + 1):
        # MUTEX.acquire()
        if FOUND or i >= len(DICTIONARY):
            break

        try:
            guess = bytes(DICTIONARY[i].replace('\n', ''), 'ascii')
        except UnicodeEncodeError:
            continue

        h = hmac.new(guess, bytes(f"{header}.{body}", "ascii"), hashlib.sha256)
        if sig in base64.urlsafe_b64encode(h.digest()).decode():
            print(f'Found signature {guess}')
            FOUND = True
            break


def main():
    load_dictionary()
    workload_per_thread = ceil(len(DICTIONARY)/MAX_THREADS)
    # payload = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.A9a5uGTT7nLlR6tFo7WuIyYPnamlq3uHOmVfYOhcPtQ"
    payload = sys.argv[1]
    threads = []
    for i in range(MAX_THREADS):
        start_i = i * workload_per_thread
        end_i = start_i + workload_per_thread
        thread = Thread(target=bruteforce, args=(payload, start_i, end_i))
        thread.start()
        threads.append(thread)

    for t in threads:
        t.join()


if __name__ == '__main__':
    main()
