import os
from testcases import test_cases
import time

def main():    
# # used for common cases
    ids = test_cases.keys()

#  set the receive addresses
    receive_addresses = []
    with open("receive_address.txt") as f:
        lines = f.readlines()
        for line in lines:
            address = line.strip("\n")
            receive_addresses.append(address)

    for address in receive_addresses:
        for id in ids:
            script = f"python espoofer.py -m s -id {id} -to {address} "
            try:
                os.system(script)
            except (ConnectionAbortedError):
                pass
            time.sleep(90)

# n = len(ids)
# print(f"The Numbers of All situations is {ids}")
if __name__ == '__main__':
    main()
