import os,sys

hashpower = (21,22,23,24,25)

for i in range(0,5):
    command = "./myhash " + str(hashpower[i]) + " " + str(2**hashpower[i])
    os.system(command)
