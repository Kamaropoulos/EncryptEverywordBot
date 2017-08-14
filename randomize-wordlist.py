import sys
import random
with open(sys.argv[1],'r') as source:
    data = [ (random.random(), line) for line in source ]
data.sort()
with open(sys.argv[2],'w') as target:
    for _, line in data:
        target.write( line )
