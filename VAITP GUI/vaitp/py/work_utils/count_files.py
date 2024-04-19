import os
dir = "H:\\Sem 5\\vaitp\\vaitp\\VAITP GUI\\vaitp\\vaitp_dataset\\train\\injectable"
dir2 = "H:\\Sem 5\\vaitp\\vaitp\\VAITP GUI\\vaitp\\vaitp_dataset\\test\\injectable"
sw = input()
tifCounter = 0
tifCounter2 = 0
for root, dirs, files in os.walk(dir):
    for file in files:    
        if file.startswith(sw):
            tifCounter += 1

for root, dirs, files in os.walk(dir2):
    for file in files:    
        if file.startswith(sw):
            tifCounter2 += 1
print("Injectable Train Count", tifCounter)
print("Injectable Test Count", tifCounter2)


dir3 = "H:\\Sem 5\\vaitp\\vaitp\\VAITP GUI\\vaitp\\vaitp_dataset\\train\\vulnerable"
dir4 = "H:\\Sem 5\\vaitp\\vaitp\\VAITP GUI\\vaitp\\vaitp_dataset\\test\\vulnerable"
tifCounter3 = 0
tifCounter4 = 0
for root, dirs, files in os.walk(dir3):
    for file in files:    
        if file.startswith(sw):
            tifCounter3 += 1

for root, dirs, files in os.walk(dir4):
    for file in files:    
        if file.startswith(sw):
            tifCounter4 += 1
print("Vulnerable Train Count", tifCounter3)
print("Vulnerable Test Count", tifCounter4)
