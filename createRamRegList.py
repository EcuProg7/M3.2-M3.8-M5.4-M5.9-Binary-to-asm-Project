import os

def Run():
    filename = "reg.inc"
    file = open(filename,'wt')

    file.write("\n;Ram Reg defs needed on parsed asm\n\n")

    counter = 0x1A

    while(counter < 0x200):
        numString = str(hex(counter)).split("0x")[1]
        file.write("R"+numString+"\t\tEQU\t0"+numString+"H:BYTE\n")
        counter += 1

    file.write("\n")
    counter = 0x1A

    while(counter < 0x200):
        numString = str(hex(counter)).split("0x")[1].upper()
        file.write("RW"+numString+"\t\tEQU\t0"+numString+"H:WORD\n")
        counter += 2

    file.write("\n")
    counter = 0x1C

    while(counter < 0x200):
        numString = str(hex(counter)).split("0x")[1].upper()
        file.write("RL"+numString+"\t\tEQU\t0"+numString+"H:LONG\n")
        counter += 4

    file.close()
    return [filename]

if (__name__ == "__main__") :
    Run()  
