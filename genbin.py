import intelhex

def Run():
    ihex = intelhex.IntelHex();

    ihex.loadhex("build/lowSegm.HEX");
    #ihex.tobinfile("build/lowSegm.bin",0x0000, 0xffff)
    binaryLow = ihex.tobinarray(0x0000, 0xffff)
    del ihex

    binaryHigh = []
    counter = 0x10000
    do = True
    length = 0
    while do == True:
        try:
        #if(1):
            ihex = intelhex.IntelHex();
            filename = "build/P" + str(hex(counter)).split("0x")[1] + ".HEX"
            ihex.loadhex(filename);
            binaryHigh += [ihex.tobinarray(0xc000, 0xffff)]
            del ihex
            counter += 0x4000
            length += len(binaryHigh[-1])
        except:
            do = False


    file = open("build/FullBinary.bin", 'wb')

    file.write(bytes(binaryLow))
    length += len(binaryLow)

    for el in binaryHigh:
        
        file.write(bytes(el))

    file.close()
    
    print("lenght of full binary: ", hex(length))

if (__name__ == "__main__") :
    Run()  
    
    
