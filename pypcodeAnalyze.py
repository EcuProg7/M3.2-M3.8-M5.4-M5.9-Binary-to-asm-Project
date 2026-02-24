import sys, os
import monkeyhex # this will format numerical results in hexadecimal
#import angr
import pypcode
import re
import xml.etree.ElementTree as ET
import shutil
import createRamRegList

class M38ToCode:
    def __init__(self):
        self._ctx = pypcode.Context("MCS196:LE:16:default")
        self._ramSpace = self._ctx.registers["SERBUF_RX"].space
        self._pspecTree = ET.parse(self._ctx.language.pspec_path)
        self._pspecRoot = self._pspecTree.getroot()
        self._lastORB = ["RF0,", 0x07]
        self._segmentJumpState = 0
        self._funcJumpList = [dict(),dict()]
        self._funcCallList = dict()
        self._vectDict = dict()
        self.firstC000found = False
        self.lineadd = 0
        self._wsrDefList = dict()
        
        for el in self._pspecRoot[1]:
            name = el.get('name')
            addr = el.get('address').split(":")[1]
            addr = int(addr, 16)
            self._vectDict[addr] = name


    def ConvertRightAddressToRegister(self, line):
        regSize = 2
        if(line.find("ORB") == 2)|(line.find("STB") == 1)|(line.find("LDB") == 1)|(line.find("ANDB") == 1)|(line.find("SUBB") == 1)|(line.find("ADDB") == 1)|(line.find("CMPB") == 1):
            regSize = 1
            #print(line)
        if(line.find("OR") == 2)|(line.find("ST") == 1)|(line.find("LD") == 1)|(line.find("AND") == 1)|(line.find("SUB") == 1)|(line.find("ADD") == 1)|(line.find("CMP") == 1):
            rightOx = line.rfind("0x")
            go = True;
            m = re.search("\[ZR\]", line)

            if m is None:
                m = re.search("\[\w*\]", line)
                if m is not None:
                    go = False;
            if(rightOx != -1) & ( go == True):
                if((line[rightOx-1] != '#')):
                    m = re.search( r'0x\w*', line[rightOx:])
                    end = m.span()[1]
                    afterNum = line[rightOx+end:]
                    num = line[rightOx:rightOx+end]
                    num = int(num,16)
                    regname = self._ctx.getRegisterName(self._ramSpace, num,regSize)
                    if(len(regname) == 0):
                        regname = self._ctx.getRegisterName(self._ramSpace, num,1)
                    if(len(regname)!= 0):
                        line = line[:rightOx] + regname + line[rightOx+end:]
        return line

    def ParseRightImmedNum(self, line):
        parsed = []
        rightOx = line.rfind("0x")
        if(rightOx != -1):
            if((line[rightOx-1] == '#')):
                m = re.search( r'0x\w*', line[rightOx:])
                end = m.span()[1]
                afterNum = line[rightOx+end:]
                num = line[rightOx:rightOx+end]
                num = int(num,16)
                parsed += [num]
        return parsed

    def ParseRightNotImmedNumOldHexFormat(self, line):
        parsed = []
        rightOx = line.rfind("H")
        if(rightOx == (len(line)-1)):
            line = line.split(" ")
            line = line[-1]
            m = re.search( r'\w*H', line)
            end = m.span()[1]
            start = m.span()[0]
            num = "0x"+line[start:end-1]
            num = int(num,16)
            parsed += [num]
        return parsed

    def ConvertWsrRegister(self, line, wsrByte):
        if (line.find("LDB WSR") != -1):
            parsed = self.ParseRightImmedNum(line)
            if(len(parsed) != 0):
                wsrByte = parsed[0]
                #print("window select found", hex(wsrByte))
            else:
                print("parse of immed error in Convert Wsr")

            return line, wsrByte
        elif(line.find("CLRB WSR") != -1):
            return line, 0
        elif(line.find("PUSHA") != -1):
            return line, 0
        elif(line.find("POPA") != -1):
            return line, 0

        splitline = line.split(" ")
        
        if(wsrByte != 0) & (len(splitline) > 1):
            newline = splitline[0] 
            splitcounter = 1;
            
            while splitcounter < len(splitline):
                partline = splitline[splitcounter] 
                windowSize = 0x20
                m = re.search( r'R\w+', partline)
                goOn = True
                stop = 10
                start = 10
                try:
                #if 1:
                    start, stop = m.span()
                except:
                    goOn = False
                    pass


                if(goOn) & (partline.find("ZR") == -1)& (partline.find("ONES") == -1)& (partline.find("_") == -1) & ((stop - start) < 5):
                    try:
                    #if 1:
                        #print(line[start:stop])
                        registerAddr = self._ctx.registers[partline[start:stop]].offset
                        if(wsrByte > 0x40):
                            windowSize = 0x20
                            windowOffset = (wsrByte - 0x40) * windowSize
                            if(wsrByte >= 0x60):
                                windowOffset += 0x1800
                        elif(wsrByte > 0x20):
                            windowSize = 0x40
                            windowOffset = (wsrByte - 0x20) * windowSize
                            if(wsrByte >= 0x30):
                                windowOffset += 0x1800
                        else:
                            windowSize = 0x80
                            windowOffset = (wsrByte - 0x10) * windowSize
                            if(wsrByte >= 0x18):
                                windowOffset += 0x1800
                        windowStart = 0x100 - windowSize

                        if(registerAddr >= windowStart) & (registerAddr < 0x100):

                            normregisterAddr = registerAddr - windowStart + windowOffset
                            #print( hex(registerAddr))
                            #input("sweilr")
                            regname = self._ctx.getRegisterName(self._ramSpace, normregisterAddr,1)
                            newRegName = regname + "_W0" + str(hex(wsrByte)).split("0x")[1]+"H"
                            newline += " " + partline[:start] + newRegName + partline[stop:]
                            self._wsrDefList[newRegName] = registerAddr
                        else:
                            newline += " " + partline
                    except:
                        print(line)
                        newline += " " + partline

                else:
                    newline += " " + partline
                splitcounter += 1

                
            line = newline

        return line, wsrByte

    def ConvertToPos(self, line):
        newLine = ""

        splitLine = line.split("-0x")
        splitcounter = 0
        newline = splitLine[0]
        if(len(splitLine)>1):
            #print(splitLine)
            while((splitcounter+1) < len(splitLine)):
                pre = newline
                post = splitLine[1+splitcounter]
                splitcounter += 1
                m = re.search( r'\w*', post)
                end = m.span()[1]
                afterNum = post[end:]
                num = post[:end]
                if(end>2):
                    add = 0x10000
                else:
                    add = 0x100

                num = int("-0x"+num,16) + add
                strNum = str(hex(num))
                newline = pre + strNum + afterNum

            line = newline

                    
        newLine = line
        return newLine

    def RemoveLookup(self, line):
        newLine = ""
        lookupPos = line.find(", LOOKUP")
        lenRemove = len(", LOOKUP")

        if(lookupPos == -1):
            lookupPos = line.find(", TABLE")
            lenRemove = len(", TABLE")

        if(lookupPos != -1):
            regStart = (lookupPos+lenRemove+1)
            zrString = line[regStart:regStart+2]
##            if(zrString == "ZR"):
##                newLine = line[:lookupPos]
##            else:
            newLine = line[:lookupPos] +" " + line[(lookupPos + lenRemove):]

            return newLine
        else:                               # add whitespace in front of index brackets (needed for parsing wsr´s)
            bracketPos = line.rfind("[")
            if(bracketPos != -1):
                if(line[bracketPos-1] != ' '):
                    newLine = line[:bracketPos] +" " + line[bracketPos:]
                    return newLine
        
        return line

    def AddAddrToJumpList(self, line, lineAddr, jumplist, comment, nextLineAddr):
        jumpAddr = self.ParseRightNotImmedNumOldHexFormat(line)[0]
        if(jumpAddr >= 0xC000):
            if(lineAddr >= 0xC000):
                jumpAddr = (jumpAddr - 0xC000) + (lineAddr & 0xFC000)
            if(self._segmentJumpState == 2):
                #print(line)
                if(jumpAddr < 0x10000):
                    segmJumpAddr = self._lastORB[1]*0x4000 + (jumpAddr - 0xC000)
                    comment = ";\t segment jump to : " + str(hex(segmJumpAddr))+"\n"
                    jumpAddr = segmJumpAddr
                else :
                    print(hex(jumpAddr))

        jumplist[lineAddr] = [jumpAddr, nextLineAddr]
        return jumplist, comment

    def FindJumpAddr(self, line, lineAddr, nextLineAddr):
        comment = ""
        if(line.find("ORB") == 1):
            try:
                splitline = line.split(" ")
                if(splitline[2].find("#")!= -1):
                    num = int("0x"+splitline[2][2:3],16)
                    self._lastORB = [splitline[1], num]
                    self._segmentJumpState = 1
                    #print(line)
            except:
                print(line)
            
        elif ((line.find("PPAGE") != -1) & (line.find("STB") == 1) & (self._segmentJumpState == 1)):
            splitline = line.split(" ")
            #print(line)
            if(self._lastORB[0] == splitline[1] ):
                self._segmentJumpState = 2
        
              
        elif(line.find("J") == 1) | (line.find("DJ") == 1)| (line.find("SJMP") == 1):
            self._funcJumpList[0], comment = self.AddAddrToJumpList( line, lineAddr, self._funcJumpList[0], comment, nextLineAddr)
        elif(line.find("LJMP") == 1):
            self._funcJumpList[1], comment = self.AddAddrToJumpList( line, lineAddr, self._funcJumpList[1], comment, nextLineAddr)
        elif(line.find("SCALL") == 1) | (line.find("LCALL") == 1):
            self._funcCallList, comment = self.AddAddrToJumpList( line, lineAddr, self._funcCallList, comment, nextLineAddr)

        else:
            self._segmentJumpState = 0

        return comment

        
    def ConvertHexFormat(self, line):
        splitLine = line.split("0x")
        splitcounter = 0
        newline = splitLine[0]
        if(len(splitLine)>1):
            #print(splitLine)
            while((splitcounter+1) < len(splitLine)):
                pre = newline
                post = splitLine[1+splitcounter]
                splitcounter += 1
                m = re.search( r'\w*', post)
                end = m.span()[1]
                afterNum = post[end:]
                num = post[:end]

                num = int("0x"+num,16)
                if(num >= 0x10000):
                    num -= 0x10000
                strNum = "0" + str(hex(num)).split("0x")[1].upper()+"H"
                newline = pre + strNum + afterNum
            line = newline
        return line

    def ConvertTijmp(self, line):
        if(line.find("TIJMP") != -1):
           lastImmedNumPos = line.rfind("#0x")
           line = line[:lastImmedNumPos] + "," + line[lastImmedNumPos:]
        
        return line

    def FillFunctionHeaders(self, fileName):
        infile = open(fileName, 'rt')
        inData = infile.read()
        infile.close()
        outfileparsed = open(fileName, 'wt')

        actFuncJumpedFrom = 0x0
        nextAfterjumpLineAddr = 0x0
        

        inData = inData.split("\n")

        #remove empty rst´s on end of file

        counter = len(inData)-2
        while(inData[counter].find("RST")!= -1):
            counter -= 1

        inData = inData[:counter+1]
        #######
        
        returnFound = False

        for el in inData:
            line = el + "\n"
        

            endFuncComment =""
            callComment = ""
            callRef = ""
            if (line.find(";0x") != -1) & (line.find("/") != -1):
                split = line.split(";0x")

                lineAddr = int("0x"+split[1].split("/")[0], 16)
                nextLineAddr = lineAddr + int("0x"+split[1].split("/")[1], 16)
                for el in self._funcCallList:
                    jumpAddr = self._funcCallList[el][0]
                    if(jumpAddr == lineAddr):
                        if( returnFound == False):
                            endFuncComment = ";***** maybe end of former func\n\n"
                        else:
                            endFuncComment = ";***** for shure end of former func\n\n"
                        callComment += "; called from: "+ str(hex(el)) +":\n"
                        callRef = "CallF_"+str(hex(lineAddr))+":\n"
                        

                
                for el in self._funcJumpList[1]:    ##only LJMP is used
                    jumpAddr = self._funcJumpList[1][el][0]
                    
                    if(jumpAddr == lineAddr):
                        if( returnFound == True):
                            endFuncComment = ";***** maybe end of former func\n\n"
                            actFuncJumpedFrom = el
                            nextAfterjumpLineAddr = self._funcJumpList[1][el][1]
                        callComment += "; jumped from: "+ str(hex(el)) +":\n"
                        if(len(callRef) == 0):
                            callRef = "LjmpF_"+str(hex(lineAddr))+":\n"

                    elif(el == lineAddr):
                        
                        if(nextAfterjumpLineAddr >= 0x10000):
                            jumpAddr = (jumpAddr - 0xC000) + (nextAfterjumpLineAddr & 0xFC000)
                            #print(line)
                        if (abs(nextAfterjumpLineAddr - jumpAddr) <= 0x100 ):
                            endFuncComment = "; backjump to former func: "+str(hex(jumpAddr))+"\n"
                            self._funcJumpList[1][el][0] = jumpAddr
                
                if(len(callRef) == 0):
                    for el in self._funcJumpList[0]:    ##only SJMP, JBx, DJxxx
                        jumpAddr = self._funcJumpList[0][el][0]
                        
                        if(jumpAddr == lineAddr)& (len(callRef) == 0):
                            callRef = "Sjmp_"+str(hex(lineAddr))+":\n"


            if(line.find("RET")==1):
                returnFound = True
            elif(line.find("RST")==-1):
                returnFound = False
                
            outfileparsed.write(endFuncComment)
            outfileparsed.write(callComment)
            outfileparsed.write(callRef)
            outfileparsed.write(line)


        outfileparsed.close()

    def ReduceJumpLists(self):
        self._funcCallListwJumps = dict()
        self._funcJumpListRed1 = [dict(),dict()]
        self._funcJumpListRed = [dict(),dict()]

        for el in self._funcCallList:
            jumpAddr = self._funcCallList[el][0]
            self._funcCallListwJumps[el] = self._funcCallList[el]

            for el2 in self._funcJumpList[1]:    ##only LJMP is used
                jumpAddr2 = self._funcJumpList[1][el2][0]

                if(jumpAddr2 == jumpAddr):
                    self._funcCallListwJumps[el2] = self._funcJumpList[1][el2]
                else:
                    self._funcJumpListRed1[1][el2] = self._funcJumpList[1][el2]
                    
            for el2 in self._funcJumpList[0]:    ##only Sjmp...
                jumpAddr2 = self._funcJumpList[0][el2][0]

                if(jumpAddr2 == jumpAddr):
                    self._funcCallListwJumps[el2] = self._funcJumpList[0][el2]
                else:
                    self._funcJumpListRed1[0][el2] = self._funcJumpList[0][el2]

        for el in self._funcJumpListRed1[1]:
            jumpAddr = self._funcJumpListRed1[1][el][0]
            self._funcJumpListRed[1][el] = self._funcJumpListRed1[1][el]

            for el2 in self._funcJumpList[0]:    ##only Sjmp...
                jumpAddr2 = self._funcJumpList[0][el2][0]

                if(jumpAddr2 == jumpAddr):
                    self._funcJumpListRed[1][el2] = self._funcJumpListRed1[0][el2]
                else:
                    self._funcJumpListRed[0][el2] = self._funcJumpListRed1[0][el2]



    def FillJumpCallRefs(self, fileName):
        infile = open(fileName, 'rt')
        inData = infile.read()
        infile.close()
        outfileparsed = open(fileName, 'wt')


                    

        

        inData = inData.split("\n")

        #######
        
        for el in inData:
            line = el + "\n"
        

            if (line.find(";0x") != -1) & (line.find("/") != -1):
                split = line.split(";0x")
                found = False

                lineAddr = int("0x"+split[1].split("/")[0], 16)
                nextLineAddr = lineAddr + int("0x"+split[1].split("/")[1], 16)
                for el in self._funcCallListwJumps:
                    jumpAddr = self._funcCallListwJumps[el][0]
                    if(el == lineAddr):
                        foundAddr = re.findall("\w+H\s", line)[-1].split(" ")[0]
                        pos = line.rfind(foundAddr)
                        newline = line[:pos] + "CallF_"+str(hex(jumpAddr))
                        postcomment = ";" + line[(pos+len(foundAddr)):].split(";")[1]
                        line = newline + (60-len(newline))*" " + postcomment
                        found = True
                        

                if(found == False):
                    for el in self._funcJumpListRed[1]:    ##only LJMP is used
                        jumpAddr = self._funcJumpListRed[1][el][0]
                        
                        if(el == lineAddr):
                            foundAddr = re.findall("\w+H\s", line)[-1].split(" ")[0]
                            pos = line.rfind(foundAddr)
                            newline = line[:pos] + "LjmpF_"+str(hex(jumpAddr))
                            postcomment = ";" + line[(pos+len(foundAddr)):].split(";")[1]
                            line = newline + (60-len(newline))*" " + postcomment
                            found = True


                if(found == False):

                    for el in self._funcJumpListRed[0]:    ##only SJMP, JBx, DJxxx
                        jumpAddr = self._funcJumpListRed[0][el][0]

                            
                        
                        if(el == lineAddr):

                            foundAddr = re.findall("\w+H\s", line)[-1].split(" ")[0]
                            pos = line.rfind(foundAddr)

                                
                            newline = line[:pos] + "Sjmp_"+str(hex(jumpAddr))
                            
                            postcomment = ";" + line[(pos+len(foundAddr)):].split(";")[1]
                            line = newline + (60-len(newline))*" " + postcomment

                

            outfileparsed.write(line)


        outfileparsed.close()

    def NumToOldHexString(self, num):
        return "0" + str(hex(num)).split("0x")[1]+"H"

    def WriteIndexRefs(self, filename, projectDir, IndexRefs, projectName):
        file = open(projectDir+filename, 'wt')

        file.write("	"+filename.split(".")[0] + " module \n")
        file.write("$title(\"external index file "+ projectName + "\")\n\n")

        preText = "$include (KR.INC)\n"
        preText += "$include (reg.inc)\n"
        preText += "$include (regwsr.inc)\n"
        preText += "$include (asic.inc)\n\n"

        file.write(preText)

        d= dict()

        for el in IndexRefs:
            d[el] = 1
        for el in d:
            file.write(el+"\n")

        file.write("\n")
        for el in d:
            file.write("\tpublic\t"+el.split("EQU")[0]+"\n")

        file.write("\n\tend\n")

        file.close()

        filename = filename.split(".")[0]+"Ext.inc"

        file = open(projectDir+filename, 'wt')



        file.write("\n")
        for el in d:
            file.write("\textrn\t"+el.split("EQU")[0]+"\n")

        file.close()


    def WriteDataFile(self, fileName, projectDir, startAddr, indata, projectName):
        file = open(projectDir+fileName, 'wt')
        file.write("	"+fileName.split(".")[0] + " module \n")
        file.write("$title(\"Data segment " + str(hex(startAddr)) +" "+ projectName + "\")\n")
        file.write("\n\tCSEG\tAT (0"+str(hex(startAddr)).split("0x")[1] + "H" + ")\n\n")

        for el in indata:
            file.write("\tdcb\t0"+ str(hex(el)).split("0x")[1] + "H" +"\n")

        file.write("\n\tend\n")

        file.close()

    def ParseToNoneConf(self, filename):
        dataRef = []
        infile = open(filename, 'rt')
        inData = infile.read()
        infile.close()

        outfileparsed = open(filename, 'wt')

        inData = inData.split("\n")

        #######
        
        for el in inData:
            line = el + "\n"

            
            m = re.search("\s\w+,\s\w+, \w+\s*\[\w+\]", line)
            find = 4

            if m is None:
                m = re.search("\s\w+, \w+\s*\[\w+\]", line)
                find = 3

            if m is not None:
                go = True
                if(find == 3):
                    lastReg = line.split(" ")[2]
                else:
                    lastReg = line.split(" ")[3]
                    #print(lastReg, line)

                try:
                    registerAddr = self._ctx.registers[lastReg].offset

                    if(registerAddr < 0x80):
                        go = False
                    elif(registerAddr >= 0x100):
                        go = False

                    
                except:
                    if(lastReg[-1] == 'H') & (lastReg.find("_") == -1):
                        registerAddr = int(lastReg[:-1], 16)

                        if(registerAddr < 0x80):
                            go = False
                        elif(registerAddr >= 0x100):
                            go = False
                        
                    else:
                        go = False

                if(line.find("/"+str(find+1)) == -1):   # compiler error on long indexed above 0xFF7E error workaround with external ref
                    go = False
                    start = line.find(lastReg)
                    if(registerAddr >= 0xFF80):
                        lastReg = lastReg.split(",")[0]
                        dataRef += ["\tIdx_"+lastReg+"\t\tEQU\t"+lastReg]
                        line = line[:start] + "Idx_" + line[start:]
                    
                        #&(line[3] != 'B')
                pos = line.find("[ZR]")
                if(pos != -1):      
                    
                    line = line[:pos] + "    " + line[pos+4:]


            outfileparsed.write(line)


        outfileparsed.close()
        return dataRef

    def ParseToOriBinCompatible(self, filename):
        dataRef = []
        infile = open(filename, 'rt')
        inData = infile.read()
        infile.close()
        macrofilename = filename[:-4] + "_m.a96"
        #print(macrofilename)
        outfileparsed = open(macrofilename, 'wt')

        inData = inData.split("\n")

        #######
        
        for el in inData:
            line = el + "\n"

            
            m = re.search("\s\w+,\s\w+, \w+\s*\[\w+\]", line)
            find = 4

            if m is None:
                m = re.search("\s\w+, \w+\s*\[\w+\]", line)
                find = 3

            if m is not None:
                go = True
                if(find == 3):
                    lastReg = line.split(" ")[2]
                else:
                    lastReg = line.split(" ")[3]
                    #print(lastReg, line)

                try:
                    registerAddr = self._ctx.registers[lastReg].offset

                    if(registerAddr < 0x80):
                        go = False
                    elif(registerAddr >= 0x100):
                        go = False

                    
                except:
                    if(lastReg[-1] == 'H') & (lastReg.find("_") == -1):
                        registerAddr = int(lastReg[:-1], 16)

                        if(registerAddr < 0x80):
                            go = False
                        elif(registerAddr >= 0x100):
                            go = False
                        
                    else:
                        go = False

                if(line.find("/"+str(find+1)) == -1):
                    go = False
                    start = line.rfind(lastReg)
                    if(registerAddr < 0x100) | (registerAddr >= 0xFF80):
                        lastReg = lastReg.split(",")[0]
                        dataRef += ["\tIdx_"+lastReg+"\t\tEQU\t"+lastReg]
                        line = line[:start] + "Idx_" + line[start:]
                    
                        #&(line[3] != 'B')
                if(((line.find("LD") != -1) | (line.find("ST") != -1) ) | (((line.find("SUB") != -1) | (line.find("ADD") != -1))&(line[4] != 'B')) | ((line.find("CMP") != -1))) & (go == True):
                    end = m.span()[1]
                    start = m.span()[0]
                    line = line[:start] + "_SI" + str(find) + line[start:]
                    
                    brPos1 = line.find("[")
                    brPos2 = line.find("]")
                    
                    line = line[:brPos1] + "," + line[brPos1+1:brPos2] + line[brPos2+1:]


            outfileparsed.write(line)


        outfileparsed.close()
        return dataRef

    def EmmitJumpRefsToDict(self, segm, segmSize, toLowerLimit, toUpperLimit):
        jumpfromDict= dict()
        jumpToDict= dict()
        for el in self._funcJumpList[0]:
            jumpaddr = self._funcJumpList[0][el][0]
            if (jumpaddr >= toLowerLimit) &(jumpaddr <= toUpperLimit) &((jumpaddr < segm)|(jumpaddr >= (segm + segmSize)))   & (el >= segm)& (el < (segm + segmSize)):
                jumpfromDict[jumpaddr] =  "Sjmp"+str(hex(jumpaddr))+"\t\tEQU\t" + self.NumToOldHexString(jumpaddr )
            
            if (jumpaddr >= segm) &(jumpaddr < (segm + segmSize))  & ((el < segm) | (el >= (segm + segmSize))):
                jumpToDict[jumpaddr] =  "Sjmp"+str(hex(jumpaddr))+"\t\tEQU\t" + self.NumToOldHexString(jumpaddr )
                    
        for el in self._funcJumpList[1]:
            jumpaddr = self._funcJumpList[1][el][0]
            if (jumpaddr >= toLowerLimit) &(jumpaddr <= toUpperLimit)&((jumpaddr < segm)|(jumpaddr >= (segm + segmSize)))  & (el >= segm)& (el < (segm + segmSize)):
                jumpfromDict[jumpaddr] =  "LjmpF_"+str(hex(jumpaddr))+"\t\tEQU\t" +self.NumToOldHexString(jumpaddr )

            if (jumpaddr >= segm) &(jumpaddr < (segm + segmSize))  & ((el < segm) | (el >= (segm + segmSize))):
                jumpToDict[jumpaddr] =  "LjmpF_"+str(hex(jumpaddr))+"\t\tEQU\t" + self.NumToOldHexString(jumpaddr )

        for el in self._funcCallList:
            jumpaddr = self._funcCallList[el][0]
            if (jumpaddr >= toLowerLimit) &(jumpaddr <= toUpperLimit) &((jumpaddr < segm)|(jumpaddr >= (segm + segmSize)))  & (el >= segm)& (el < (segm + segmSize)):
                jumpfromDict[jumpaddr] =  "CallF_"+str(hex(jumpaddr))+"\t\tEQU\t" + self.NumToOldHexString(jumpaddr )
            
            if (jumpaddr >= segm) &(jumpaddr < (segm + segmSize))  & ((el < segm) | (el >= (segm + segmSize))):
                jumpToDict[jumpaddr] =  "CallF_"+str(hex(jumpaddr))+"\t\tEQU\t" + self.NumToOldHexString(jumpaddr )

        for el in self._vectPointerList:
            jumpaddr = self._vectPointerList[el]
##            if (jumpaddr >= toLowerLimit) &(jumpaddr <= toUpperLimit) &((jumpaddr < segm)|(jumpaddr >= (segm + segmSize)))  & (el >= segm)& (el < (segm + segmSize)):
##                jumpfromDict[jumpaddr] =  el+"\t\tEQU\t" + self.NumToOldHexString(jumpaddr )
            
            if (jumpaddr >= segm) &(jumpaddr < (segm + segmSize)):
                jumpToDict[jumpaddr] =  el+"\t\tEQU\t" + self.NumToOldHexString(jumpaddr )

        return jumpfromDict, jumpToDict
           

    def ParseFile(self, infile, outfileparsed):
        line = infile.readline()
        wsr = 0
        
        lineAddr = 0
        nextLineAddr = 0
        segmentJumpComment = ""
        
        while(len(line)!= 0):
            if line.find(":") != -1:
                #remove counter in front of code
                split = line.split(":")
                line = "\t" + split[1][1:].split("\n")[0]

                lineAddr = int(split[0].split("/")[0], 16)
                nextLineAddr = lineAddr + int(split[0].split("/")[1], 16)
                if(lineAddr == 0xc000):
                    if(self.firstC000found == False):
                        self.firstC000found = True
                    else:
                        self.lineadd += 0x4000
                elif(lineAddr <= 0xc000):
                    self.lineadd = 0
                lineAddr += self.lineadd
                nextLineAddr += self.lineadd

                
                line = self.ConvertToPos(line)

                line = self.ConvertRightAddressToRegister(line)

                line, wsr = self.ConvertWsrRegister(line, wsr)
                line = self.RemoveLookup(line)

                line = self.ConvertTijmp(line)
                
                line = self.ConvertHexFormat(line)

                segmentJumpComment = self.FindJumpAddr(line, lineAddr, nextLineAddr)
                    
                # add file offset
##                m = re.search( r'\w*', line)
##                end = m.span()[1]
##                num = line[:end]
##                num = int(num,16)
##                line = str(hex(num)) + line[end:]

                
                while(len(line) < 60):
                    line += " "
                line += ";"+ str(hex(lineAddr)) + "/" + split[0].split("/")[1] + "\n"

                for el in self._vectPointerList:
                    #print(el, vectPointerList[el])
                    if (lineAddr == self._vectPointerList[el] ):
                        vectorline = "\n\t ; interrupt : " + el + "\n" + el + ":\n"
                        outfileparsed.write(vectorline)
            
                
            outfileparsed.write(segmentJumpComment)
            outfileparsed.write(line)
            line = infile.readline()
            segmentJumpComment = ""
            
        return nextLineAddr     #returns last nextLine addr

    def GetVectorLine(self, counter, data):
        ccbText = ""
        addr = 0x2000+counter
        name = self._vectDict.get(addr)
        jumpAddr = data[counter] + data[counter+1]*256
        if(jumpAddr != 0xFFFF) & (name is not None):
            if(len(name) != 0):
                try:
                    jumpAddr2 = self._vectPointerList[name]
                    if(jumpAddr2 != jumpAddr):
                        print("\n VectorPointerList error, wrong address in list found: )", hex(addr))
                except:
                    print("\n VectorPointerList error, jump not found: )", hex(addr))

                ccbText += "\tdcw\t" + name + "\n"
        else:
            if name is None:
                name = "NONE"
            if(jumpAddr != 0xFFFF):
                print("\n _vectDict error, jump name not found: )", hex(addr))
            ccbText += "\tdcw\t0FFFFH\t; "+ name + " not used\n"

        
        return ccbText

    def GenCCBsAndJumpTable(self, data):
##207F
##205E Reserved (each byte must contain FFH)
        
##205D
##2040 PTS vectors
        
##203F
##2030 Upper interrupt vectors
        
##202F
##2020 Security key
        
##201F Reserved (must contain 20H)
##201E Reserved (must contain FFH)
##201D Reserved (must contain 20H)
##201C Reserved (must contain FFH)
##201B Reserved (must contain 20H)
##201A CCB1
##2019 Reserved (must contain 20H)
##2018 CCB0
        
##2017
##2016 OFD flag 
        
##2015
##2014 Reserved (each byte must contain FFH)
        
##2013
##2000 Lower interrupt vectors
##        counter = 0
##        for el in data:
##            print(hex(counter),hex(el))
##            counter +=1

        ccbText = ""

        ccbText += "\n;\tRam interrupt addresses:\n\n"
        #build externals for interrupt vectors
        extIntNames = []
        RamIntNames = []
        for el in self._vectPointerList:
            jumpAddr = self._vectPointerList[el]
            if((jumpAddr < 0x2000)&(jumpAddr >= 0x500)) | ((jumpAddr < 0x400)&(jumpAddr >= 0x200)):
                extIntNames += [el]
            elif(jumpAddr < 0x500):
                ccbText += "\t" + el + "\tEQU\t" + self.NumToOldHexString(jumpAddr) + "; WARNING: find ramcopy to have ISR code \n"

        ccbText += "\n;\tinterrupt externals:\n"
        for el in extIntNames:
            ccbText += "\textrn\t" + el + "\n"

        ccbText += "\n;\tlower interrupt vectors\n\n"
        counter = 0
        while counter < 0x14:       #Lower interrupt vectors
            ccbText += self.GetVectorLine(counter, data)
            counter += 2

        ccbText += "\n\tdcw\t0FFFFH\t;2014 - 2015 Reserved (each byte must contain FFH)\n"        #2014 - 2015 Reserved (each byte must contain FFH)
        word = data[0x16]+ data[0x17]*256
        ccbText += "\tdcw\t0" + str(hex(word)).split("0x")[1].upper() + "H\t;2016 - 2017 OFD flag Oszillator fail detect\n"        #2016 - 2017 OFD flag Oszillator fail detect
        ccbText += "\tdcb\t0" + str(hex(data[0x18])).split("0x")[1].upper() + "H\t;2018 CCB0\n"        #2018 CCB0
        ccbText += "\tdcb\t0" + str(hex(data[0x19])).split("0x")[1].upper() + "H\t;2019 Reserved (must contain 20H)\n"        #2019 Reserved (must contain 20H)
        ccbText += "\tdcb\t0" + str(hex(data[0x1A])).split("0x")[1].upper() + "H\t;201A CCB1\n"        #201A CCB1
        ccbText += "\tdcb\t0" + str(hex(data[0x1B])).split("0x")[1].upper() + "H\t;201B Reserved (must contain 20H)\n"        #201B Reserved (must contain 20H)
        
        ccbText += "\tdcb\t0" + str(hex(data[0x1C])).split("0x")[1].upper() + "H\t;201C Reserved (must contain FFH)\n"        #201C Reserved (must contain FFH)
        ccbText += "\tdcb\t0" + str(hex(data[0x1D])).split("0x")[1].upper() + "H\t;201D Reserved (must contain 20H)\n"        #201D Reserved (must contain 20H)
        ccbText += "\tdcb\t0" + str(hex(data[0x1E])).split("0x")[1].upper() + "H\t;201E Reserved (must contain FFH)\n"        #201E Reserved (must contain FFH)
        ccbText += "\tdcb\t0" + str(hex(data[0x1F])).split("0x")[1].upper() + "H\t;201F Reserved (must contain 20H)\n"        #201F Reserved (must contain 20H)

        ccbText += "\n;\tsecurity key 0x2020 - 0x202F\n"
        counter = 0x20
        while counter < 0x30:
            ccbText += "\tdcb\t0" + str(hex(data[counter])).split("0x")[1].upper() + "H\n"
            counter += 1

        ccbText += "\n;\tupper interrupt vectors\n\n"
        counter = 0x30
        while counter < 0x40:
            ccbText += self.GetVectorLine(counter, data)
            counter += 2

        ccbText += "\n;\tPTS interrupt vectors\n\n"
        counter = 0x40
        while counter <= 0x5D:
            
            ccbText += self.GetVectorLine(counter, data)
            counter += 2

##    #205E - 0x207F Reserved (each byte must contain FFH)
##        ccbText += "\n;\t0x205E - 0x207F Reserved (each byte must contain FFH)\n"
##        counter = 0x5E
##        while counter < 0x80:
##            ccbText += "\tdcw\t0" + str(hex(data[counter])).split("0x")[1].upper() + "H\n"
##            counter += 2

        return ccbText
    


    def WriteMainFile(self, filename, projectDir, jumpdefFilename, publicsFilename, projectName, ccbText):
        infile = open(filename, 'rt')
        filename = projectDir+"main.a96"
        outfile = open(filename, 'wt')

        preText = "\tPMain module main\n"
        preText += "$title(\"" + projectName +" Rev.0.1\")\n\n"

        preText += "$include (KR.INC)\n"
        preText += "$include (macro.INC)\n"
        preText += "$include (reg.inc)\n"
        preText += "$include (regwsr.inc)\n"
        preText += "$include (asic.inc)\n"
        preText += "$include (idxExt.inc)\n"
        preText += "$include (SegRef.inc)\n\n\n"


        if(len(jumpdefFilename) > 0):
            preText += ";\tjump and call externals\n\n"
            jumpfile = open(jumpdefFilename, 'rt')
            line = jumpfile.readline()
            while(len(line)>0):
                split = line.split("\t")[0]
                if(len(split) > 1):
                    preText += "\textrn\t" + split + "\n"
                line = jumpfile.readline()

            jumpfile.close()

        if(len(publicsFilename) > 0):
            preText += "\n;\tjump and call pubilcs\n\n"
            jumpfile = open(publicsFilename, 'rt')
            line = jumpfile.readline()
            while(len(line)>0):
                split = line.split("\t")[0]
                if(len(split) > 1):
                    preText += "\tpublic\t" + split + "\n"
                line = jumpfile.readline()

            jumpfile.close()

        preText += "\n$eject\n"
        preText += ";\n"
        preText += "; This section contains EQUates which may change with different versions\n"
        preText += "; ----------------------------------------------------------------------\n"
        preText += ";\n"
        preText += "offset			equ	2000H	; Code offset\n\n\n"




        preText += "$eject\n"
        preText += ";\n"
        preText += "\t\tcseg at (offset )\n"
        preText += ";	------------------------\n"
        preText += "; ccbs and Interrupt service routine addresses\n\n"

        #preText += "\t\tdcw	NMI_Interrupt_Routine		;first dummy int\n\n"
        preText += ccbText

        preText += "\n$eject\n\n"

        preText += ";	------------------------	Reset Handler ---------------------------------------\n"
        preText += "\t\tcseg at (offset + 0080H)\n"
        preText += ";	------------------------\n\n"
        
        preText += "ResetHandler:\n"

        outfile.write(preText)
        outfile.write(infile.read())
        infile.close()

        outfile.write("\n\n\tend\n")
        outfile.close()

        return filename
        
    def WriteModuleFile(self, infilename, startAddress, codeOffset, projectDir, jumpdefFilename, publicsFilename, projectName, includes, mainString):
        infile = open(infilename, 'rt')
        modulename = "P"+str(hex(startAddress)).split("0x")[1]
        outfilename = projectDir + modulename+".a96"
        outfile = open(outfilename, 'wt')

        if(codeOffset >= 0x10000):
            codeOffset = 0xC000 + (codeOffset & 0x3FFF)
        else:
            codeOffset = codeOffset

        preText = "\t"+modulename+" module " + mainString + "\n"
        preText += "$title(\"" + projectName +" Rev.0.1\")\n\n"

        preText += "$include (KR.INC)\n"
        preText += "$include (macro.INC)\n"
        preText += "$include (reg.inc)\n"
        preText += "$include (regwsr.inc)\n"
        preText += "$include (asic.inc)\n"
        preText += includes
        preText += "\n\n"

        if(len(jumpdefFilename) > 0):
            preText += ";\tjump and call externals\n\n"
            jumpfile = open(jumpdefFilename, 'rt')
            line = jumpfile.readline()
            while(len(line)>0):
                split = line.split("\t")[0]
                if(len(split) > 2):
                    preText += "\textrn\t" + split + "\n"
                
                line = jumpfile.readline()

            jumpfile.close()

        if(len(publicsFilename) > 0):
            preText += "\n;\tjump and call pubilcs\n\n"
            jumpfile = open(publicsFilename, 'rt')
            line = jumpfile.readline()
            while(len(line)>0):
                split = line.split("\t")[0]
                if(len(split) > 1):
                    preText += "\tpublic\t" + split + "\n"
                line = jumpfile.readline()

            jumpfile.close()
        

        preText += "\n$eject\n"
        preText += ";\n"
        preText += "; This section contains EQUates which may change with different versions\n"
        preText += "; ----------------------------------------------------------------------\n"
        preText += ";\n"
        preText += "offset			equ	0"+ str(hex(codeOffset)).split("0x")[1]+"H	; Code offset\n\n\n"




        preText += "$eject\n"
        preText += ";\n"
        preText += "\t\tcseg at (offset )\n"
        preText += ";	------------------------\n"

        preText += ";	------------------------\n\n"

        outfile.write(preText)
        outfile.write(infile.read())
        infile.close()

        outfile.write("\n\n\tend\n")
        outfile.close()

        return outfilename

    def WriteJumpRefFile(self, filename, jumpdict):

        regFile = open(filename, 'wt')
        regFile.write("\n")
        for addr in jumpdict:
            el = jumpdict[addr]
            line = el +(20-(len(el)))*" " + "\n"
            regFile.write(line)
            
        regFile.write("\n")
        regFile.close()

    def Run(self, infileName):
            infile= open(infileName, 'rb')
            indata= infile.read()
            infile.close()
            
            # calc caldata checksum 16
            calChkCalc = 0xFFFF
            counter = 0x8000
            while counter < 0xc000:
                calChkCalc = calChkCalc - indata[counter] - (indata[counter+1]*256)
                calChkCalc = calChkCalc & 0xFFFF
                counter +=2

            print("\n caldata checksum 16 over all and saved chk: ", hex(calChkCalc))
            
            # full caldata checksum 16
            fullChkCalc16 = 0xFFFF
            counter = 0x200
            while counter < (len(indata)-2):
                fullChkCalc16 = fullChkCalc16 - indata[counter] - (indata[counter+1]*256)
                fullChkCalc16 = fullChkCalc16 & 0xFFFF
                counter +=2
                if(counter == 0x400):
                    counter = 0x500

            
            fullChkCalc = 0xFFFF
            counter = 0x200
            while counter < (len(indata)-2):
                fullChkCalc = fullChkCalc - indata[counter]
                fullChkCalc = fullChkCalc & 0xFFFF
                counter +=1
                if(counter == 0x400):
                    counter = 0x500

            print("\n full checksum 16 over all and saved chk: ", hex(fullChkCalc16), hex(fullChkCalc))
            
            #generate interrupt list:
            addr = 0x2000
            self._vectPointerList = dict()
            while addr < 0x2080:
                name = self._vectDict.get(addr)
                try:
                    if(len(name)!=0):
                        jumpaddr = indata[addr] + indata[addr+1]*256
                        if(jumpaddr != 0xFFFF):
                            self._vectPointerList[name] = jumpaddr
                            #self._funcCallList[addr] = [jumpaddr, 0]
                except:
                    pass
                addr += 2
            

            #print(self._vectPointerList)
##            for el in self._vectPointerList:
##                print(el, hex(self._vectPointerList[el]))

            projectDirName= "./" + infileName.split(".")[0]+"_Project/"
            if not os.path.exists(projectDirName):
                os.makedirs(projectDirName)
            srcDirName = projectDirName + "src/"
            if not os.path.exists(srcDirName):
                os.makedirs(srcDirName)

            projectOriConformDirName = projectDirName + "src/"+infileName.split(".")[0]+"_oriBinConform/"
            if not os.path.exists(projectOriConformDirName):
                os.makedirs(projectOriConformDirName)

            srcOriConformDirName = projectOriConformDirName + "src/"
            if not os.path.exists(srcOriConformDirName):
                os.makedirs(srcOriConformDirName)

            projectNoneConformDirName = projectDirName + "src/"+infileName.split(".")[0]+"_NoneOriBinConform/"
            if not os.path.exists(projectNoneConformDirName):
                os.makedirs(projectNoneConformDirName)

            srcNoneConformDirName = projectNoneConformDirName + "src/"
            if not os.path.exists(srcNoneConformDirName):
                os.makedirs(srcNoneConformDirName)


            projectName = infileName.split(".")[0]+"_Project "

            outfileName2080_8000Raw = projectDirName + infileName.split(".")[0]+"_2080_8000_raw.asm"
            outfileName2000_8000Parsed = srcDirName + infileName.split(".")[0]+"_2080_8000.a96"
            
            

            print("Dissassembling indata[0x2080:0x8000]")
            outfile = open(outfileName2080_8000Raw, 'wt')
            dx = self._ctx.disassemble(indata[0x2080:0x8000], base_address = 0x2080, offset = 0x00)
            outfile.write(str(dx))
            outfile.close()

            infile = open(outfileName2080_8000Raw, 'rt')
            outfileparsed = open(outfileName2000_8000Parsed, 'wt')

            lastNextLineAddr0x2000 = self.ParseFile(infile, outfileparsed)   

            infile.close()
            outfileparsed.close()

            parsedOutfilenames =[outfileName2000_8000Parsed]

            # find last none FF entry in indata:
            counter = len(indata) - 1
            lastAddr = 0

            while(counter > 0) & (lastAddr == 0):
                if (indata[counter] != 0xFF):
                    lastAddr = counter
                counter -= 1
            
            counter = 0xc000


            while(counter < lastAddr):
                print("Dissassembling indata["+str(hex(counter))+" : "+str(hex((counter+0x4000)))+"]")
                dx = self._ctx.disassemble(indata[counter : (counter+0x4000)], base_address = 0xC000, offset = 0x00)

                outfileNameRaw = projectDirName + infileName.split(".")[0]+"_" + str(hex(counter)) +"_" + str(hex(counter+0x4000)) +"_raw.asm"
                outfileNameParsed = srcDirName + infileName.split(".")[0]+"_" + str(hex(counter)) +"_" + str(hex(counter+0x4000)) +".a96"
                parsedOutfilenames += [outfileNameParsed]

                outfile = open(outfileNameRaw, 'wt')

                outfile.write(str(dx))
                outfile.close()

                infile = open(outfileNameRaw, 'rt')
                outfileparsed = open(outfileNameParsed, 'wt')

                self.ParseFile(infile, outfileparsed)   

                infile.close()
                outfileparsed.close()
            
                counter +=0x4000

            

            

            # search for jumppoint in lower addr areas
            first200Addr = 0x400
            first500Addr = 0x2000
            
            print("\nsearch for jumppoint in lower addr areas\n")
            for el in self._funcJumpList[0]:
                jumpaddr = self._funcJumpList[0][el][0]
                if (jumpaddr >= 0x500) & (jumpaddr < 0x2000):
                    if(jumpaddr < first500Addr):
                        first500Addr = jumpaddr
                
                if (jumpaddr >= 0x200) & (jumpaddr < 0x400):
                    if(jumpaddr < first200Addr):
                        first200Addr = jumpaddr
                        
            for el in self._funcJumpList[1]:
                jumpaddr = self._funcJumpList[1][el][0]
                if (jumpaddr >= 0x500) & (jumpaddr < 0x2000):
                    if(jumpaddr < first500Addr):
                        first500Addr = jumpaddr
                
                if (jumpaddr >= 0x200) & (jumpaddr < 0x400):
                    if(jumpaddr < first200Addr):
                        first200Addr = jumpaddr

            for el in self._funcCallList:
                jumpaddr = self._funcCallList[el][0]
                if (jumpaddr >= 0x500) & (jumpaddr < 0x2000):
                    if(jumpaddr < first500Addr):
                        first500Addr = jumpaddr
                
                if (jumpaddr >= 0x200) & (jumpaddr < 0x400):
                    if(jumpaddr < first200Addr):
                        first200Addr = jumpaddr
            
            for el in self._vectPointerList:
                jumpaddr = self._vectPointerList[el]
                if (jumpaddr >= 0x500) & (jumpaddr < 0x2000):
                    if(jumpaddr < first500Addr):
                        first500Addr = jumpaddr
                
                if (jumpaddr >= 0x200) & (jumpaddr < 0x400):
                    if(jumpaddr < first200Addr):
                        first200Addr = jumpaddr

            #print(hex(first200Addr), hex(first500Addr))

            print("Dissassembling indata["+str(hex(first200Addr))+" : 0x400]")
            outfileName200_400Raw = projectDirName + infileName.split(".")[0]+"_200_400_raw.asm"
            outfileName200_400Parsed = srcDirName + infileName.split(".")[0]+"_200_400.a96"
            parsedOutfilenames = [outfileName200_400Parsed] + parsedOutfilenames

            outfile = open(outfileName200_400Raw, 'wt')
            
            dx = self._ctx.disassemble(indata[first200Addr:0x400], base_address = first200Addr, offset = 0x00)

            outfile.write(str(dx))
            outfile.close()
            
            infile = open(outfileName200_400Raw, 'rt')
            outfileparsed = open(outfileName200_400Parsed, 'wt')
            self.ParseFile(infile, outfileparsed)   

            outfileparsed.close()
            infile.close()

            print("Dissassembling indata["+str(hex(first500Addr))+" : 0x2000]")
            outfileName500_2000Raw = projectDirName + infileName.split(".")[0]+"_500_2000_raw.asm"
            outfileName500_2000Parsed = srcDirName + infileName.split(".")[0]+"_500_2000.a96"
            parsedOutfilenames = [outfileName500_2000Parsed] + parsedOutfilenames
            outfile = open(outfileName500_2000Raw, 'wt')
            dx = self._ctx.disassemble(indata[first500Addr:0x2000], base_address = first500Addr, offset = 0x00)

            outfile.write(str(dx))
            outfile.close()

            infile = open(outfileName500_2000Raw, 'rt')
            outfileparsed = open(outfileName500_2000Parsed, 'wt')
            self.ParseFile(infile, outfileparsed)   

            outfileparsed.close()
            infile.close()

            # second search for jumppoint in lower addr areas (appears if code is ahead of jumped locations)
            first200AddrOld = first200Addr
            first500AddrOld = first500Addr
            
            print("\n second search for jumppoint in lower addr areas\n")
            for el in self._funcJumpList[0]:
                jumpaddr = self._funcJumpList[0][el][0]
                if (jumpaddr >= 0x500) & (jumpaddr < 0x2000):
                    if(jumpaddr < first500Addr):
                        first500Addr = jumpaddr
                
                if (jumpaddr >= 0x200) & (jumpaddr < 0x400):
                    if(jumpaddr < first200Addr):
                        first200Addr = jumpaddr
                        
            for el in self._funcJumpList[1]:
                jumpaddr = self._funcJumpList[1][el][0]
                if (jumpaddr >= 0x500) & (jumpaddr < 0x2000):
                    if(jumpaddr < first500Addr):
                        first500Addr = jumpaddr
                
                if (jumpaddr >= 0x200) & (jumpaddr < 0x400):
                    if(jumpaddr < first200Addr):
                        first200Addr = jumpaddr

            for el in self._funcCallList:
                jumpaddr = self._funcCallList[el][0]
                if (jumpaddr >= 0x500) & (jumpaddr < 0x2000):
                    if(jumpaddr < first500Addr):
                        first500Addr = jumpaddr
                
                if (jumpaddr >= 0x200) & (jumpaddr < 0x400):
                    if(jumpaddr < first200Addr):
                        first200Addr = jumpaddr

            if(first200Addr < first200AddrOld):
                print("Dissassembling indata["+str(hex(first200Addr))+" : 0x400]")
                outfileName200_400Raw = projectDirName + infileName.split(".")[0]+"_200_400_raw.asm"
                outfileName200_400Parsed = srcDirName + infileName.split(".")[0]+"_200_400.a96"
                #parsedOutfilenames = [outfileName200_400Parsed] + parsedOutfilenames

                outfile = open(outfileName200_400Raw, 'wt')
                
                dx = self._ctx.disassemble(indata[first200Addr:0x400], base_address = first200Addr, offset = 0x00)

                outfile.write(str(dx))
                outfile.close()
                
                infile = open(outfileName200_400Raw, 'rt')
                outfileparsed = open(outfileName200_400Parsed, 'wt')
                self.ParseFile(infile, outfileparsed)   

                outfileparsed.close()
                infile.close()

            if(first500Addr < first500AddrOld):
                print("Dissassembling indata["+str(hex(first500Addr))+" : 0x2000]")
                outfileName500_2000Raw = projectDirName + infileName.split(".")[0]+"_500_2000_raw.asm"
                outfileName500_2000Parsed = srcDirName + infileName.split(".")[0]+"_500_2000.a96"
                #parsedOutfilenames = [outfileName500_2000Parsed] + parsedOutfilenames
                outfile = open(outfileName500_2000Raw, 'wt')
                dx = self._ctx.disassemble(indata[first500Addr:0x2000], base_address = first500Addr, offset = 0x00)

                outfile.write(str(dx))
                outfile.close()

                infile = open(outfileName500_2000Raw, 'rt')
                outfileparsed = open(outfileName500_2000Parsed, 'wt')
                self.ParseFile(infile, outfileparsed)   

                outfileparsed.close()
                infile.close()

                
            copyFiles = []
            
            startAddr = 0x500
            fileName =  "D500.a96"
            self.WriteDataFile(fileName, srcDirName,  startAddr, indata[startAddr:first500Addr], projectName)
            copyFiles += [srcDirName+fileName]

            startAddr = 0x8000
            #find first data in main segment:
            counter = lastNextLineAddr0x2000
            while(indata[counter] == 0xFF):
                counter += 1

            if(counter < startAddr):
                startAddr = counter
                print("found data in main segment < 0x8000", hex(counter))
            fileName = "D8000.a96"
            self.WriteDataFile(fileName, srcDirName, startAddr, indata[startAddr:0xc000], projectName)
            copyFiles += [srcDirName+fileName]

            ##add function headers

            for el in parsedOutfilenames:
                print("adding function headers in file :", el)
                self.FillFunctionHeaders(el)

            self.ReduceJumpLists()

            ##replace jump adresses with references

            for el in parsedOutfilenames:
                print("replacing jump adresses with references in file :", el)
                self.FillJumpCallRefs(el)

            

            ## emmit window register defs:
            print("emmit window register defs :")
            
            regFileName = srcDirName + "regwsr.inc"
            regFile = open(regFileName, 'wt')
            regFile.write("\n")
            for el in self._wsrDefList:
                addr = self._wsrDefList[el]
                line = el +(20-(len(el)))*" " + "\tEQU\t\t" + self.NumToOldHexString(addr) + ":BYTE\n"
                regFile.write(line)
                
            regFile.write("\n")
            regFile.close()

            copyFiles += [regFileName]



            jumpCallRefFiles = []
            jumpCallPublicsFiles = []

## emmit JumpCallRefs from no segms to none segm defs:
            
            print("emmit JumpCallRefs from part 0x500 to none segm defs:")
            
            segm = 0x500
            segmSize = 0x1B00
            toLowerLimit = 0
            toUpperLimit = 0xffff

            self.jumpListfrom500, self.jumpListTo500 = self.EmmitJumpRefsToDict( segm, segmSize, toLowerLimit, toUpperLimit)

            SegmJumpFileName = srcDirName + infileName.split(".")[0]+"_JumpRefs"+hex(segm)+"ToNoneSegm.inc"
            jumpCallRefFiles += [SegmJumpFileName]
            self.WriteJumpRefFile(SegmJumpFileName, self.jumpListfrom500)

            SegmJumpFileName = srcDirName + infileName.split(".")[0]+"_JumpRefPubilcsTo"+hex(segm)+".inc"
            jumpCallPublicsFiles += [SegmJumpFileName]
            self.WriteJumpRefFile(SegmJumpFileName, self.jumpListTo500)
            

## emmit JumpCallRefs from no segms to none segm defs:
            print("emmit JumpCallRefs from part 0x200 to none segm defs:")
            
            segm = 0x200
            segmSize = 0x200
            toLowerLimit = 0
            toUpperLimit = 0xffff

            self.jumpListfrom200, self.jumpListTo200 = self.EmmitJumpRefsToDict( segm, segmSize, toLowerLimit, toUpperLimit)

            SegmJumpFileName = srcDirName + infileName.split(".")[0]+"_JumpRefs"+hex(segm)+"ToNoneSegm.inc"
            jumpCallRefFiles += [SegmJumpFileName]
            self.WriteJumpRefFile(SegmJumpFileName, self.jumpListfrom200)

            SegmJumpFileName = srcDirName + infileName.split(".")[0]+"_JumpRefPubilcsTo"+hex(segm)+".inc"
            jumpCallPublicsFiles += [SegmJumpFileName]
            self.WriteJumpRefFile(SegmJumpFileName, self.jumpListTo200)

## emmit JumpCallRefs from no segms to none segm defs:
            print("emmit JumpCallRefs from part 0x2000 to none segm defs:")
            
            segm = 0x2000
            segmSize = 0x6000
            toLowerLimit = 0
            toUpperLimit = 0xffff

            self.jumpListfrom2000, self.jumpListTo2000 = self.EmmitJumpRefsToDict( segm, segmSize, toLowerLimit, toUpperLimit)

            SegmJumpFileName = srcDirName + infileName.split(".")[0]+"_JumpRefs"+hex(segm)+"ToNoneSegm.inc"
            jumpCallRefFiles += [SegmJumpFileName]
            self.WriteJumpRefFile(SegmJumpFileName, self.jumpListfrom2000)

            SegmJumpFileName = srcDirName + infileName.split(".")[0]+"_JumpRefPubilcsTo"+hex(segm)+".inc"
            jumpCallPublicsFiles += [SegmJumpFileName]
            self.WriteJumpRefFile(SegmJumpFileName, self.jumpListTo2000)

            ## emmit JumpCallRefs from first Segment defs:
            segm = 0xc000
            segmSize = 0x4000
            toLowerLimit = 0
            toUpperLimit = 0xbfff
            while (segm < len(indata)):
                print("emmit JumpCallRefs from part ", str(hex(segm)),"to < 0xc000 :")
                

                jumpListfromSegm, jumpListToSegm = self.EmmitJumpRefsToDict( segm, segmSize, toLowerLimit, toUpperLimit)

                SegmJumpFileName = srcDirName + infileName.split(".")[0]+"_JumpRefsToLowerFromSegm"+hex(segm)+".inc"
                jumpCallRefFiles += [SegmJumpFileName]
                self.WriteJumpRefFile(SegmJumpFileName, jumpListfromSegm)

                SegmJumpFileName = srcDirName + infileName.split(".")[0]+"_JumpRefPubilcsTo"+hex(segm)+".inc"
                jumpCallPublicsFiles += [SegmJumpFileName]
                self.WriteJumpRefFile(SegmJumpFileName, jumpListToSegm)
                segm += segmSize

            
            ## emmit JumpCallRefs from all Segment defs:
            segm = 0x10000
            segmSize = len(indata) - segm
            toLowerLimit = 0
            toUpperLimit = 0xbfff
##            while (segm < len(indata)):
            print("emmit JumpCallRefs from all uppper part ", str(hex(segm)),"to < 0xc000 :")
            

            self.jumpListfromSegm, self.jumpListToSegm = self.EmmitJumpRefsToDict( segm, segmSize, toLowerLimit, toUpperLimit)

##            SegmJumpFileName = srcDirName + "_JumpRefsToLowerFromUpperSegms.inc"
##            jumpCallRefFiles += [SegmJumpFileName]
##            self.WriteJumpRefFile(SegmJumpFileName, jumpListfromSegm)
##            
##
##            SegmJumpFileName = srcDirName + infileName.split(".")[0]+"_JumpRefPubilcsTo"+hex(segm)+".inc"
##            jumpCallPublicsFiles += [SegmJumpFileName]
##            self.WriteJumpRefFile(SegmJumpFileName, jumpListToSegm)

            SegmJumpFileName = srcDirName + "ToLowRef.inc"
            regFile = open(SegmJumpFileName, 'wt')
            regFile.write("\n")
            for addr in self.jumpListfromSegm:
                el = self.jumpListfromSegm[addr]
                line = "\textrn\t"+ el.split("\t")[0] + "\n"
                regFile.write(line)
                
            regFile.write("\n")
            regFile.close()

            copyFiles += [SegmJumpFileName]
            

            SegmJumpFileName = srcDirName + "SegRef.inc"
            regFile = open(SegmJumpFileName, 'wt')
            regFile.write("\n")
            for addr in self.jumpListToSegm:
                el = self.jumpListToSegm[addr]
                line = "\textrn\t"+ el.split("\t")[0] + "\n"
                regFile.write(line)
                
            regFile.write("\n")
            regFile.close()

            copyFiles += [SegmJumpFileName]

##                segm += segmSize
            
            

            
            
            #print("\n sjmp and cond jumps jumplist 0x8000 - 0xc000\n")
            for el in self._funcJumpList[0]:
                jumpaddr = self._funcJumpList[0][el][0]
                if (jumpaddr >= 0x8000) & (jumpaddr < 0xc000):
                    print("ParseError: sjump not handled :",hex(el), hex(jumpaddr))

            #print("\n LJMP jumplist 0x8000 - 0xc000\n")
            for el in self._funcJumpList[1]:
                jumpaddr = self._funcJumpList[1][el][0]
                if (jumpaddr >= 0x8000) & (jumpaddr < 0xc000):
                    print("ParseError: Ljump not handled :",hex(el), hex(jumpaddr))

            #print("\\n_funcCallList 0x8000 - 0xc000\n")
            for el in self._funcCallList:
                jumpaddr = self._funcCallList[el][0]
                if (jumpaddr >= 0x8000) & (jumpaddr < 0xc000):
                    print("ParseError: Call not handled :",hex(el), hex(jumpaddr))

##            for el in self._funcCallList:
##                jumpaddr = self._funcCallList[el][0]
##                print(hex(el), hex(jumpaddr))

            print("emmit none ori bin conform files")
            outfiles = []

            
            includes = "$include (idxExt.inc)\n"
            includes += "$include (SegRef.inc)\n"

            mainString = ""

            ccbText = self.GenCCBsAndJumpTable(indata[0x2000:0x2080])

            print(hex(first200Addr), hex(first500Addr))
            outfilename = self.WriteMainFile(parsedOutfilenames[2], srcDirName, jumpCallRefFiles[2], jumpCallPublicsFiles[2], projectName, ccbText)
            outfiles += [outfilename]
            codeOffset = first500Addr;
            moduleNameAddr = 0x500
            outfilename = self.WriteModuleFile(parsedOutfilenames[0], moduleNameAddr, codeOffset, srcDirName, jumpCallRefFiles[0], jumpCallPublicsFiles[0], projectName, includes, mainString)
            outfiles += [outfilename]
            codeOffset = first200Addr;
            moduleNameAddr = 0x200
            outfilename = self.WriteModuleFile(parsedOutfilenames[1], moduleNameAddr, codeOffset, srcDirName, jumpCallRefFiles[1], jumpCallPublicsFiles[1], projectName, includes, mainString)
            outfiles += [outfilename]
            codeOffset = 0xC000;
            moduleNameAddr = 0xC000
            outfilename = self.WriteModuleFile(parsedOutfilenames[3], moduleNameAddr, codeOffset, srcDirName, jumpCallRefFiles[3], jumpCallPublicsFiles[3], projectName, includes, mainString)
            outfiles += [outfilename]

            includes = "$include (idxExt.inc)\n"
            includes += "$include (ToLowRef.inc)\n"

            refs = []   # empty refs and publics for segment files, refs are in ToLowRef.inc for all segment files

            mainString = "main"
            counter = 4
            startAddress = 0x10000
            while(counter < len(parsedOutfilenames)):
                outfilename = self.WriteModuleFile(parsedOutfilenames[counter], startAddress, startAddress, srcDirName, refs, jumpCallPublicsFiles[counter], projectName, includes, mainString)
                outfiles += [outfilename]
                startAddress += 0x4000
                counter += 1


            IndexRefs = []
            IndexRefsNoneConf = []

            print("emmit ori bin conform files", outfiles)

            for file in outfiles:
                dataRef = self.ParseToOriBinCompatible(file)
                IndexRefs += dataRef

            for file in outfiles:
                dataRef = self.ParseToNoneConf(file)
                IndexRefsNoneConf += dataRef

            print("write ext index ref file")
            indexFileName = "idx.a96"

            self.WriteIndexRefs(indexFileName, srcOriConformDirName, IndexRefs, projectName);

            self.WriteIndexRefs(indexFileName, srcNoneConformDirName, IndexRefsNoneConf, projectName);

            incfiles = ["80C196KR.H"]
            incfiles += ["asic.inc"]
            incfiles += ["kr.inc"]
            incfiles += ["macro.inc"]
            incfiles += createRamRegList.Run()
            

            print("copy and move files to ori bin conform and none conform src folder")
            # copy files and rename
            for file in outfiles:
                slashpos = file.rfind("/")
                newfilePath = srcNoneConformDirName + file[slashpos+1:]
                shutil.move(file, newfilePath)
                ppos = file.rfind(".")
                confFileName = file[:ppos]+"_m"+file[ppos:]
                os.rename(confFileName, file)
                newfilePath = srcOriConformDirName + file[slashpos+1:]
                shutil.move(file, newfilePath)

            for file in copyFiles:
                slashpos = file.rfind("/")
                newfilePath = srcNoneConformDirName + file[slashpos+1:]
                shutil.copyfile(file, newfilePath)
                newfilePath = srcOriConformDirName + file[slashpos+1:]
                shutil.move(file, newfilePath)

            for file in incfiles:
                newfilePath = srcNoneConformDirName + file
                shutil.copyfile(file, newfilePath)
                newfilePath = srcOriConformDirName + file
                shutil.copyfile(file, newfilePath)

            compileFiles = ["genbin.py", "RunClean.bat", "RunCompile.py", "dosboxbuild.conf"]
            for file in compileFiles:
                newfilePath = projectNoneConformDirName + file
                shutil.copyfile(file, newfilePath)
                newfilePath = projectOriConformDirName + file
                shutil.copyfile(file, newfilePath)


            
##
def Run():
    infileName = []

    if(len(sys.argv) < 2):
        print("no file argument given! like: 557s.bin")
        infileName = input("type filename and enter:\n")
    ##    if(len(infileName) == 0):
    ##       return 2
        
    else:
        infileName = sys.argv[1]

    try:
        infileName = str(infileName)


        inFile = open(infileName,'rb')

        #inData = inFile.read()
        inFile.close()
        del inFile
    except:
        print("wrong filename given and needs to be string! ")
        input("press enter to exit")
        return 3
    
    toCode = M38ToCode()
    toCode.Run(infileName)


if (__name__ == "__main__") :
    Run()  
