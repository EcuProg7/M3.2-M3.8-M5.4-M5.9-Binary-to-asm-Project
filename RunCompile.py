import os
import genbin
import shlex;
import subprocess;
import re

IC96Path = "E:\\temp\\MCS96"

RunCompFileName = "Runcomp.bat"
compFileName = "comp.bat"
compFileName2 = "comp2.bat"
RunCompFileName2 = "Runcomp2.bat"
LinkerPramFileName = "lfile.l"

compileBat = open(RunCompFileName, 'wt')
cwd = os.getcwd()
lastBslash = cwd.rfind("\\")
projectDir = cwd[lastBslash+1:]
upperDir = cwd[:lastBslash]

srcDirName = cwd + "\\build\\"
if not os.path.exists(srcDirName):
    os.makedirs(srcDirName)

srcDirName = cwd + "\\build\\lst\\"
if not os.path.exists(srcDirName):
    os.makedirs(srcDirName)

srcDirName = cwd + "\\build\\obj\\"
if not os.path.exists(srcDirName):
    os.makedirs(srcDirName)


srcDirName = cwd + "\\build\\m96\\"
if not os.path.exists(srcDirName):
    os.makedirs(srcDirName)



compileBat.write("\"C:\\Program Files (x86)\\DOSBox-0.74-3\\DOSBox.exe\" -conf .\\dosboxbuild.conf -noconsole -c \"mount c "+ cwd +"\" -c \"mount e "+ IC96Path +"\" -c c:  -c "+compFileName+ "\n")
compileBat.close()


compileBat = open(compFileName, 'wt')
mypath = cwd + "\\src"
mainFiles = ["main.a96", "P200.a96", "P500.a96", "Pc000.a96"]
asmFiles = []
files = []
for (dirpath, dirnames, filenames) in os.walk(mypath):
    files = filenames
    break

for file in files:
    counter = 0x10
    while counter < 0x40:
        name = "P" + str(hex(counter)).split("0x")[1]+"000.a96"
        if (file.find(name) != -1):
            asmFiles += [name]
        counter += 0x4
print("segment files found: ",asmFiles)


compileBat.write("set C96INC=e:\\IC96\\include\n")
compileBat.write("set C96LIB=e:\\IC96\\lib\n")
compileBat.write("set PATH=%PATH%;e:\\IC96\\bin\n\n")
#compileBat.write("cd "+projectDir+"\\src\n")
compileBat.write("cd src\n\n")


compileBat.write("asm96 D500.a96 sb ge db\n")
compileBat.write("asm96 D8000.a96 sb ge db\n")
compileBat.write("asm96 idx.a96 sb ge db\n")
for file in mainFiles:
    compileBat.write("asm96 " + file + " sb ge db\n")

for file in asmFiles:
    compileBat.write("asm96 " + file + " sb ge db\n")

compileBat.write("\n")



#compileBat.write("pause\n")
compileBat.write("exit\n")



compileBat.close()

args = shlex.split(RunCompFileName);
ret = subprocess.call(args);

jumpToLowerDict = dict()
# parse publics to generate ToLowRef.a96
for file in mainFiles:
    lstFile = open("./src/"+file.split(".")[0]+".lst")
    line = lstFile.readline()
    while (line.find("SYMBOL TABLE LISTING") == -1) & (len(line) != 0):
        line = lstFile.readline()
    #print("\n jump and call publics in file ", file,"\n")
    while (len(line) != 0):
        if(line.find("PUBLIC ENTRY") != -1) :
            name = line.split(".")[0]
            addr = re.search("\w*H", line).group()
            jumpToLowerDict[name] = addr
            #print(line)
        line = lstFile.readline()
    lstFile.close()
    
refFile = open("./src/ToLowRef.a96", 'wt')
refFile.write("\tToLowRef module \n")
for name in jumpToLowerDict:
    addrstring = jumpToLowerDict[name]
    refFile.write("\t"+name+"\tEQU\t0"+ addrstring +" \n")


refFile.write("\n")
for name in jumpToLowerDict:
    addrstring = jumpToLowerDict[name]
    refFile.write("\tpublic\t"+name+"\n")

refFile.write("\n\n\tend\n")
refFile.close()
    

jumpToSegDict = dict()
# parse publics to generate SegRef.a96
for file in asmFiles:
    lstFile = open("./src/"+file.split(".")[0]+".lst")
    line = lstFile.readline()
    while (line.find("SYMBOL TABLE LISTING") == -1) & (len(line) != 0):
        line = lstFile.readline()
    #print("\n jump and call publics in file ", file,"\n")
    while (len(line) != 0):
        if(line.find("PUBLIC ENTRY") != -1) :
            name = line.split(".")[0]
            addr = re.search("\w*H", line).group()
            jumpToSegDict[name] = addr
            #print(line)
        line = lstFile.readline()
    lstFile.close()
    
refFile = open("./src/SegRef.a96", 'wt')
refFile.write("\tToLowRef module \n")
for name in jumpToSegDict:
    addrstring = jumpToSegDict[name]
    refFile.write("\t"+name+"\tEQU\t0"+ addrstring +" \n")


refFile.write("\n")
for name in jumpToSegDict:
    addrstring = jumpToSegDict[name]
    refFile.write("\tpublic\t"+name+"\n")

refFile.write("\n\n\tend\n")
refFile.close()

compileBat = open(RunCompFileName2, 'wt')

compileBat.write("\"C:\\Program Files (x86)\\DOSBox-0.74-3\\DOSBox.exe\" -conf .\\dosboxbuild.conf -noconsole -c \"mount c "+ cwd +"\" -c \"mount e "+ IC96Path +"\" -c c:  -c "+compFileName2+ "\n")

compileBat.write("move src\\*.lst build\\lst\\\n")
compileBat.write("move src\\*.obj build\\obj\\\n")
compileBat.write("move src\\*.hex build\\\n")
compileBat.write("move src\\*.m96 build\\m96\\\n")
compileBat.write("move src\\*.abs build\\\n")
#compileBat.write("pause\n")
compileBat.close()



compileBat = open(compFileName2, 'wt')

compileBat.write("set C96INC=e:\\IC96\\include\n")
compileBat.write("set C96LIB=e:\\IC96\\lib\n")
compileBat.write("set PATH=%PATH%;e:\\IC96\\bin\n\n")
#compileBat.write("cd "+projectDir+"\\src\n")
compileBat.write("cd src\n\n")

compileBat.write("asm96 ToLowRef.a96 sb ge db\n")
compileBat.write("asm96 SegRef.a96 sb ge db\n")

compileBat.write("rl96 &< ..\\lfile.l\n")

for file in asmFiles:
    compileBat.write("rl96 " + file.split(".")[0]+".obj,idx.obj,ToLowRef.obj to " + file.split(".")[0]+".abs RAM(1AH-1FFH, 400H-4FFH) ROM(0c000H-0FFFFH(" + file.split(".")[0] + ")) stacksize(20H)\n")

#compileBat.write("pause\n")
compileBat.write("oh lowSegm.abs\n")
for file in asmFiles:
    compileBat.write("oh " + file.split(".")[0]+".abs\n")

#compileBat.write("pause\n")
compileBat.write("exit\n")

compileBat.close()

compileBat = open(LinkerPramFileName, 'wt')

compileBat.write("main.obj,P200.obj,P500.obj,PC000.obj,D500.obj,&\n")
compileBat.write(" D8000.obj,idx.obj,SegRef.obj to lowSegm.abs&\n")
compileBat.write(" RAM(1AH-1FFH, 400H-4FFH)&\n")
compileBat.write(" ROM(200H-3FFH(P200),500H-1FFFH(D500, P500),&\n")
compileBat.write(" 2000H-7FFFH(PMAIN),8000H-0BFFFH(D8000),&\n")
compileBat.write(" 0c000H-0FFFFH(PC000)) stacksize(20H)\n")
compileBat.close()

args = shlex.split(RunCompFileName2);
ret = subprocess.call(args);

genbin.Run()
os.remove(RunCompFileName)
os.remove(RunCompFileName2)
os.remove(compFileName)
os.remove(compFileName2)
print("\n")

#parse warnings and errors
mypath = cwd + "\\build\\lst"
lstFiles = []
for (dirpath, dirnames, filenames) in os.walk(mypath):
    files = filenames
    break


name = ".lst"
for file in files:
    if (file.lower().find(name) != -1):
        lstFiles += [file]

for file in lstFiles:
    print("errors in asm list file ", file)
    infile = open("./build/lst/" + file, 'rt')
    lastline = infile.readline()
    line = infile.readline()
    while (len(line) > 0):
        if(line.lower().find("error") != -1):
            print(lastline, line)
        
        lastline = line
        line = infile.readline()

print("\n")

#parse warnings and errors
mypath = cwd + "\\build\\m96"
lstFiles = []
for (dirpath, dirnames, filenames) in os.walk(mypath):
    files = filenames
    break


name = ".m96"
for file in files:
    if (file.lower().find(name) != -1):
        lstFiles += [file]

for file in lstFiles:
    print("errors in module file ", file)
    infile = open("./build/m96/" + file, 'rt')
    line = infile.readline()
    while (len(line) > 0):
        if(line.lower().find("error") != -1) | (line.lower().find("warning") != -1):
            while(len(line)>1):
                print( line[:-1])
                line = infile.readline()
            print("\n")
        
        line = infile.readline()


input("press enter to leave")


