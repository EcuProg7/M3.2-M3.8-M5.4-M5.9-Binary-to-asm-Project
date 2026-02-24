# M3.2-M3.8-M5.4-M5.9-Binary-to-asm-Project
Generates asm files from binary of Motronic 3.2/3.8/5.4/5.9 and yields compileable assembler project

For educational and research use only

# Start of parsing
  open RunCompile.py and change the line with compile Path : IC96Path = "E:\\temp\\MCS96" to yours .
    directory needs to have IC96, IC96/include, IC96/lib, IC96/bin with asm96, RL96, OH96 in bin folder
    compiler is here: https://www.njohnson.co.uk/zip/Roland/96tools.zip 

  unpack MCS196.zip and copy to your python path with pypcode script: #python#/lib/site-packages/pypcode/processors/
    
  start pypcodeAnalyze.py and input filename to parse like : 4D0907557G.bin .
  parser outputs a project directory with two source folder, one original binary conform, one not .
    the conform files have additional parsing to get the intel asm compiler behave like the one used for ori bin .
    the none conform files have unnecessary zero index removed .

# start compile
  Dosbox is needed to compile
  open Project folder, goto either  source you want, compile scripts have been copied from parser .
  hit RunCompile.py and relax
