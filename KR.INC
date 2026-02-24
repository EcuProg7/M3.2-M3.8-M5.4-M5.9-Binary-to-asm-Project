;*****************************************************************************
;       KR.INC - DEFINITION OF SYMBOLIC NAMES FOR THE I/O REGISTERS
;                OF THE 8XC196KR
;
;                These symbols correspond with the register names
;                as defined in the 8XC196KR User's Manual.
;
;                Copyright INTEL Corporation 1991
;*****************************************************************************

ZR				EQU     00H:WORD	;zero_reg
ZRlo			EQU     00H:BYTE	;zero_reg
ZRhi			EQU     01H:BYTE	;zero_reg
ONES_REG_L      EQU     02H:BYTE	;ones_reg
ONES_REG_H      EQU     03H:BYTE	;ones_reg
ONES_REG        EQU     02H:WORD	;ones_reg
ZR_ONES         EQU     00H:LONG	;zero_and_ones_reg double word
WATCHDOG        EQU     0AH:BYTE
WATCHDOG_L      EQU     0AH:BYTE
WSR             EQU     14H:BYTE
SP              EQU     18H:WORD
SPlo            EQU     18H:BYTE

USFR            EQU     1FF6H:BYTE

P0_PIN          EQU     1FDAH:BYTE

P1_PIN          EQU     1FD6H:BYTE
P1_REG          EQU     1FD4H:BYTE
P1_DIR          EQU     1FD2H:BYTE
P1_MODE         EQU     1FD0H:BYTE

P2_PIN          EQU     1FCFH:BYTE
P2_REG          EQU     1FCDH:BYTE
P2_DIR          EQU     1FCBH:BYTE
P2_MODE         EQU     1FC9H:BYTE

P3_PIN          EQU     1FFEH:BYTE
P3_REG          EQU     1FFCH:BYTE

P4_PIN          EQU     1FFFH:BYTE
P4_REG          EQU     1FFDH:BYTE

P5_PIN          EQU     1FF7H:BYTE
P5_REG          EQU     1FF5H:BYTE
P5_DIR          EQU     1FF3H:BYTE
P5_MODE         EQU     1FF1H:BYTE

P6_PIN          EQU     1FD7H:BYTE
P6_REG          EQU     1FD5H:BYTE
P6_DIR          EQU     1FD3H:BYTE
P6_MODE         EQU     1FD1H:BYTE

PTSSEL          EQU     04H:WORD
PTSSEL_L        EQU     04H:BYTE
PTSSEL_H        EQU     05H:BYTE
PTSSRV          EQU     06H:WORD
PTSSRV_L        EQU     06H:BYTE
PTSSRV_H        EQU     07H:BYTE

INT_MASK        EQU     08H:BYTE
INT_PEND        EQU     09H:BYTE
INT_PEND1       EQU     12H:BYTE
INT_MASK1       EQU     13H:BYTE

EPAIPV          EQU     1FA8H:BYTE
EPAIPV_L        EQU     1FA8H:BYTE
EPA_PEND        EQU     1FA2H:WORD
EPA_PEND1       EQU     1FA6H:BYTE      ; BUG... must write to pend1 as a word
EPA_MASK        EQU     1FA0H:WORD
EPA_MASK1       EQU     1FA4H:WORD      ; BUG... must write to mask1 as a word

EPA9_TIME       EQU     1F86H:WORD
EPA9_CON        EQU     1F84H:BYTE
EPA9_CON_L      EQU     1F84H:BYTE
EPA8_TIME       EQU     1F82H:WORD
EPA8_CON        EQU     1F80H:BYTE
EPA8_CON_L      EQU     1F80H:BYTE
EPA7_TIME       EQU     1F7EH:WORD
EPA7_CON        EQU     1F7CH:BYTE
EPA7_CON_L      EQU     1F7CH:BYTE
EPA6_TIME       EQU     1F7AH:WORD
EPA6_CON        EQU     1F78H:BYTE
EPA6_CON_L      EQU     1F78H:BYTE
EPA5_TIME       EQU     1F76H:WORD
EPA5_CON        EQU     1F74H:BYTE
EPA5_CON_L      EQU     1F74H:BYTE
EPA4_TIME       EQU     1F72H:WORD
EPA4_CON        EQU     1F70H:BYTE
EPA4_CON_L      EQU     1F70H:BYTE
EPA3_TIME       EQU     1F6EH:WORD
EPA3_CON        EQU     1F6CH:WORD
EPA3_CON_L      EQU     1F6CH:BYTE
EPA2_TIME       EQU     1F6AH:WORD
EPA2_CON        EQU     1F68H:BYTE
EPA2_CON_L      EQU     1F68H:BYTE
EPA1_TIME       EQU     1F66H:WORD
EPA1_CON        EQU     1F64H:WORD
EPA1_CON_L      EQU     1F64H:BYTE
EPA0_TIME       EQU     1F62H:WORD
EPA0_CON        EQU     1F60H:BYTE
EPA0_CON_L      EQU     1F60H:BYTE

COMP1_TIME      EQU     1F8EH:WORD
COMP1_CON       EQU     1F8CH:BYTE
COMP0_TIME      EQU     1F8AH:WORD
COMP0_CON       EQU     1F88H:BYTE

TIMER1          EQU     1F9AH:WORD
T1VALUE         EQU     1F9AH:WORD
TIMER2          EQU     1F9EH:WORD
T2VALUE         EQU     1F9EH:WORD
T1CONTROL       EQU     1F98H:BYTE
T2CONTROL       EQU     1F9CH:BYTE

AD_TIME         EQU     1FAFH:BYTE
AD_TEST         EQU     1FAEH:BYTE
AD_COMMAND      EQU     1FACH:WORD
AD_COMMAND_L    EQU     1FACH:BYTE
AD_RESULT       EQU     1FAAH:WORD
AD_RESULT_L     EQU     1FAAH:BYTE
AD_RESULT_H     EQU     1FABH:BYTE

SER_CON         EQU     1FBBH:BYTE
SER_BAUD        EQU     1FBCH:WORD
SER_STATUS      EQU     1FB9H:BYTE
SERBUF_TX       EQU     1FBAH:BYTE
SERBUF_RX       EQU     1FB8H:BYTE

SSIO_BAUD       EQU     1FB4H:BYTE
SSIO1_CON       EQU     1FB3H:BYTE
SSIO1_BUF       EQU     1FB2H:BYTE
SSIO0_CON       EQU     1FB1H:BYTE
SSIO0_BUF       EQU     1FB0H:BYTE

SLP_CON         EQU     1FFBH:BYTE
SLP_CMD         EQU     1FFAH:BYTE
SLP_STAT        EQU     1FF8H:BYTE


BANK0           EQU     00H
BANK1F          EQU     1FH       ; WSR = 1f to map 1F80/1FDF -> 80/DF

;***************************************************************************** 

P1PIN           EQU     0D6H:BYTE
P1REG           EQU     0D4H:BYTE
P1IO            EQU     0D2H:BYTE
P1SSEL          EQU     0D0H:BYTE

P3PIN           EQU     0FEH:BYTE
P3REG           EQU     0FCH:BYTE

P6PIN           EQU     0D7H:BYTE
P6REG           EQU     0D5H:BYTE
P6IO            EQU     0D3H:BYTE
P6SSEL          EQU     0D1H:BYTE

P2PIN           EQU     0CFH:BYTE
P2REG           EQU     0CDH:BYTE
P2IO            EQU     0CBH:BYTE
P2SSEL          EQU     0C9H:BYTE

TIMER1_          EQU     09AH:WORD
TIMER2_          EQU     09EH:WORD
TIMER1_CONTROL_  EQU     098H:BYTE
TIMER2_CONTROL_  EQU     09CH:BYTE

SP_BAUD_         EQU     0BCH:WORD
SP_CONTROL_      EQU     0BBH:BYTE
SP_STATUS_       EQU     0B9H:BYTE
SBUF_TX_         EQU     0BAH:BYTE
SBUF_RX_         EQU     0B8H:BYTE

EPAIPV_          EQU     0A8H:BYTE
EPA_PEND_        EQU     0A2H:WORD
EPA_PEND1_       EQU     0A6H:BYTE
EPA_MASK_        EQU     0A0H:WORD
EPA_MASK1_       EQU     0A4H:WORD ; BUG... must write to mask as a word

AD_TIME_         EQU     0AFH:BYTE
AD_TEST_         EQU     0AEH:BYTE
AD_COMMAND_      EQU     0ACH:WORD
AD_RESULT_       EQU     0AAH:WORD

SSIO_BAUD_COUNT_ EQU     0B6H:BYTE
SSIO_BAUD_       EQU     0B4H:BYTE
SSIO_STCR1_      EQU     0B3H:BYTE
SSIO_STB1_       EQU     0B2H:BYTE
SSIO_STCR0_      EQU     0B1H:BYTE
SSIO_STB0_       EQU     0B0H:BYTE
