/* 80C196KR.h
 * Copyright (c) 1990 Intel Corporation, ALL RIGHTS RESERVED.
 *
 * 80C196KR.h  - declarations for 80C196KR SFRs
 */

#ifndef _80c196krh
#define _80c196krh

#pragma extend
#pragma code
#pragma debug
#pragma model(kr)

void enable(void);
void disable(void);

extern register unsigned short					ZERO_REG;
extern register unsigned short					ONES_REG;
extern register volatile unsigned short		PTSSEL;
extern register volatile unsigned short		PTSSRV;

extern register volatile unsigned char		 	INT_MASK;
extern register volatile unsigned char		 	INT_PEND;
extern register volatile unsigned char			WATCHDOG;
extern register volatile unsigned char		 	INT_PEND1;
extern register volatile unsigned char		 	INT_MASK1;
extern register volatile unsigned char			WSR;
extern register volatile unsigned short		SP;

/*
* windows selection BANK1F          EQU     1FH       ; WSR = 1f to map 1F80/1FDF -> 80/DF
*/

extern register volatile unsigned short		AD_RESULT_WSR1F;




extern volatile unsigned char		 USFR;

extern volatile unsigned char		 P0_PIN;

extern volatile unsigned char		 P1_PIN;
extern volatile unsigned char		 P1_REG;
extern volatile unsigned char		 P1_DIR;
extern volatile unsigned char		 P1_MODE;

extern volatile unsigned char		 P2_PIN;
extern volatile unsigned char		 P2_REG;
extern volatile unsigned char		 P2_DIR;
extern volatile unsigned char		 P2_MODE;

extern volatile unsigned char		 P3_PIN;
extern volatile unsigned char		 P3_REG;

extern volatile unsigned char		 P4_PIN;
extern volatile unsigned char		 P4_REG;

extern volatile unsigned char		 P5_PIN;
extern volatile unsigned char		 P5_REG;
extern volatile unsigned char		 P5_DIR;
extern volatile unsigned char		 P5_MODE;

extern volatile unsigned char		 P6_PIN;
extern volatile unsigned char		 P6_REG;
extern volatile unsigned char		 P6_DIR;
extern volatile unsigned char		 P6_MODE;



extern volatile unsigned char		 EPAIPV;
extern volatile unsigned char		 EPA_PEND;
extern volatile unsigned short		 EPA_PEND1;
extern volatile unsigned short		 EPA_MASK;
extern volatile unsigned short		 EPA_MASK1;

extern volatile unsigned short		 EPA9_TIME;
extern volatile unsigned char		 EPA9_CON;
extern volatile unsigned short		 EPA8_TIME;
extern volatile unsigned char		 EPA8_CON;
extern volatile unsigned short		 EPA7_TIME;
extern volatile unsigned char		 EPA7_CON;
extern volatile unsigned short		 EPA6_TIME;
extern volatile unsigned char		 EPA6_CON;
extern volatile unsigned short		 EPA5_TIME;
extern volatile unsigned char		 EPA5_CON;
extern volatile unsigned short		 EPA4_TIME;
extern volatile unsigned char		 EPA4_CON;
extern volatile unsigned short		 EPA3_TIME;
extern volatile unsigned short		 EPA3_CON;
extern volatile unsigned short		 EPA2_TIME;
extern volatile unsigned char		 EPA2_CON;
extern volatile unsigned short		 EPA1_TIME;
extern volatile unsigned short		 EPA1_CON;
extern volatile unsigned short		 EPA0_TIME;
extern volatile unsigned char		 EPA0_CON;

extern volatile unsigned short		 COMP1_TIME;
extern volatile unsigned char		 COMP1_CON;
extern volatile unsigned short		 COMP0_TIME;
extern volatile unsigned char		 COMP0_CON;

extern volatile unsigned short		 TIMER1;
extern volatile unsigned short		 TIMER2;
extern volatile unsigned char		 T1CONTROL;
extern volatile unsigned char		 T2CONTROL;

extern volatile unsigned char		 AD_TIME;
extern volatile unsigned char		 AD_TEST;
extern volatile unsigned short		 AD_COMMAND;
extern volatile unsigned short		 AD_RESULT;

extern volatile unsigned char		 SP_CON;
extern volatile unsigned short		 SP_BAUD;
extern volatile unsigned char		 SP_STATUS;
extern volatile unsigned char		 SBUF_TX;
extern volatile unsigned char		 SBUF_RX;

extern volatile unsigned char		 SSIO_BAUD;
extern volatile unsigned char		 SSIO1_CON;
extern volatile unsigned char		 SSIO1_BUF;
extern volatile unsigned char		 SSIO0_CON;
extern volatile unsigned char		 SSIO0_BUF;

extern volatile unsigned char		 SLP_CON;
extern volatile unsigned char		 SLP_CMD;
extern volatile unsigned char		 SLP_STAT;





#endif /* _80c196krh */
