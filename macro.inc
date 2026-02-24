; This section defines utility macros non-specific to this program
; ----------------------------------------------------------------
DEFINE_BIT	macro	name,bitnum
			name	equ bitnum
			endm

SET_BIT		macro	regnum,bitnum
			orb	regnum,#( 1 SHL (bitnum mod 8)  )
			endm

CLR_BIT		macro	regnum,bitnum
			andb	regnum,#not( 1 SHL (bitnum mod 8) )
			endm

SET_PORT_BIT	macro	regnum,bitnum
			ldb	WSR,#1FH
			orb	regnum,#( 1 SHL (bitnum mod 8)  )
			clrb	WSR
			endm

CLR_PORT_BIT	macro	regnum,bitnum
			ldb	WSR,#1FH
			andb	regnum,#not( 1 SHL (bitnum mod 8) )
			clrb	WSR
			endm

BL		macro	label
			bnc	label
			endm

LD_SI3	macro	first,sec, index
			dcb		0A3H
			dcb		index
			dcb		sec
			dcb		first
			endm

ST_SI3	macro	first,sec, index
			dcb		0C3H
			dcb		index
			dcb		sec
			dcb		first
			endm
			
LDB_SI3	macro	first,sec, index
			dcb		0B3H
			dcb		index
			dcb		sec
			dcb		first
			endm

STB_SI3	macro	first,sec, index
			dcb		0C7H
			dcb		index
			dcb		sec
			dcb		first
			endm
			
SUB_SI4	macro	first,sec, third, index
			dcb		04BH
			dcb		index
			dcb		third
			dcb		sec
			dcb		first
			endm	
			
SUB_SI3	macro	first,sec, index
			dcb		06BH
			dcb		index
			dcb		sec
			dcb		first
			endm

ADD_SI4	macro	first,sec, third, index
			dcb		047H
			dcb		index
			dcb		third
			dcb		sec
			dcb		first
			endm	

ADD_SI3	macro	first,sec, index
			dcb		067H
			dcb		index
			dcb		sec
			dcb		first
			endm
			
CMP_SI3	macro	first,sec, index
			dcb		08BH
			dcb		index
			dcb		sec
			dcb		first
			endm	
			
CMPB_SI3	macro	first,sec, index
			dcb		09BH
			dcb		index
			dcb		sec
			dcb		first
			endm

			
