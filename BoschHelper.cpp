// BoschHelper.cpp: implementation of the BoschHelper class.
//
//////////////////////////////////////////////////////////////////////
//Standard Defs
typedef int     BOOL;
#define FALSE   0
#define TRUE    1
#define NULL    0

#include <ida.hpp>
#include <idp.hpp>//str2reg()
#include <expr.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <offset.hpp>
#include <search.hpp>
#include <srarea.hpp> //SetDefaultRegisterValue()
#include <allins.hpp> // processor instructions
#include <funcs.hpp> //get_func()
#include <enum.hpp> //for enumerations
//#include <ctype.h>
#include "BoschHelper.h"


//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

BoschHelper::BoschHelper()
{
	mSelector = 1;

}

BoschHelper::~BoschHelper()
{

}



//////////////////////////////////////////////////////////////////////
// Helpers
//////////////////////////////////////////////////////////////////////


char *patchASCII(char *src)
	{
	char *instr="122 z 123 { 124 | 125 } 126 ~ 127  128 Ä 129 Å 130 Ç 131 É 132 Ñ 133 Ö 134 Ü 135 á 136 à 137 â 138 ä 139 ã 140 å 141 ç 142 é 143 è 144 ê 145 ë 146 í 147 ì 148 î 149 ï 150 ñ 151 ó 152 ò 153 ô 154 ö 155 õ 156 ú 157 ù 158 û 159 ü 160   161 ° 162 ¢ 163 £ 164 § 165 • 166 ¶ 167 ß 168 ® 169 © 170 ™ 171 ´ 172 ¨ 173 ≠ 174 Æ 175 Ø 176 ∞ 177 ± 178 ≤ 179 ≥ 180 ¥ 181 µ 182 ∂ 183 ∑ 184 ∏ 185 π 186 ∫ 187 ª 188 º 189 Ω 190 æ 191 ø 192 ¿ 193 ¡ 194 ¬ 195 √ 196 ƒ 197 ≈ 198 ∆ 199 « 200 » 201 … 202   203 À 204 Ã 205 Õ 206 Œ 207 œ 208 – 209 — 210 “ 211 ” 212 ‘ 213 ’ 214 ÷ 215 ◊ 216 ÿ 217 Ÿ 218 ⁄ 219 € 220 ‹ 221 › 222 ﬁ 223 ﬂ 224 ‡ 225 · 226 ‚ 227 „ 228 ‰ 229 Â 230 Ê 231 Á 232 Ë 233 È 234 Í 235 Î 236 Ï 237 Ì 238 Ó 239 Ô 240  241 Ò 242 Ú 243 Û 244 Ù 245 ı 246 ˆ 247 ˜ 248 ¯ 249 ˘ 250 ˙ 251 ˚ 252 ¸ 253 ˝ 254 ˛";
	char *gotba="122 z 123 { 124 | 125 } 126 ~ 127  128 « 129 ¸ 130 È 131 ‚ 132 ‰ 133 ‡ 134 Â 135 Á 136 Í 137 Î 138 Ë 139 Ô 140 Ó 141 Ï 142 ƒ 143 ≈ 144 … 145 Ê 146 ∆ 147 Ù 148 ˆ 149 Ú 150 ˚ 151 ˘ 152 ˇ 153 ÷ 154 ‹ 155 ¯ 156 £ 157 ÿ 158 ◊ 159 É 160   161 Ì 162 Û 163 ˙ 164 Ò 165 — 166 ™ 167 ∫ 168 ø 169 Æ 170 ¨ 171 Ω 172 º 173 ° 174 ´ 175 ª 176 ¶ 177 ¶ 178 ¶ 179 ¶ 180 ¶ 181 ¡ 182 ¬ 183 ¿ 184 © 185 ¶ 186 ¶ 187 + 188 + 189 ¢ 190 • 191 + 192 + 193 - 194 - 195 + 196 - 197 + 198 „ 199 √ 200 + 201 + 202 - 203 - 204 ¶ 205 - 206 + 207 § 208  209 – 210   211 À 212 » 213 i 214 Õ 215 Œ 216 œ 217 + 218 + 219 ¶ 220 _ 221 ¶ 222 Ã 223 Ø 224 ” 225 ﬂ 226 ‘ 227 “ 228 ı 229 ’ 230 µ 231 ˛ 232 ﬁ 233 ⁄ 234 € 235 Ÿ 236 ˝ 237 › 238 Ø 239 ¥ 240 ≠ 241 ± 242 = 243 æ 244 ∂ 245 ß 246 ˜ 247 ∏ 248 ∞ 249 ® 250 ∑ 251 π 252 ≥ 253 ≤ 254 ¶";
			
	size_t f=0;
	for (f;f<qstrlen(src);f++)
	{
		if (src[f]=='¸') 
			{
			src[f]=char(129);
			}
		if (src[f]=='‰')
			{
			src[f]=char(132);
			}
		if (src[f]=='ˆ')
			{
			src[f]=char(148);
			}
		
		if (src[f]=='ﬂ')
			{
			src[f]=char(225);
			}

	}
	return(src);
}

char *strip_leading_whitespace(char *dest, char *src)
{
	char *s, *d;
	s= src;
	d= dest;
				size_t i;
				i=0;
				size_t j;
				j=0;
				bool started= false;
				for (i; i<qstrlen(s);i++)
					{
					while (s[i]==' ' && started==false)
						{
						i++;
						}
					//get paste the starting whitespace
						started=true;
						d[j]=s[i];
						j++;
					}
					d[j]=0; //just to be sure


return dest;
}

// Removes **ALL** whitespace from a string
char *strip_whitespace(char *dest, char *src, int n)
{
    char *s, *d;

    /* 
     * Copy 'src' to 'dest', omitting whitespace and making sure we don't
     * overflow 'dest'.
     */
    for(s=src, d=dest; *s && (d-dest)<n; s++) {
        if( !qisspace(*s) ) {
            *d = *s;
            d++;
        }
    }

    /* Ensure that dest is NUL terminated in any event */
    if( d-dest < n ) {
        *d = '\0';
    } else {
        dest[n-1] = '\0';
    }

    return dest;
}

void BoschHelper::CreateInterruptVectorTable()

{
	msg("Creating Interrupt Vector table\n\n");
	size_t eaStartAddress=0x800000;
	size_t tableSize = 0x200;
	size_t eaCurrentAddress=0x800000;


	do_unknown_range (0x800000, 0x30000, 0x0000);

	for (eaCurrentAddress;eaCurrentAddress<(eaStartAddress+tableSize);eaCurrentAddress+=4)
	{
		create_insn(eaCurrentAddress);
	}

return;
}


// Loops through the binary and makes disassembled code
bool BoschHelper::CreateDissCode(ea_t eaStartAddr, ea_t eaEndAddr)
{
	msg("Creating disassembly from 0x%x through to 0x%x\n", eaStartAddr, eaEndAddr);

	ea_t	eaAddr, eaLenOfGeneratedCode;
	int		iCount, iReturns;
	ushort	uWord;

	eaAddr = eaStartAddr;
	eaLenOfGeneratedCode = 1;
	iCount = iReturns = 1;

	for(eaAddr;eaAddr<eaEndAddr;eaAddr+=eaLenOfGeneratedCode)
	{
		//guard against disassembling 0xffff or 0x0000 pairs
		uWord = (ushort)get_16bit(eaAddr);//read the word at the current location
		
		if(uWord == 0xffff)
		{
//			msg("0xffff read at 0x%x\n", eaAddr);
			//doWord(eaAddr, 4);//Convert to data word
			eaAddr+=1;//skip these bytes
		}
		if(uWord == 0x0000)
		{
//			msg("0x0000 read at 0x%x\n", eaAddr);
			//doWord(eaAddr, 4);//Convert to data word
			eaAddr+=1;//skip these bytes
		}
		if(uWord == 0x8000)
		{
//			msg("0x8000 read at 0x%x\n", eaAddr);
			//doWord(eaAddr, 4);//Convert to data word
			//eaAddr+=1;//skip these bytes
		}
		else
		{
			//attempt to disassemble the next code

		//	eaLenOfGeneratedCode = ua_code(eaAddr);//ua_code is deprecatd
			eaLenOfGeneratedCode = create_insn(eaAddr);//create the disassembled code and return the length of it


			//msg("Code created at 0x%X\n", eaAddr);
			if(eaLenOfGeneratedCode == 0)
			{//guard against nothing happening
				eaLenOfGeneratedCode++;
			}
			if(iCount >= 0x200)
			{
				iCount=0;
				msg(".");
			}
			if(iReturns >= 0x4000)
			{
				iReturns=0;
				msg("\n");
			}
		}
	}
	msg("\n");

	msg("Looking through code to make subroutines....\n");
	//
	// Look for subroutines within the code
	//

	eaAddr = eaStartAddr;
	eaLenOfGeneratedCode = 1;
	iCount = iReturns = 1;

	// Instructions we know that subroutines don't start with.
	int instrs[] = { C166_jmps, C166_jmpr, C166_ret, C166_reti, C166_retp, C166_rets, C166_rol, C166_add, C166_shr, C166_xor, C166_xorb, 0 };
	char mnem[MAXSTR];
	const char *res;
	bool	bFound;

	for(eaAddr;eaAddr<eaEndAddr;)
	{
		//Create a function if possible but ignore certain instructions
		//because we know functions will not start with them
		bFound = 0;

		//Get the mnemonic at this address
		res = ua_mnem(eaAddr, mnem, sizeof(mnem)-1);
		// Check the mnemonic of this address against all
		// mnemonics we're interested in.
		for (int i = 0; instrs[i] != 0; i++)
		{
			if (cmd.itype == instrs[i])
			{
				bFound = 1;
			}
		}
		if(!bFound)
		{
			if(add_func(eaAddr, BADADDR))
			{
				msg("Function created at %x\n", eaAddr);
				func_t *func = get_func(eaAddr);
				if (func != NULL)
				{
					eaAddr += (func->endEA - func->startEA);
				}
				else
					eaAddr++;
			}
			else
				eaAddr++;
		}
		else
			eaAddr++;
	}
	return 1;
}

// Loops through the binary and searches for where DTC flags are being set.
bool BoschHelper::EnumDTCflags(ea_t eaStartAddr, ea_t eaEndAddr)
{
	msg("Searching for DTC setting flags from 0x%x through to 0x%x\n", eaStartAddr, eaEndAddr);

	// Instructions we know that DTC setting is done by.
	char mnem[MAXSTR];
	const char *res;
//	uval_t		uvalOp1Value, uvalOp2Value;

	ea_t	eaAddr;

	eaAddr = eaStartAddr;// sets the start

	for(eaAddr;eaAddr<eaEndAddr;)
	{
		// Get the flags for this address
		flags_t flags = getFlags(eaAddr);

		// Only look at the address if it's a head byte, i.e.
		// the start of an instruction and is code.
		if (isHead(flags) && isCode(flags))
		{
			//char mnem[MAXSTR];

			//Get the mnemonic at this address
			res = ua_mnem(eaAddr, mnem, sizeof(mnem)-1);
			// Check the mnemonic of this address against all
			// mnemonics we're interested in.

			if(cmd.itype == C166_bfldh)//We've found the instruction we're interested in.
			{
				msg("bfldh found at 0x%x\n", eaAddr);

				//we've found the instruction we're interested in.
				//get_operand_immvals(eaAddr, 1, &uvalOp1Value);
				//get_operand_immvals(eaAddr, 2, &uvalOp2Value);

				//msg("Instruction Len 0x%x : Op1 Value 0x%x : Op2 Value 0x%x\n", cmd.size, uvalOp1Value, uvalOp2Value);

				op_enum(eaAddr, 1, get_enum("DTCHBit"), NULL);

				eaAddr+= cmd.size;//next instruction
			}
			else if(cmd.itype == C166_bfldl)//We've found the instruction we're interested in.
			{
				msg("bfldl found at 0x%x\n", eaAddr);

				//we've found the instruction we're interested in.
				//get_operand_immvals(eaAddr, 1, &uvalOp1Value);
				//get_operand_immvals(eaAddr, 2, &uvalOp2Value);

				op_enum(eaAddr, 1, get_enum("DTCLBit"), NULL);

				eaAddr+= cmd.size;//next instruction
			}
			else
				eaAddr++;
		}
		else
			eaAddr++;
	}
	return 1;
}

// Sets the default register values on the C16x CPU
bool BoschHelper::SetC16xRegs(const char *szRegName, sel_t value)
{
	int		iReg;

	iReg = str2reg(szRegName);
	msg("Setting register %s, number %i to %x", szRegName, iReg, value);
	if(SetDefaultRegisterValue(NULL, iReg, value)) //SetDefaultRegisterValue is deprecated
		msg(" successful.\n");
	else
	{
		msg(" failed.\n");
		return 0;
	}
	return 1;
}

// Creates a Bosch segment and default registers
bool BoschHelper::CreateC16xSmallBoschSegments(ea_t eaStartAddr, ea_t eaEndAddr, char* cName, const char *sclass, sel_t dpp0, sel_t dpp1, sel_t dpp2, sel_t dpp3)
{
	char	cBuf[20];
	ea_t	eaParagraph;
//	CreateC16xSmallBoschSegments(0xf600, 0xfe00, "IRAM", "RAM", 0x0, 0x1, 0x2, 0x3);
	msg("\nBoschHelper::CreateC16xSmallBoschSegments Started\n");
//	msg("Deleting Segments\n");
	del_segm(eaStartAddr, SEGDEL_KEEP); //this deletes what is there.
	qsnprintf(cBuf, 17, "%s", cName);
	eaParagraph = eaStartAddr >> 4;// divide by 16
	msg("Creating segment at para %x, start address %x, end address %x, name %s, selector 0x%x\n", eaParagraph, eaStartAddr, eaEndAddr, cBuf, mSelector);
	set_selector(mSelector, eaParagraph);
//	set_selector(mSelector, 0);
	mSelector++;
	msg("Adding new segments\n");
//	line below sets the starting point for each segment at 0x0 and you cant type goto 0xfd16 for example :(
//  it might be corrct but it just isnt useful for me
//	add_segm(eaParagraph, eaStartAddr, eaEndAddr, cBuf, sclass);
	add_segm(0, eaStartAddr, eaEndAddr, cBuf, sclass);


	//Set the default register values for this segment
	msg("Setting DPPs\n");
	SetC16xRegs("dpp0", dpp0);
	SetC16xRegs("dpp1", dpp1);
	SetC16xRegs("dpp2", dpp2);
	SetC16xRegs("dpp3", dpp3);
	msg("BoschHelper::CreateC16xSmallBoschSegments Finished\n");
	return 1;
}

// Creates the correct Bosch segments and default registers
bool BoschHelper::CreateC16xBoschSegments(ea_t eaParagraph, unsigned int iNumSegsToCreate, const char *sclass, sel_t dpp0, sel_t dpp1, sel_t dpp2, sel_t dpp3)
{
	sel_t	selSelector = 0;
	ea_t	eaStartAddr, eaEndAddr;
	int		iDPPNum;
	char	cBuf[20];

	msg("\nBoschHelper::CreateC16xBoschSegments Started\n");
	for(selSelector; selSelector<iNumSegsToCreate; selSelector++)
	{
		eaStartAddr = (eaParagraph * 0x10) + (selSelector * 0x4000);
		//eaEndAddr = eaStartAddr + 0x4000; // makes small 1 page segments
		eaEndAddr = eaStartAddr + 0x10000;  // makes big 4 page segements
		iDPPNum = eaStartAddr / 0x4000;//gets the dpp equivalent for the segment label
//		24 bit address.  
		del_segm(eaStartAddr, SEGDEL_KEEP); //this deletes what is there.

	//	qsnprintf(cBuf, 17, "Seg0x%x@%x", iDPPNum, eaStartAddr); //prepends segment and start address
	//	qsnprintf(cBuf, 17, "Seg0x%x", iDPPNum); //prepends segment only
		qsnprintf(cBuf, 4, "ROM"); //prepends nothing, max data on screen
		msg("Creating segment at para %x, start address %x, end address %x, name %s, selector 0x%x\n", eaParagraph, eaStartAddr, eaEndAddr, cBuf, mSelector);
	
	
		set_selector(mSelector, eaParagraph);
	//	set_selector(mSelector, 0);
		mSelector++;

//		putting the paragraph in is correct but it means I can't type absolute addresses
		add_segm(0, eaStartAddr, eaEndAddr, cBuf, sclass);
	//	add_segm(eaParagraph, eaStartAddr, eaEndAddr, cBuf, sclass); // puts paragraphs in
		
		
		//Set the default register values for this segment
		msg("Setting DPPs\n");
		SetC16xRegs("dpp0", dpp0);
		SetC16xRegs("dpp1", dpp1);
		SetC16xRegs("dpp2", dpp2);
		SetC16xRegs("dpp3", dpp3);
	}
	msg("BoschHelper::CreateC16xBoschSegments Finished\n");
	return 1;
}

// Loops through the binary and tries to make code offsets from arrays
// e.g. movb    [r5+0E0A4h], rl4 = movb    [r5+word_E0A4], rl4
bool BoschHelper::FindAndCreateArrayOffsets(ea_t eaStartAddr, ea_t eaEndAddr)
{
	msg("Finding array offsets and trying to create them from 0x%x through to 0x%x\n", eaStartAddr, eaEndAddr);

	ea_t	eaAddr, eaLenOfGeneratedCode;
	int		iCount, iReturns;

	//
	// Look for known function that will contain offsets within the code
	//

	eaAddr = eaStartAddr;
	eaLenOfGeneratedCode = 1;
	iCount = iReturns = 1;

	// Instructions we know that contain arrays.
	int instrs[] = { C166_mov, C166_movb, 0 };
	char mnem[MAXSTR];
	const char *res;
	bool	bFound;

	for(eaAddr;eaAddr<eaEndAddr;)
	{
		//Find instructions we know will have offsets in them
		bFound = 0;

		//Get the flags for this address
		flags_t flags = getFlags(eaAddr);

		//Only look at the address if it's a head byte
		//i.e. the start of an instruction and its code
		if(isHead(flags) && isCode(flags))
		{
			//Get the mnemonic at this address
			res = ua_mnem(eaAddr, mnem, sizeof(mnem)-1);
			// Check the mnemonic of this address against all
			// mnemonics we're interested in.
			for (int i = 0; instrs[i] != 0; i++)
			{
				if (cmd.itype == instrs[i])
				{
					bFound = 1;
				}
			}
			//We have an instruction we're interested in
			if(bFound)
			{
				//check the type of mnemonic.
/*				msg("Instruction mnemonic at 0x%x :->\n", eaAddr);
				msg("    Op0: n = %d type = %d reg = %d value = %a addr = %a\n",
					cmd.Operands[0].n,
					cmd.Operands[0].type,
					cmd.Operands[0].reg,
					cmd.Operands[0].value,
					cmd.Operands[0].addr);
				msg("    Op1: n = %d type = %d reg = %d value = %a addr = %a\n",
					cmd.Operands[1].n,
					cmd.Operands[1].type,
					cmd.Operands[1].reg,
					cmd.Operands[1].value,
					cmd.Operands[1].addr);
*/				
				// Is the instruction Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr?
				// If so, then these need converting into offset addresses
				if(cmd.Operands[0].type == o_displ)
				{
					//r0 is a special register and should not be offsetted
					if(cmd.Operands[0].reg!= 0)
						if(cmd.Operands[0].addr >= 0x00ff)
							MakeC166Offset(eaAddr, 0);
				}
				else if(cmd.Operands[1].type == o_displ)
				{
					//r0 is a special register and should not be offsetted
					if(cmd.Operands[1].reg!= 0)
						if(cmd.Operands[1].addr >= 0x00ff)
							MakeC166Offset(eaAddr, 1);
				}
			}
		}
		eaAddr++;
	}
	return 1;
}

//Makes C166 offsets utilising the correct DPP value
// eaAddr = Address of the instruction
// nOp = Operand Number
void BoschHelper::MakeC166Offset(ea_t eaAddr, int nOp)
{
	//Translate the address we get into a real address
	int		iReg;
	ea_t	eaDpp;
	sel_t	selSelector;
					
	//Find out what DPP the address we've found lives in.
	//The DPP selector is the top two bits
	eaDpp = (cmd.Operands[1].addr & 0xc000) >> 14;
	if(eaDpp == 0)
	{
		iReg = str2reg("DPP0");
	}
	else if (eaDpp==1)
	{
		iReg = str2reg("DPP1");
	}
	else if (eaDpp==2)
	{
		iReg = str2reg("DPP2");
	}
	else
	{
		iReg = str2reg("DPP3");
	}
	//Get the value of the selected register
	//Don't ask me why but the register needs to be multiplied by 16 to become the base
	
	selSelector = getSR(eaAddr, iReg) << 4; //deprecated, need to replace. getSR returns 0x204, 0x205 or 0xe0  ie the DPPs.
	msg("selSelector = 0x%x \n", selSelector >> 4);


	ea_t eaOffsetBase = get_offbase(eaAddr, nOp);//For information, not used
	msg("**** At address 0x%x DPP number 0x%x for Register 0x%x, is 0x%x. Op is 0x%x. Offset base is 0x%x\n", eaAddr, eaDpp, iReg, selSelector, nOp, eaOffsetBase);

	//Create the offset
	if(op_offset(eaAddr, nOp, REF_OFF16, BADADDR, selSelector) == 0)
	{
		msg("op_offset failed\n");
	}
}

// Loops through the binary and tries to make code offsets from implicit references
// e.g. movb    [r5+0E0A4h], rl4 = movb    [r5+word_E0A4], rl4
//mov     r4, #0F9F6h     ; Move Word <- Here's the address
//mov     r5, #0          ; Move Word <- Here's the segment
//movbz   r2, rl6         ; Move Byte Zero Extend
//shl     r2, #1          ; Shift Left
//mov     r3, #0          ; Move Word
//add     r4, r2          ; Integer Addition
//addc    r5, r3          ; Integer Addition with Carry
//exts    r5, #1          ; Begin Extended Segment Sequence <- This requires a segment
//mov     r12, [r4]       ; Move Word with phrase <- This requires an address
bool BoschHelper::FindAndCreateImplicitOffsets(ea_t eaStartAddr, ea_t eaEndAddr)
{
	msg("Finding implicit offsets and trying to create them from 0x%x through to 0x%x\n", eaStartAddr, eaEndAddr);

	ea_t	eaAddr, eaLenOfGeneratedCode;
	int		iCount, iReturns;

	//
	// Look for known function that will contain offsets within the code
	//

	eaAddr = eaStartAddr;
	eaLenOfGeneratedCode = 1;
	iCount = iReturns = 1;

	// Instructions we know that contain addresses.
	int instrs[] = { C166_mov, 0 };
	char mnem[MAXSTR];
	const char *res;
	bool	bFound;

	for(eaAddr;eaAddr<eaEndAddr;)
	{
		//Find instructions we know will have offsets in them
		bFound = 0;

		//Get the flags for this address
		flags_t flags = getFlags(eaAddr);

		//Only look at the address if it's a head byte
		//i.e. the start of an instruction and its code
		if(isHead(flags) && isCode(flags))
		{
			//Get the mnemonic at this address
			res = ua_mnem(eaAddr, mnem, sizeof(mnem)-1);
			// Check the mnemonic of this address against all
			// mnemonics we're interested in.
			for (int i = 0; instrs[i] != 0; i++)
			{
				if (cmd.itype == instrs[i])
				{
					bFound = 1;
				}
			}
			//We have an instruction we're interested in
			if(bFound)
			{
				//check the type of mnemonic.
				msg("Instruction mnemonic at 0x%x :->\n", eaAddr);
				msg("    Op0: n = %d type = %d reg = %d value = %a addr = %a\n",
					cmd.Operands[0].n,
					cmd.Operands[0].type,
					cmd.Operands[0].reg,
					cmd.Operands[0].value,
					cmd.Operands[0].addr);
				msg("    Op1: n = %d type = %d reg = %d value = %a addr = %a\n",
					cmd.Operands[1].n,
					cmd.Operands[1].type,
					cmd.Operands[1].reg,
					cmd.Operands[1].value,
					cmd.Operands[1].addr);
				
				// Is the instruction a Memory Ref [Base Reg + Index Reg] and not r0?
				// If so, then we need to back track and see when it's loaded with an immediate
				// Need to do this for cmd.Operands[0] and cmd.Operands[1]
				// Also backtrack one instruction and see if there's a "exts"
				if((cmd.Operands[1].type == o_phrase) & (cmd.Operands[1].reg != 0))
				{
					msg("We're at a phrase and need to look for where r%a was immediate loaded.\n", cmd.Operands[1].reg);
					// We need to backtrack & find where this register was loaded immediate at op1

					//r0 is a special register and should not be offsetted
//					if(cmd.Operands[1].reg!= 0)
//						if(cmd.Operands[1].addr >= 0x00ff)
//							MakeC166Offset(eaAddr, 1);
				}
			}
		}
		eaAddr++;
	}
	return 1;
}

//////////////////////////////////////////////////////////////////////
// Implementation
//////////////////////////////////////////////////////////////////////

//Automatically disassembles the code and tries to make subroutines
void BoschHelper::MakeDissCode()
{
	CreateInterruptVectorTable();
	// might need some detection in here. 
	//CreateDissCode(0x00000, 0x1ff);
	//CreateDissCode(0x700, 0x7fff);
	//CreateDissCode(0x800000, 0x800200);	
	//gap 0x800200 to 0x800700 is jump tables
	CreateDissCode(0x800700, 0x808000);
	//gap 0x808000 to xxx is jump tables
	CreateDissCode (0x808500, 0x810000);

	CreateDissCode(0x820000, 0x826A00); // gap at 0x826a00 might not be universal.
	CreateDissCode(0x830000, 0x8fff00);
}


//Makes the segments of the disassembly
void BoschHelper::MakeSegments()
{
	msg("Entering BoschHelper::MakeSegments()\n");
	//bool BoschHelper::CreateC16xSmallBoschSegments(ea_t eaStartAddr, ea_t eaEndAddr, char* cName, const char *sclass, sel_t dpp0, sel_t dpp1, sel_t dpp2, sel_t dpp3)
	//CreateC16xSmallBoschSegments(0x0000, 0x8000, "MEM_EXT", "CODE", 0x0, 0x1, 0x2, 0x3); // should be a memory mapping not a real segment
	//SFR
	CreateC16xSmallBoschSegments(0x8000, 0xE000, "MEM_EXT", "CODE", 0x0, 0x1, 0x2, 0x3);
	CreateC16xSmallBoschSegments(0xE000, 0xE800, "XRAM", "DATA", 0x0, 0x1, 0x2, 0x3);
	CreateC16xSmallBoschSegments(0xE800, 0xEf00, "RESERVED", "BSS", 0x0, 0x1, 0x2, 0x3);
	CreateC16xSmallBoschSegments(0xEf00, 0xf000, "CAN1", "DATA", 0x0, 0x1, 0x2, 0x3);
	CreateC16xSmallBoschSegments(0xf000, 0xf200, "E_SFR", "DATA", 0x0, 0x1, 0x2, 0x3);
	CreateC16xSmallBoschSegments(0xf200, 0xf600, "RESERVED", "BSS", 0x0, 0x1, 0x2, 0x3);
	CreateC16xSmallBoschSegments(0xf600, 0xfe00, "IRAM", "RAM", 0x0, 0x1, 0x2, 0x3);
	CreateC16xSmallBoschSegments(0xfe00, 0x10000, "SFR", "DATA", 0x0, 0x1, 0x2, 0x3);
	
	//RAM
	CreateC16xSmallBoschSegments(0x380000, 0x384000, "RAM", "DATA", 0x0, 0x1, 0x2, 0x3);
	CreateC16xSmallBoschSegments(0x384000, 0x388000, "RAM", "DATA", 0x0, 0x1, 0x2, 0x3);
//	CreateC16xBoschSegments(0x38000, 2, "MEM_EXT" , 0x204, 0x205, 0xe0, 3);
	//ROM

	//number of segments to create is inf.maxEA / 0x10000
uint x =0;
for(x; x<(inf.maxEA-0x800000)/0x10000;x++) // inf.maxEA-0x800000)/0x10000 is how many 0x10000 byte segments needed before MaxEX
	{
		CreateC16xBoschSegments((0x80000+(x*0x1000)), 1, "CODE", 0x204, 0x205, 0xe0, 3);
	}


//now lets clear the mess out of the maps area
//idaman void ida_export do_unknown_range	(	ea_t 	ea, size_t 	size, int 	flags )	

do_unknown_range (0x808000, 0x7fff, 0x0000);
do_unknown_range (0x810000, 0x10000, 0x0000);

}



//Looks for signatures of commonly known functions and set their name.
//Test routine!
//void BoschHelper::SearchForFuncSigs(BOOL bNewME711)
//{
//	//No longer used
//	const uchar	test[]={0xfa, 0x82, 0xd8, 0x00, 0xfa, 0xff, 0xDC, 0x00};
//	ea_t	eaFound;
//
//	eaFound = FindBinaryWithDontCare((uchar*)test, 8, 0x800000, 0x80ffff);
//	if(eaFound != BADADDR)
//		msg("Found Sig at 0x%x\n", eaFound);
//	else
//		msg("Sig not found\n");
//}

//Looks for Bosch DTC setting fields.
void BoschHelper::SearchForDTCFlagSetting()
{
	//Create the enum constants first
	enum_t	enumtID;

	//The DTC enum for low bits
	enumtID = add_enum(BADADDR, "DTCLBit", 0x1100000);//Create the enum
	set_enum_bf(enumtID, 1);//Set the enum to a bitfield
	//Now fill the enum structure
	add_enum_member(enumtID,"DTCBit_L0",	0x1,	0x1);
	add_enum_member(enumtID,"DTCBit_L1",	0x2,	0x2);
	add_enum_member(enumtID,"DTCBit_L2",	0x4,	0x4);
	add_enum_member(enumtID,"DTCBit_L3",	0x8,	0x8);
	add_enum_member(enumtID,"DTCBit_L4",	0x10,	0x10);
	add_enum_member(enumtID,"DTCBit_L5",	0x20,	0x20);
	add_enum_member(enumtID,"DTCBit_L6",	0x40,	0x40);
	add_enum_member(enumtID,"DTCBit_L7",	0x80,	0x80);

	//The DTC enum for high bits
	enumtID = add_enum(BADADDR, "DTCHBit", 0x1100000);//Create the enum
	set_enum_bf(enumtID, 1);//Set the enum to a bitfield
	//Now fill the enum structure
	add_enum_member(enumtID,"DTCFieldA_H0",	0x1,	0x1);
	//set_enum_cmt(get_const(enumtID, 0x1, NULL, 0x1),"Select DTC Group A",1);  //deprecated
	set_enum_cmt(get_enum_idx(enumtID),"Select DTC Group A",1);
	add_enum_member(enumtID,"DTCFieldB_H1",	0x2,	0x2);
//	set_enum_cmt(get_const(enumtID, 0x2, NULL, 0x2),"Select DTC Group B",1); //deprecated
	set_enum_cmt(get_enum_idx(enumtID),"Select DTC Group B",1);
	add_enum_member(enumtID,"DTCFieldC_H2",	0x4,	0x4);
//	set_enum_cmt(get_const(enumtID, 0x4, NULL, 0x4),"Select DTC Group C",1);//deprecated
	set_enum_cmt(get_enum_idx(enumtID),"Select DTC Group C",1);
	add_enum_member(enumtID,"DTCFieldD_H3",	0x8,	0x8);
//	set_enum_cmt(get_const(enumtID, 0x8, NULL, 0x8),"Select DTC Group D",1);//deprecated
	set_enum_cmt(get_enum_idx(enumtID),"Select DTC Group D",1); 
	add_enum_member(enumtID,"DTCBit_H4",	0x10,	0x10);
	add_enum_member(enumtID,"DTCBit_H5",	0x20,	0x20);
	add_enum_member(enumtID,"DTCBit_H6",	0x40,	0x40);
	add_enum_member(enumtID,"DTCBit_H7",	0x80,	0x80);

	//Search the disassembly for enum flag setting
		EnumDTCflags(0x820000, 0x8ff000);
	
}

//Looks for specific binary patterns and then makes a subroutine and comments it
void BoschHelper::SearchForFuncSigsAndThenCmt()
{
		msg("Searching for function signatures\n");
		functionsigsclass.FindFuncSigsAndComment(0x0, 0xffffff);
}

//Looks for instructions that will probably contain an offset. When found it creates them.
void BoschHelper::SearchForArrayOffsetsAndThenCreate()
{
	FindAndCreateArrayOffsets(0x0, 0x8fffff);
//	FindAndCreateImplicitOffsets(0x8694b4, 0x8694ce);
}

// load an ASAP file, parse it and apply debug data to database.
void BoschHelper::loadASAPfile()
{
	msg("Entering BoschHelper::loadASAPfile()\n");

// get the a2l file from the user.
	char * ASAPfileToLoad;
	ASAPfileToLoad =  askfile2_c(false, NULL, "*.a2l|ASAP2 file\n", "Import ASAP data. Select ASAP2 file\n");
	//check if NULL returned
	if (ASAPfileToLoad)
		//&& ASAPfileToLoad[0] == '\0')
		{
		msg("User selected ASAP2 file: %s\n",ASAPfileToLoad);
		}
	else
		{
		msg("User cancelled./n");
		return;	
		}

	FILE * pASAPfile;
	pASAPfile = qfopen (ASAPfileToLoad,"r");
	if (pASAPfile!=NULL) //is it open or do we have a NULL pointer?
	{
    // read the ASAP file in here.
		char line[MAXSTR];

	//	char searchWord[MAXSTR];
		while	 (qfgets(line, MAXSTR, pASAPfile)!=NULL){
			 // if line contains "CHARACTERISTIC" then it contains something we're interested in
				/*
				/begin CHARACTERISTIC

				 A0
				"‹bertragungsfunktionskoeffizient"
				VALUE
				0x816250
				KwSw
				0.1249981
				fak_sw_b0p0625
				-0.06250000
				0.06249809

				FORMAT "%10.8"
    
				/begin IF_DATA ETK  DP_BLOB 0x816250  0x2  /end IF_DATA
				/end CHARACTERISTIC
/begin MEASUREMENT

    abak
    "Aufteilungsfaktor Wandfilm bei BA"
    UBYTE
    fak_ub_b1
    1
    100
    0
    0.996094

    
    FORMAT "%6.4"
    
    ECU_ADDRESS 0x38488E
    /begin IF_DATA ASAP1B_ADDRESS  KP_BLOB 0x38488E /end IF_DATA
    /begin IF_DATA ETK  KP_BLOB 0x38488E 0x1 0x1 /end IF_DATA
/end MEASUREMENT

				*/

			
			ea_t eaAddress;
			char* searchWord = "begin CHARACTERISTIC";
			char const *searchWord2 ="begin MEASUREMENT";
			if(qstrstr(line, searchWord) || qstrstr(line, searchWord2)  != NULL) 
				{
				bool isBitMask = false;
				ea_t bitMask = 0x0;
				qfgets(line, MAXSTR, pASAPfile);
				while (qstrlen(line)<=1) // /0 terminated string
					{
						qfgets(line, MAXSTR, pASAPfile); //read blank line(s), asap file has blank line after /begin CHARACTERISTIC
					}
				//msg (line); // line has the name of the CHARACTERISTIC
				char characteristicName[MAXSTR];
				char characteristicComment[MAXSTR];
				char tempString[MAXSTR];
				strip_whitespace(characteristicName,line,1024);
				qfgets(line, MAXSTR, pASAPfile);
				
				//find start and end of string inside line
				
				size_t i = 0;
				int startPos = 0;
				int endPos = 0;
				
				for (0; i<qstrlen(line); i++) // find first " in the line
				{
					char myChar =  line[i];
					if  (myChar == 34) //ascii 34 is "
					{	
						line[i] = ' ';
						startPos = i;
						break; //exit loop
					}	
				}
				i=qstrlen(line);
				for (i;i>0; i--) // find last " in the line
				{
					char myChar =  line[i];
					if  (myChar == 34) //ascii 34 is "
					{
						endPos = i+1;
						break; //exit loop
					}	
				}
				qstrncpy(tempString,line,endPos); // create string without trailing spaces. contains leading whitespace. 
				strip_leading_whitespace(characteristicComment, tempString);
				
// now we're looking for the address
				
				char* searchWord = "0x";
				while (qstrstr(line, searchWord) == NULL)
					{
					qfgets(line, MAXSTR, pASAPfile);// read a line
					}
				//line has 0x in it. line is a pointer
				char  * pAddress = line;
				char const * name = characteristicName;
				strip_whitespace(pAddress, line, 1024); 

				//need to turn pAddress from pointer to string to ea_t
				// pAddress might contain "ECU_ADDRESS 0xXXXXXX"
				// or just "0xXXXXXX"
				char *finalAddress= pAddress;
				if(qstrstr(pAddress,"ECU_ADDRESS")  != NULL)
				{
					// we need to lose the "ECU_ADDRESS" part, so chop off the first 11 chars
				size_t f=11;
				size_t j=0;
					for(f; f<	qstrlen(pAddress);f++)
					{		
						
							finalAddress[j]=pAddress[f];
							j++;
					}	
					finalAddress[j]=0; //terminate it
				}

				
				eaAddress = (uint32)strtol(finalAddress, NULL, 0); //strtol copes with text in front of the number.
			//	msg("**************************************address was 0x%x, name was %s, start text %s\n", eaAddress, name, pAddress);
				
				// now we need to read until we hit "end".


			char const *searchWord3 ="end";

			while(qstrstr(line, searchWord)  == NULL)  // qstrstr returns NULL on no match
			qfgets(line, MAXSTR, pASAPfile);// read a line
			{
				
			
				if(qstrstr(line, "BIT_MASK")  != NULL)  // look in every line in case we find out were talking about an enum
					{
					
					isBitMask=true;
					// pAddress contains something like BIT_MASK0x2, need to chop 8 chars
					size_t h=8;
					size_t i=0;
					char * cBitMask=pAddress; 
					for(h; h<	qstrlen(pAddress);h++)
					{		
						
							cBitMask[i]=pAddress[h];
							i++;
					}	
					cBitMask[i]=0; //terminate it
				
			
					bitMask = (uint32)strtol(cBitMask, NULL, 0);
	
					//our 0x search term found the bit mask not the ecu_address line, but we've stored that so now find the address
					qfgets(line, MAXSTR, pASAPfile);// read a line until we find the ecu address
					qfgets(line, MAXSTR, pASAPfile);// read a line until we find the ecu address
					qfgets(line, MAXSTR, pASAPfile);// read a line until we find the ecu address, its in here 
					char *bitfieldaddress =line;
					strip_whitespace(bitfieldaddress, line, 1024);
					
					size_t f=11;
					size_t j=0;
					char *finalAddress = bitfieldaddress;
					for(f; f<	qstrlen(bitfieldaddress);f++)
						{		
							finalAddress[j]=bitfieldaddress[f];
							j++;
						}	
					finalAddress[j]=0; //terminate it
					eaAddress = (uint32)strtol(finalAddress, NULL, 0);
					}
			}
			
				
				if (isBitMask == false)
					{
					bool clear = do_data_ex(eaAddress, 1, 1,NULL);
					int result = set_name(eaAddress, name);
					
					if (result==0)
						{
						msg("setting object %s at 0x%x failed\n",name, eaAddress);
						}
					else
						{
							msg("created object %s at direct address: 0x%x\n", name, eaAddress);
						}

					/*size_t fi=97;
							for (fi;fi<255;fi++)
						{
							msg(" %d %c",fi,fi);
						}
					msg("\n");
					*/
					
				
				result = set_cmt(eaAddress, patchASCII(characteristicComment), true);
				}
				else
				{
			//		msg("ASAP object %s was part of a bitfield.mask 0x%x, eaAddress 0x%x  ASAP to ENUM functionality not yet implemented. Poor.\n", name, bitMask, eaAddress);
					// deal with enums now 

				/*	enumtID = add_enum(BADADDR, "DTCLBit", 0x1100000);//Create the enum
	set_enum_bf(enumtID, 1);//Set the enum to a bitfield
	//Now fill the enum structure
	add_enum_member(enumtID,"DTCBit_L0",	0x1,	0x1);
	add_enum_member(enumtID,"DTCBit_L1",	0x2,	0x2);
	add_enum_member(enumtID,"DTCBit_L2",	0x4,	0x4);
	add_enum_member(enumtID,"DTCBit_L3",	0x8,	0x8);
	add_enum_member(enumtID,"DTCBit_L4",	0x10,	0x10);
	add_enum_member(enumtID,"DTCBit_L5",	0x20,	0x20);
	add_enum_member(enumtID,"DTCBit_L6",	0x40,	0x40);
	add_enum_member(enumtID,"DTCBit_L7",	0x80,	0x80);
*/
					enum_t	enumID;
					char temp[14]="";
					qstrncpy(temp,"enum_",14);
					qstrncat(temp, finalAddress,14);
					enumID = get_enum(temp);
					if (get_enum(temp)== 0xffffffff)
					{
						// need to create the enum
						enumID = add_enum(BADADDR, temp, 0x1100000); //BADADDR selects last eaAddress
						msg("Creating enum: %s which is enumID 0x%x\n", temp, enumID);
						set_enum_bf(enumID, 1);
						op_enum(eaAddress, 0, enumID, 0);



					}
					else
					{
						enumID = get_enum(temp);
					}
				
					//add the bitfield
					add_enum_member(enumID,name,	bitMask,	bitMask);
					bmask_t mask = bitMask;
				/*	char const * cmt = "fishpuke";
					if (set_bmask_cmt(enumID, 2, characteristicComment, false)==false)
					{
						msg("setting bitmask comment failed.  %x %x %s\n\n", enumID, 0, characteristicComment)	;
					}
*/
					set_enum_cmt(get_const(enumID, mask, NULL, mask),patchASCII(characteristicComment),1); 

					//set_const_cmt(enumID, "fishpuke",true);
						//SetConstCmt(GetConst(id,0x1,0x1), "LREB: Bedingung Lambdaregelung (vor Kat); (Bank 1)",1);

					//get_enum_idx(enumtID)
				}

			}

		}

		

    qfclose (pASAPfile); // clean up.
	return;
	}
}
