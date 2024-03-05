/*########################################################################################################*/
// cd /nfs/iil/ptl/bt/ghaber1/pin/pin-2.10-45467-gcc.3.4.6-ia32_intel64-linux/source/tools/SimpleExamples
// make
//  ../../../pin -t obj-intel64/rtn-translation.so -- ~/workdir/tst
/*########################################################################################################*/
/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2011 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
/* ===================================================================== */

/* ===================================================================== */
/*! @file
 * This probe pintool generates translated code of routines, places them in an allocated TC 
 * and patches the orginal code to jump to the translated routines.
 */

#include "pin.H"
extern "C" {
#include "xed-interface.h"
}
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <values.h>
#include <set>


using namespace std;

/*======================================================================*/
/* commandline switches                                                 */
/*======================================================================*/
KNOB<BOOL>   KnobVerbose(KNOB_MODE_WRITEONCE, "pintool",
    "verbose", "0", "Verbose run");

KNOB<BOOL>   KnobDumpTranslatedCode(KNOB_MODE_WRITEONCE, "pintool",
    "dump_tc", "0", "Dump Translated Code");

KNOB<BOOL>   KnobDoNotCommitTranslatedCode(KNOB_MODE_WRITEONCE, "pintool",
    "no_tc_commit", "0", "Do not commit translated code");

KNOB<BOOL>   KnobInst(KNOB_MODE_WRITEONCE, "pintool",
	"opt", "0", "Probe mode");
KNOB<BOOL>   KnobProf(KNOB_MODE_WRITEONCE, "pintool",
	"prof", "0", "JIT mode");
	
	
KNOB <BOOL> KnobDebug(KNOB_MODE_WRITEONCE, "pintool", "debug", "0",
                      "Add debug prints");	
	

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

std::ofstream* out = 0;

// For XED:
#if defined(TARGET_IA32E)
    xed_state_t dstate = {XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b};
#else
    xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b};
#endif

//For XED: Pass in the proper length: 15 is the max. But if you do not want to
//cross pages, you can pass less than 15 bytes, of course, the
//instruction might not decode if not enough bytes are provided.
const unsigned int max_inst_len = XED_MAX_INSTRUCTION_BYTES;

ADDRINT lowest_sec_addr = 0;
ADDRINT highest_sec_addr = 0;

#define MAX_PROBE_JUMP_INSTR_BYTES  14

// tc containing the new code:
char *tc;	
int tc_cursor = 0;

// instruction map with an entry for each new instruction:
typedef struct { 
	ADDRINT orig_ins_addr;
	ADDRINT new_ins_addr;
	ADDRINT orig_targ_addr;
	bool hasNewTargAddr;
	char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
	xed_category_enum_t category_enum;
	unsigned int size;
	int targ_map_entry;
//	UINT64 inline_count;
} instr_map_t;


instr_map_t *instr_map = NULL;
int num_of_instr_map_entries = 0;
int max_ins_count = 0;







// total number of routines in the main executable module:
int max_rtn_count = 0;

// Tables of all candidate routines to be translated:
typedef struct { 
	ADDRINT rtn_addr; 
	USIZE rtn_size;
	int instr_map_entry;   // negative instr_map_entry means routine does not have a translation.
	bool isSafeForReplacedProbe;	
} translated_rtn_t;

translated_rtn_t *translated_rtn;
int translated_rtn_num = 0;

/*Project*/
const ADDRINT NO_DOMINATE_CALL = (ADDRINT)0, NO_DIRECT_CONTROL_FLOW = (ADDRINT)0;


class xed_ins_to_translate {
public:
	ADDRINT addr;
	USIZE size;
	ADDRINT target_addr;
	xed_decoded_inst_t data;
	xed_category_enum_t category_enum;
	xed_ins_to_translate() : addr((ADDRINT)0), size(0), target_addr((ADDRINT)0) {
		xed_decoded_inst_zero_set_mode(&(data), &dstate);
	}
	xed_ins_to_translate(ADDRINT new_addr, USIZE new_size, xed_error_enum_t& xed_code) : addr(new_addr), size(new_size) {
		target_addr = (ADDRINT)0;
		xed_decoded_inst_zero_set_mode(&data, &dstate);
		xed_code = xed_decode(&data, reinterpret_cast<UINT8*>(addr), max_inst_len);
		if (xed_code == XED_ERROR_NONE) {
			category_enum = xed_decoded_inst_get_category(&data);
			if (xed_decoded_inst_get_branch_displacement_width(&data) > 0) { // there is a branch offset.
				target_addr = new_addr + xed_decoded_inst_get_length(&data) + xed_decoded_inst_get_branch_displacement(&data);
			}
		}
	}
	/* unconditonal jump decoded constructor: 
		The user must check output parameters and category_enum, before usage.
	*/
	xed_ins_to_translate(ADDRINT new_orig_addr, ADDRINT new_orig_target, xed_bool_t& convert_ok,
		xed_error_enum_t& xed_code) {
		xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
		xed_int32_t disp = (xed_int32_t)(new_orig_target - new_orig_addr);
		xed_encoder_instruction_t  enc_instr;

		xed_inst1(&enc_instr, dstate,
			XED_ICLASS_JMP, 64,
			xed_relbr(disp, 32));

		xed_encoder_request_t enc_req;

		xed_encoder_request_zero_set_mode(&enc_req, &dstate);
		convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
		if (convert_ok) {
			unsigned int new_size = 0;
			xed_code = xed_encode(&enc_req, enc_buf, max_inst_len, &new_size);
			if (xed_code == XED_ERROR_NONE) {
				xed_ins_to_translate* result = new xed_ins_to_translate();
				xed_code = xed_decode(&(result->data), enc_buf, max_inst_len);
				if (xed_code == XED_ERROR_NONE) {
					data = result->data;
					addr = new_orig_addr;
					size = xed_decoded_inst_get_length(&data);
					target_addr = new_orig_target;
					xed_category_enum_t test_category = xed_decoded_inst_get_category(&data);
					category_enum = (test_category == XED_CATEGORY_UNCOND_BR) ? test_category : XED_CATEGORY_INVALID;
				}
				else {
					cerr << "JUMP: Failed to decode." << endl;
				}
				delete result;
			}
			else {
				cerr << "JUMP: Failed to encode." << endl;
			}
		}
	}
	xed_ins_to_translate(const xed_ins_to_translate& obj) : addr(obj.addr), size(obj.size), target_addr(obj.target_addr),
		data(obj.data), category_enum(obj.category_enum) {}
	xed_ins_to_translate& operator= (const xed_ins_to_translate& obj) {
		if (this == &obj) {
			return *this;
		}
		addr = obj.addr;
		size = obj.size;
		target_addr = obj.target_addr;
		data = obj.data;
		category_enum = obj.category_enum;
		return *this;
	}
	bool revert_cond_jump(xed_error_enum_t& xed_code) {
		if (this->category_enum != XED_CATEGORY_COND_BR) {
			xed_code = XED_ERROR_NONE;
			return false;
		}

		xed_decoded_inst_t xed_to_revert = this->data;
		xed_iclass_enum_t iclass_enum = xed_decoded_inst_get_iclass(&xed_to_revert);
		if (iclass_enum == XED_ICLASS_JRCXZ) {
			xed_code = XED_ERROR_NONE;
			return false;    // do not revert JRCXZ
		}
		xed_iclass_enum_t 	retverted_iclass;
		switch (iclass_enum) {

		case XED_ICLASS_JB:
			retverted_iclass = XED_ICLASS_JNB;
			break;

		case XED_ICLASS_JBE:
			retverted_iclass = XED_ICLASS_JNBE;
			break;

		case XED_ICLASS_JL:
			retverted_iclass = XED_ICLASS_JNL;
			break;

		case XED_ICLASS_JLE:
			retverted_iclass = XED_ICLASS_JNLE;
			break;

		case XED_ICLASS_JNB:
			retverted_iclass = XED_ICLASS_JB;
			break;

		case XED_ICLASS_JNBE:
			retverted_iclass = XED_ICLASS_JBE;
			break;

		case XED_ICLASS_JNL:
			retverted_iclass = XED_ICLASS_JL;
			break;

		case XED_ICLASS_JNLE:
			retverted_iclass = XED_ICLASS_JLE;
			break;

		case XED_ICLASS_JNO:
			retverted_iclass = XED_ICLASS_JO;
			break;

		case XED_ICLASS_JNP:
			retverted_iclass = XED_ICLASS_JP;
			break;

		case XED_ICLASS_JNS:
			retverted_iclass = XED_ICLASS_JS;
			break;

		case XED_ICLASS_JNZ:
			retverted_iclass = XED_ICLASS_JZ;
			break;

		case XED_ICLASS_JO:
			retverted_iclass = XED_ICLASS_JNO;
			break;

		case XED_ICLASS_JP:
			retverted_iclass = XED_ICLASS_JNP;
			break;

		case XED_ICLASS_JS:
			retverted_iclass = XED_ICLASS_JNS;
			break;

		case XED_ICLASS_JZ:
			retverted_iclass = XED_ICLASS_JNZ;
			break;

		default:
			xed_code = XED_ERROR_NONE;
			return false;
		}

		// Converts the decoder request to a valid encoder request:
		xed_encoder_request_init_from_decode(&xed_to_revert);

		// set the reverted opcode;
		xed_encoder_request_set_iclass(&xed_to_revert, retverted_iclass);

		xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
		unsigned int new_size = 0;

		xed_error_enum_t xed_error = xed_encode(&xed_to_revert, enc_buf, max_inst_len, &new_size);
		if (xed_error != XED_ERROR_NONE) {
			xed_code = xed_error;
			return false;
		}
		xed_decoded_inst_t new_xedd;
		xed_decoded_inst_zero_set_mode(&new_xedd, &dstate);

		xed_error = xed_decode(&new_xedd, enc_buf, max_inst_len);
		if (xed_error != XED_ERROR_NONE) {
			xed_code = xed_error;
			return false;
		}
		xed_decoded_inst_zero_set_mode(&this->data, &dstate);
		this->data = new_xedd;
		this->size = xed_decoded_inst_get_length(&new_xedd);
		return true;
	}
	~xed_ins_to_translate() {}
};





class rtn {
public:
	std::string name;
	UINT64 ins_count;
	UINT64 call_count;
	bool is_recursive;
	bool to_translate;
	std::map<ADDRINT, UINT64> caller_map;
	rtn() :name(""), ins_count(0), call_count(0), is_recursive(false), to_translate(true) {}
	rtn(const std::string new_name) :name(new_name), ins_count(0), call_count(0), is_recursive(false), to_translate(true) {}
	bool isCallerExist(ADDRINT caller_address) {
		return (!(this->caller_map.find(caller_address) == this->caller_map.end()));
	}
	ADDRINT dominate_call() {
		if (this->caller_map.empty()) {
			return NO_DOMINATE_CALL;
		}
		std::vector<std::pair<ADDRINT, UINT64>> vec;
		for (auto itr = this->caller_map.begin(); itr != this->caller_map.end(); ++itr) {
			vec.push_back(*itr);
		}
		sort(vec.begin(), vec.end(),
			[=](std::pair<ADDRINT, UINT64>& a, std::pair<ADDRINT, UINT64>& b) {return a.second > b.second; });
		for (size_t i = 1; i < vec.size(); i++) {
			if (vec[i].second == vec[0].second) {
				return NO_DOMINATE_CALL;
			}
		}
		return vec[0].first;
	}
	void do_not_translate() {
		if (this->to_translate) {
			this->to_translate = false;
		}
	}
	~rtn() {}
};
class loop {
public:
	ADDRINT target_address;
	ADDRINT rtn_address;
	UINT64 totalCountSeen;
	UINT64 countLoopInvoked;
	std::vector<UINT64> countSeen;


	loop() :target_address((ADDRINT)0), rtn_address((ADDRINT)0), totalCountSeen(0), countLoopInvoked(0) {}
	loop(ADDRINT target_addr, ADDRINT rtn_addr) :target_address(target_addr), rtn_address(rtn_addr), totalCountSeen(0), countLoopInvoked(0) {}
	~loop() {}
};

class bbl {
public:
	ADDRINT endAddress;
	ADDRINT rtn_address;
	UINT64 count_total;
	UINT64 count_taken;
	ADDRINT jumpAddress;
	ADDRINT fall_address;
	bbl() :endAddress((ADDRINT)0), rtn_address((ADDRINT)0), count_total(0), count_taken(0),
		jumpAddress((ADDRINT)0), fall_address((ADDRINT)0) {}
	bbl(ADDRINT new_tail) :endAddress(new_tail), rtn_address((ADDRINT)0), count_total(0), count_taken(0),
		jumpAddress((ADDRINT)0), fall_address((ADDRINT)0) {}
	bool merge(const bbl& obj) {
		if (this->rtn_address != obj.rtn_address || this->endAddress != obj.endAddress) {
			return false;
		}
		this->count_total += obj.count_total;
		this->count_taken += obj.count_taken;
		//this->count_total = (this->count_total > obj.count_total) ? this->count_total : obj.count_total;
		//this->count_taken = (this->count_taken > obj.count_taken) ? this->count_taken : obj.count_taken;
		return true;
	}
	~bbl(){}

};



const float HOT_CALL = 0.6;
const int HOT_CALL_MIN_COUNT = 1;


/* ===================================================================== */
/* Types and Globals                                                     */
/* ===================================================================== */

typedef struct
{
    UINT64 count_seen;
    UINT64 count_taken;
    ADDRINT rtn_addr;
    string rtn_name;
    ADDRINT target_addr;
} branch_data;

map<ADDRINT, branch_data> branches;

map<ADDRINT, UINT64> rtn_ins_counts;
map<ADDRINT, UINT64> rtn_call_counts;
map<ADDRINT, map<ADDRINT, UINT64>> caller_count;
map<ADDRINT, ADDRINT> rtn_callers;

map<ADDRINT, ADDRINT> inlining_candidates;
map<ADDRINT, float> branch_heat;
map<ADDRINT, ADDRINT> reordering_targets;
set<ADDRINT> skipped_routines;



std::map<ADDRINT, rtn> routine_map;
std::map<ADDRINT, loop> loop_map;
std::map<ADDRINT, bbl> bbl_map;
bool isElementExistInMap(ADDRINT address, auto map) {
	return (!(map.find(address) == map.end()));
}
bool isRoutineExist(ADDRINT rtn_address) {
	return (!(routine_map.find(rtn_address) == routine_map.end()));
}
bool isLoopExist(ADDRINT loop_address) {
	return (!(loop_map.find(loop_address) == loop_map.end()));
}

bool isBblExist(ADDRINT bbl_address) {
	return isElementExistInMap(bbl_address, bbl_map);
}




/*Project*/
std::map<ADDRINT, std::vector<xed_ins_to_translate>> function_xedds_map;
std::map<ADDRINT, std::vector<std::pair<ADDRINT, ADDRINT>>> reorderd_rtn_map;
std::map<ADDRINT, ADDRINT> cond_br_address_to_end_of_fallthrough;





int GetInstructionTarget(
        xed_decoded_inst_t* xedd,
        ADDRINT insAddr,
        ADDRINT* targetAddr)
{
    xed_uint_t displacementBytes = xed_decoded_inst_get_branch_displacement_width(xedd);
    xed_int32_t displacement;

    if (displacementBytes <= 0) {
        if (KnobDebug) {
            cout << "Oops! Call with no offset." << endl;
        }
        return -1;
    }

    displacement = xed_decoded_inst_get_branch_displacement(xedd);
    *targetAddr = insAddr + xed_decoded_inst_get_length(xedd) + displacement;
    return 0;
}




/* ============================================================= */
/* Service dump routines                                         */
/* ============================================================= */

/*************************/
/* dump_all_image_instrs */
/*************************/
void dump_all_image_instrs(IMG img)
{
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {   
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {		

			// Open the RTN.
            RTN_Open( rtn );

			cerr << RTN_Name(rtn) << ":" << endl;

			for( INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins) )
            {				
	              cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;
			}

			// Close the RTN.
            RTN_Close( rtn );
		}
	}
}


/*************************/
/* dump_instr_from_xedd */
/*************************/
void dump_instr_from_xedd (xed_decoded_inst_t* xedd, ADDRINT address)
{
	// debug print decoded instr:
	char disasm_buf[2048];

    xed_uint64_t runtime_address = static_cast<UINT64>(address);  // set the runtime adddress for disassembly 	

    xed_format_context(XED_SYNTAX_INTEL, xedd, disasm_buf, sizeof(disasm_buf), static_cast<UINT64>(runtime_address), 0, 0);	

    cerr << hex << address << ": " << disasm_buf <<  endl;
}


/************************/
/* dump_instr_from_mem */
/************************/
void dump_instr_from_mem (ADDRINT *address, ADDRINT new_addr)
{
  char disasm_buf[2048];
  xed_decoded_inst_t new_xedd;

  xed_decoded_inst_zero_set_mode(&new_xedd,&dstate); 
   
  xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), max_inst_len);				   

  BOOL xed_ok = (xed_code == XED_ERROR_NONE);
  if (!xed_ok){
	  cerr << "invalid opcode" << endl;
	  return;
  }
 
  xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(new_addr), 0, 0);

  cerr << "0x" << hex << new_addr << ": " << disasm_buf <<  endl;  
 
}


/****************************/
/*  dump_entire_instr_map() */
/****************************/
void dump_entire_instr_map()
{	
	for (int i=0; i < num_of_instr_map_entries; i++) {
		for (int j=0; j < translated_rtn_num; j++) {
			if (translated_rtn[j].instr_map_entry == i) {

				RTN rtn = RTN_FindByAddress(translated_rtn[j].rtn_addr);

				if (rtn == RTN_Invalid()) {
					cerr << "Unknwon"  << ":" << endl;
				} else {
				  cerr << RTN_Name(rtn) << ":" << endl;
				}
			}
		}
		dump_instr_from_mem ((ADDRINT *)instr_map[i].new_ins_addr, instr_map[i].new_ins_addr);		
	}
}


/**************************/
/* dump_instr_map_entry */
/**************************/
void dump_instr_map_entry(int instr_map_entry)
{
	cerr << dec << instr_map_entry << ": ";
	cerr << " orig_ins_addr: " << hex << instr_map[instr_map_entry].orig_ins_addr;
	cerr << " new_ins_addr: " << hex << instr_map[instr_map_entry].new_ins_addr;
	cerr << " orig_targ_addr: " << hex << instr_map[instr_map_entry].orig_targ_addr;

	ADDRINT new_targ_addr;
	if (instr_map[instr_map_entry].targ_map_entry >= 0)
		new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;
	else
		new_targ_addr = instr_map[instr_map_entry].orig_targ_addr;

	cerr << " new_targ_addr: " << hex << new_targ_addr;
	cerr << "    new instr:";
	dump_instr_from_mem((ADDRINT *)instr_map[instr_map_entry].encoded_ins, instr_map[instr_map_entry].new_ins_addr);
}


/*************/
/* dump_tc() */
/*************/
void dump_tc()
{
  char disasm_buf[2048];
  xed_decoded_inst_t new_xedd;
  ADDRINT address = (ADDRINT)&tc[0];
  unsigned int size = 0;

  while (address < (ADDRINT)&tc[tc_cursor]) {

      address += size;

	  xed_decoded_inst_zero_set_mode(&new_xedd,&dstate); 
   
	  xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), max_inst_len);				   

	  BOOL xed_ok = (xed_code == XED_ERROR_NONE);
	  if (!xed_ok){
		  cerr << "invalid opcode" << endl;
		  return;
	  }
 
	  xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(address), 0, 0);

	  cerr << "0x" << hex << address << ": " << disasm_buf <<  endl;

	  size = xed_decoded_inst_get_length (&new_xedd);	
  }
}


/* ============================================================= */
/* Translation routines                                         */
/* ============================================================= */







int add_new_instr_entry_2(
    xed_decoded_inst_t * xedd,
    ADDRINT pc,
    unsigned int size,
    bool inserted_inst)
{
    // copy orig instr to instr map:
    ADDRINT orig_targ_addr = 0;

    if (xed_decoded_inst_get_length(xedd) != size) {
        cerr << "Invalid instruction decoding" << endl;
        return -1;
    }

    xed_uint_t disp_byts = xed_decoded_inst_get_branch_displacement_width(xedd);

    xed_int32_t disp;

    if (disp_byts > 0) { // there is a branch offset.
      disp = xed_decoded_inst_get_branch_displacement(xedd);
      orig_targ_addr = pc + xed_decoded_inst_get_length(xedd) + disp;
    }

    // Converts the decoder request to a valid encoder request:
    xed_encoder_request_init_from_decode(xedd);

    unsigned int new_size = 0;

    xed_error_enum_t xed_error = xed_encode(
        xedd,
        (xed_uint8_t *)(instr_map[num_of_instr_map_entries].encoded_ins),
        max_inst_len , &new_size);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        return -1;
    }

    // add a new entry in the instr_map:

    instr_map[num_of_instr_map_entries].orig_ins_addr = inserted_inst ? 0 : pc;
    instr_map[num_of_instr_map_entries].new_ins_addr = (ADDRINT)&tc[tc_cursor];  // set an initial estimated addr in tc
    instr_map[num_of_instr_map_entries].orig_targ_addr = orig_targ_addr;
    instr_map[num_of_instr_map_entries].hasNewTargAddr = false;
    instr_map[num_of_instr_map_entries].targ_map_entry = -1;
    instr_map[num_of_instr_map_entries].size = new_size;
    instr_map[num_of_instr_map_entries].category_enum = xed_decoded_inst_get_category(xedd);
  //  instr_map[num_of_instr_map_entries].inline_count = inline_count;

    num_of_instr_map_entries++;

    // update expected size of tc:
    tc_cursor += new_size;

    if (num_of_instr_map_entries >= max_ins_count) {
        cerr << "out of memory for map_instr" << endl;
        return -1;
    }

    // debug print new encoded instr:
    if (KnobVerbose) {
        cerr << "\tnew instr:";
        dump_instr_from_mem((ADDRINT *)instr_map[num_of_instr_map_entries-1].encoded_ins,
                            instr_map[num_of_instr_map_entries-1].new_ins_addr);
    }

    return new_size;
}







/*************************/
/* add_new_instr_entry() */
/*************************/
int add_new_instr_entry(xed_decoded_inst_t *xedd, ADDRINT pc, unsigned int size, ADDRINT orig_targ_addr = (ADDRINT)0)
{

	// copy orig instr to instr map:
	if (xed_decoded_inst_get_length (xedd) != size) {
		cerr << "Invalid instruction decoding" << endl;
		return -1;
	}

    xed_uint_t disp_byts = xed_decoded_inst_get_branch_displacement_width(xedd);
	
	xed_int32_t disp;

    if (disp_byts > 0) { // there is a branch offset.
      disp = xed_decoded_inst_get_branch_displacement(xedd);
	  orig_targ_addr = (orig_targ_addr != (ADDRINT)0) ? orig_targ_addr : (pc + xed_decoded_inst_get_length (xedd) + disp);
	}
	// Converts the decoder request to a valid encoder request:
	xed_encoder_request_init_from_decode (xedd);

    unsigned int new_size = 0;
	
	xed_error_enum_t xed_error = xed_encode (xedd, reinterpret_cast<UINT8*>(instr_map[num_of_instr_map_entries].encoded_ins), max_inst_len , &new_size);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;		
		return -1;
	}	
	
	// add a new entry in the instr_map:
	
	instr_map[num_of_instr_map_entries].orig_ins_addr = pc;
	instr_map[num_of_instr_map_entries].new_ins_addr = (ADDRINT)&tc[tc_cursor];  // set an initial estimated addr in tc
	instr_map[num_of_instr_map_entries].orig_targ_addr = orig_targ_addr; 
    instr_map[num_of_instr_map_entries].hasNewTargAddr = false;
	instr_map[num_of_instr_map_entries].targ_map_entry = -1;
	instr_map[num_of_instr_map_entries].size = new_size;	
    instr_map[num_of_instr_map_entries].category_enum = xed_decoded_inst_get_category(xedd);

	num_of_instr_map_entries++;

	// update expected size of tc:
	tc_cursor += new_size;    	     

	if (num_of_instr_map_entries >= max_ins_count) {
		cerr << "out of memory for map_instr" << endl;
		return -1;
	}
	

    // debug print new encoded instr:
	if (KnobVerbose) {
		cerr << "    new instr:";
		dump_instr_from_mem((ADDRINT *)instr_map[num_of_instr_map_entries-1].encoded_ins, instr_map[num_of_instr_map_entries-1].new_ins_addr);
	}

	return new_size;
}


/*************************************************/
/* chain_all_direct_br_and_call_target_entries() */
/*************************************************/
int chain_all_direct_br_and_call_target_entries()
{
	for (int i=0; i < num_of_instr_map_entries; i++) {			    

		if (instr_map[i].orig_targ_addr == 0)
			continue;

		if (instr_map[i].hasNewTargAddr)
			continue;

        for (int j = 0; j < num_of_instr_map_entries; j++) {

            if (j == i)
			   continue;
	
            if (instr_map[j].orig_ins_addr == instr_map[i].orig_targ_addr) {
                instr_map[i].hasNewTargAddr = true; 
	            instr_map[i].targ_map_entry = j;
                break;
			}
		}
	}
   
	return 0;
}


/**************************/
/* fix_rip_displacement() */
/**************************/
int fix_rip_displacement(int instr_map_entry) 
{
	//debug print:
	//dump_instr_map_entry(instr_map_entry);

	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd,&dstate); 
				   
	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
		return -1;
	}

	unsigned int memops = xed_decoded_inst_number_of_memory_operands(&xedd);

	if (instr_map[instr_map_entry].orig_targ_addr != 0)  // a direct jmp or call instruction.
		return 0;

	//cerr << "Memory Operands" << endl;
	bool isRipBase = false;
	xed_reg_enum_t base_reg = XED_REG_INVALID;
	xed_int64_t disp = 0;
	for(unsigned int i=0; i < memops ; i++)   {

		base_reg = xed_decoded_inst_get_base_reg(&xedd,i);
		disp = xed_decoded_inst_get_memory_displacement(&xedd,i);

		if (base_reg == XED_REG_RIP) {
			isRipBase = true;
			break;
		}
		
	}

	if (!isRipBase)
		return 0;

			
	//xed_uint_t disp_byts = xed_decoded_inst_get_memory_displacement_width(xedd,i); // how many byts in disp ( disp length in byts - for example FFFFFFFF = 4
	xed_int64_t new_disp = 0;
	xed_uint_t new_disp_byts = 4;   // set maximal num of byts for now.

	unsigned int orig_size = xed_decoded_inst_get_length (&xedd);

	// modify rip displacement. use direct addressing mode:	
	new_disp = instr_map[instr_map_entry].orig_ins_addr + disp + orig_size; // xed_decoded_inst_get_length (&xedd_orig);
	xed_encoder_request_set_base0 (&xedd, XED_REG_INVALID);

	//Set the memory displacement using a bit length 
	xed_encoder_request_set_memory_displacement (&xedd, new_disp, new_disp_byts);

	unsigned int size = XED_MAX_INSTRUCTION_BYTES;
	unsigned int new_size = 0;
			
	// Converts the decoder request to a valid encoder request:
	xed_encoder_request_init_from_decode (&xedd);
	
	xed_error_enum_t xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), size , &new_size); // &instr_map[i].size
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
		dump_instr_map_entry(instr_map_entry); 
		return -1;
	}				

	if (KnobVerbose) {
		dump_instr_map_entry(instr_map_entry);
	}

	return new_size;
}


/************************************/
/* fix_direct_br_call_to_orig_addr */
/************************************/
int fix_direct_br_call_to_orig_addr(int instr_map_entry)
{

	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd,&dstate); 
				   
	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
		return -1;
	}
	
	xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);
	if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_UNCOND_BR) {
		cerr << "ERROR: Invalid direct jump from translated code to original code in rotuine: " 
			  << RTN_Name(RTN_FindByAddress(instr_map[instr_map_entry].orig_ins_addr)) << endl;
		cerr << "category_enum: " << xed_category_enum_t2str(category_enum) << endl;
		dump_instr_map_entry(instr_map_entry);
		return -1;
	}

	// check for cases of direct jumps/calls back to the orginal target address:
	if (instr_map[instr_map_entry].targ_map_entry >= 0) {
		cerr << "ERROR: Invalid jump or call instruction" << endl;
		return -1;
	}

	unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
	unsigned int olen = 0;
				

	xed_encoder_instruction_t  enc_instr;

	ADDRINT new_disp = (ADDRINT)&instr_map[instr_map_entry].orig_targ_addr - 
		               instr_map[instr_map_entry].new_ins_addr - 
					   xed_decoded_inst_get_length (&xedd);

	if (category_enum == XED_CATEGORY_CALL)
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_CALL_NEAR, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

	if (category_enum == XED_CATEGORY_UNCOND_BR)
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_JMP, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));


	xed_encoder_request_t enc_req;

	xed_encoder_request_zero_set_mode(&enc_req, &dstate);
	xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
	if (!convert_ok) {
		cerr << "conversion to encode request failed" << endl;
		return -1;
	}
   

	xed_error_enum_t xed_error = xed_encode(&enc_req, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), ilen, &olen);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
	    dump_instr_map_entry(instr_map_entry); 
        return -1;
    }

	// handle the case where the original instr size is different from new encoded instr:
	if (olen != xed_decoded_inst_get_length (&xedd)) {
		
		new_disp = (ADDRINT)&instr_map[instr_map_entry].orig_targ_addr - 
	               instr_map[instr_map_entry].new_ins_addr - olen;

		if (category_enum == XED_CATEGORY_CALL)
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_CALL_NEAR, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

		if (category_enum == XED_CATEGORY_UNCOND_BR)
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_JMP, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));


		xed_encoder_request_zero_set_mode(&enc_req, &dstate);
		xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
		if (!convert_ok) {
			cerr << "conversion to encode request failed" << endl;
			return -1;
		}

		xed_error = xed_encode (&enc_req, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), ilen , &olen);
		if (xed_error != XED_ERROR_NONE) {
			cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
			dump_instr_map_entry(instr_map_entry);
			return -1;
		}		
	}

	
	// debug prints:
	if (KnobVerbose) {
		dump_instr_map_entry(instr_map_entry); 
	}
		
	instr_map[instr_map_entry].hasNewTargAddr = true;
	return olen;	
}


/***********************************/
/* fix_direct_br_call_displacement */
/***********************************/
int fix_direct_br_call_displacement(int instr_map_entry) 
{					

	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd,&dstate); 
				   
	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
		return -1;
	}

	xed_int32_t  new_disp = 0;	
	unsigned int size = XED_MAX_INSTRUCTION_BYTES;
	unsigned int new_size = 0;


	xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);
	
	if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_COND_BR && category_enum != XED_CATEGORY_UNCOND_BR) {
		cerr << "ERROR: unrecognized branch displacement" << endl;
		return -1;
	}

	// fix branches/calls to original targ addresses:
	if (instr_map[instr_map_entry].targ_map_entry < 0) {
	   int rc = fix_direct_br_call_to_orig_addr(instr_map_entry);
	   return rc;
	}

	ADDRINT new_targ_addr;		
	new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;
		
	new_disp = (new_targ_addr - instr_map[instr_map_entry].new_ins_addr) - instr_map[instr_map_entry].size; // orig_size;

	xed_uint_t   new_disp_byts = 4; // num_of_bytes(new_disp);  ???

	// the max displacement size of loop instructions is 1 byte:
	xed_iclass_enum_t iclass_enum = xed_decoded_inst_get_iclass(&xedd);
	if (iclass_enum == XED_ICLASS_LOOP ||  iclass_enum == XED_ICLASS_LOOPE || iclass_enum == XED_ICLASS_LOOPNE) {
	  new_disp_byts = 1;
	}

	// the max displacement size of jecxz instructions is ???:
	xed_iform_enum_t iform_enum = xed_decoded_inst_get_iform_enum (&xedd);
	if (iform_enum == XED_IFORM_JRCXZ_RELBRb){
	  new_disp_byts = 1;
	}

	// Converts the decoder request to a valid encoder request:
	xed_encoder_request_init_from_decode (&xedd);

	//Set the branch displacement:
	xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);

	xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
	unsigned int max_size = XED_MAX_INSTRUCTION_BYTES;
    
	xed_error_enum_t xed_error = xed_encode (&xedd, enc_buf, max_size , &new_size);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) <<  endl;
		char buf[2048];		
		xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 2048, static_cast<UINT64>(instr_map[instr_map_entry].orig_ins_addr), 0, 0);
	    cerr << " instr: " << "0x" << hex << instr_map[instr_map_entry].orig_ins_addr << " : " << buf <<  endl;
  		return -1;
	}		

	new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;

	new_disp = new_targ_addr - (instr_map[instr_map_entry].new_ins_addr + new_size);  // this is the correct displacemnet.

	//Set the branch displacement:
	xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);
	
	xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), size , &new_size); // &instr_map[i].size
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
		dump_instr_map_entry(instr_map_entry);
		return -1;
	}				

	//debug print of new instruction in tc:
	if (KnobVerbose) {
		dump_instr_map_entry(instr_map_entry);
	}

	return new_size;
}				


/************************************/
/* fix_instructions_displacements() */
/************************************/
int fix_instructions_displacements()
{
   // fix displacemnets of direct branch or call instructions:

    int size_diff = 0;	

	do {
		
		size_diff = 0;

		if (KnobVerbose) {
			cerr << "starting a pass of fixing instructions displacements: " << endl;
		}

		for (int i=0; i < num_of_instr_map_entries; i++) {

			instr_map[i].new_ins_addr += size_diff;
				   
			int new_size = 0;

			// fix rip displacement:			
			new_size = fix_rip_displacement(i);
			if (new_size < 0)
				return -1;

			if (new_size > 0) { // this was a rip-based instruction which was fixed.

				if (instr_map[i].size != (unsigned int)new_size) {
				   size_diff += (new_size - instr_map[i].size); 					
				   instr_map[i].size = (unsigned int)new_size;								
				}

				continue;   
			}

			// check if it is a direct branch or a direct call instr:
			if (instr_map[i].orig_targ_addr == 0) {
				continue;  // not a direct branch or a direct call instr.
			}


			// fix instr displacement:			
			new_size = fix_direct_br_call_displacement(i);
			if (new_size < 0)
				return -1;

			if (instr_map[i].size != (unsigned int)new_size) {
			   size_diff += (new_size - instr_map[i].size);
			   instr_map[i].size = (unsigned int)new_size;
			}

		}  // end int i=0; i ..

	} while (size_diff != 0);

   return 0;
 }





/*****************************************/
/* find_candidate_rtns_for_translation() */
/*****************************************/


std::vector<xed_ins_to_translate> reorder(std::vector<xed_ins_to_translate> translated_routine, std::vector<std::pair<ADDRINT, ADDRINT>> new_order)  {
	std::vector<xed_ins_to_translate> result;
	std::map<ADDRINT, size_t> back_edges;


	for (size_t i = 0; i < new_order.size(); i++) {
		for (auto itr = translated_routine.begin(); itr != translated_routine.end(); ++itr) {
			if (itr->addr >= new_order[i].first && itr->addr <= new_order[i].second) {
				if (itr->addr != new_order[i].second) {
					result.push_back(*itr);
				}
				else {
					if (itr->category_enum == XED_CATEGORY_COND_BR && (i < new_order.size() - 1 && itr != translated_routine.end() - 1)
						&& itr->target_addr == new_order[i + 1].first) {
						/* Fix cond jump. Cause the new order brings target to be FT.*/
						xed_ins_to_translate new_tail(*itr);
						xed_error_enum_t xed_error;
						if (new_tail.revert_cond_jump(xed_error)) {
							new_tail.target_addr = std::next(itr)->addr;
							result.push_back(new_tail);
						
							if(isElementExistInMap(itr->addr, cond_br_address_to_end_of_fallthrough)){
								back_edges[cond_br_address_to_end_of_fallthrough[itr->addr]] = i + 1;
							}
						}
						else if (xed_error != XED_ERROR_NONE) {
							/* Error handling in case of encoder/decoder failur. */
							cerr << "ENCODE ERROR at new_tail (Reorder): " << xed_error_enum_t2str(xed_error) << endl;
							result.clear();
							return result;
						}

					}
					else {
						result.push_back(*itr);
					}
				}
				if (isElementExistInMap(itr->addr, back_edges)) {
					xed_bool_t convert_ok;
					xed_error_enum_t xed_code;
					xed_ins_to_translate new_back_jump(itr->addr, new_order[back_edges[itr->addr]].first, convert_ok, xed_code);
					if (!convert_ok) {
						cerr << "conversion to encode request failed at new_jump. (Reorder)" << endl;
						result.clear();
						return result;
					}
					else if (xed_code != XED_ERROR_NONE) {
						cerr << "ENCODE ERROR at new_jump (Reorder): " << xed_error_enum_t2str(xed_code) << endl;
						result.clear();
						return result;
					}
					else if (new_back_jump.category_enum == XED_CATEGORY_INVALID) {
						cerr << "new_back_jump construction failed. (Reorder)" << endl;
						result.clear();
						return result;
					}
					else {
						result.push_back(new_back_jump);
					}
				}
			}
		}
	}
	return result;
}





int add_rtn_to_inst_map_2(RTN rtn)
{
    int rc = 0;
    bool skip;
    int size;
    INS head;
    ADDRINT rtn_addr;
    ADDRINT rtn_end;
    ADDRINT ins_addr;
    xed_decoded_inst_t xedd;
    xed_error_enum_t xed_code;
    ADDRINT target_addr;

    // Get routine boundaries.
    RTN_Open(rtn);
    head = RTN_InsHead(rtn);
    rtn_end = INS_Address(RTN_InsTail(rtn));
    RTN_Close(rtn);

    rtn_addr = RTN_Address(rtn);
 

    ins_addr = INS_Address(head);

    while (ins_addr <= rtn_end)
    {
        // debug print of routine name:
        if (KnobVerbose)
        {
            cerr << "\trtn name: " << RTN_Name(rtn) << " : " << dec << translated_rtn_num;
            cerr << " : " << hex << rtn_addr;
            cerr << " : " << hex << RTN_Address(rtn);
            cerr << "; " << hex << ins_addr << endl;
        }

        xed_decoded_inst_zero_set_mode(&xedd, &dstate);

        xed_code = xed_decode(&xedd,
                              reinterpret_cast<UINT8 *>(ins_addr),
                              max_inst_len);
        if (xed_code != XED_ERROR_NONE)
        {
            cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << ins_addr << endl;
            translated_rtn[translated_rtn_num].instr_map_entry = -1;
            break;
        }

        size = xed_decoded_inst_get_length(&xedd);

        //debug print of orig instruction:
        if (KnobVerbose)
        {
            cerr << "old instr: ";
            dump_instr_from_xedd(&xedd, ins_addr);
        }

        skip = false;

        xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);
         if (XED_CATEGORY_CALL == category_enum)
        {
            rc = GetInstructionTarget(&xedd, ins_addr, &target_addr);
            if (rc != 0)
            {
                return -1;
            }

            if ((inlining_candidates.count(target_addr) > 0) &&
                (ins_addr == inlining_candidates[target_addr]))
            {
                if (KnobDebug)
                {
                    cout << "Found candidate " << hex << target_addr <<
                         " -> " << ins_addr << endl;
                }
                rc = add_rtn_to_inst_map_2(RTN_FindByAddress(target_addr));
                if (rc != 0)
                {
                    if (KnobDebug)
                    {
                        cout << "Zut. failed to inline." << endl;
                    }
                    return -1;
                }
                else if (KnobDebug)
                {
                    cout << "Yay! Succeeded inline! " << num_of_instr_map_entries << endl;
                }


                // Ignore `ret` inst by decrementing entry count & tc cursor.
                num_of_instr_map_entries--;
                tc_cursor--;

                skip = true;
            }
        }

        if (!skip)
        {
            // Add instr into instr map:
            rc = add_new_instr_entry_2(&xedd, ins_addr, size,false);
            if (rc < 0)
            {
                cerr << "ERROR: failed during instruction translation." << endl;
                translated_rtn[translated_rtn_num].instr_map_entry = -1;
                return -1;
            }
        }

        ins_addr += size;
    }

    return 0;
}
void add_rtn_for_translation_2(RTN rtn)
{
    int rc;
    int tc_saved;
    int current_entry_count;

    // Backup translation data in case of translation failure.
    tc_saved = tc_cursor;
    current_entry_count = num_of_instr_map_entries;
    ADDRINT rtn_address = RTN_Address(rtn);

    // Skip over routines that were already added for translation.
    for (int i = 0; i < translated_rtn_num; ++i)
    {
        if (translated_rtn[i].rtn_addr == rtn_address)
        {
            return;
        }
    }

    translated_rtn[translated_rtn_num].rtn_addr = rtn_address;
    translated_rtn[translated_rtn_num].rtn_size = RTN_Size(rtn);
    translated_rtn[translated_rtn_num].instr_map_entry = num_of_instr_map_entries;

    rc = add_rtn_to_inst_map_2(rtn);
    if (rc != 0)
    {
        skipped_routines.insert(rtn_address);
        if (KnobDebug)
        {
            cout << "Zut. Failed to add routine " << std::hex << RTN_Address(rtn)
                 << " " << RTN_Name(rtn) << " " << rc << endl;
        }
        // Backup after failure to translate, as if the routine was never translated.
        tc_cursor = tc_saved;
        num_of_instr_map_entries = current_entry_count;
        return;
    }

    translated_rtn_num++;
}



void LoadInliningCandidates()
{
    ifstream csvFile("inline-rtn-count.csv");

    if (!csvFile.good())
    {
        cout << "Oops! Can't open " << "inline-rtn-count.csv" << endl;
        exit(1);
    }

    if (csvFile.is_open())
    {
        string line;
        while (getline(csvFile, line))
        {
            vector<string> splitLine;
            string splitWord;
            istringstream stringStream(line);

            while (getline(stringStream, splitWord, ','))
            {
                splitLine.push_back(splitWord);
            }

            ADDRINT callee = strtol(splitLine[0].c_str(), nullptr, 16);
            ADDRINT caller = strtol(splitLine[3].c_str(), nullptr, 16);

            if (caller != 0)
            {
                rtn_callers[callee] = caller;
            }
        }

        csvFile.close();
        }
}



int IsValidForInlining(RTN rtn)
{
    int returnValue = 0;
    bool hasRet = false;

    ADDRINT startAddr;
    INS lastIns;
    ADDRINT endAddr;

    ADDRINT targetAddr;

    RTN_Open(rtn);

    startAddr = RTN_Address(rtn);

    lastIns = RTN_InsTail(rtn);
    if (!INS_IsRet(lastIns))
    {
        returnValue = 1;
        goto Cleanup;
    }

    endAddr = INS_Address(lastIns);

    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
    {
        // Do not inline functions that have more than one ret instructions.
        if (INS_IsRet(ins))
        {
            if (hasRet)
            {
                returnValue = 2;
                goto Cleanup;
            }

            hasRet = true;
        }

            // Do not inline functions with indirect calls/jumps.
        else if (INS_IsIndirectControlFlow(ins))
        {
            returnValue = 3;
            goto Cleanup;
        }

        // Do not inline functions that jump outside their own scope.
        if (INS_IsBranch(ins))
        {
            targetAddr = INS_DirectControlFlowTargetAddress(ins);
            if (targetAddr < startAddr || targetAddr > endAddr)
            {
                returnValue = 4;
                goto Cleanup;
            }
        }

        if (INS_IsSub(ins) && INS_RegWContain(ins, REG::REG_RSP))
        {
            returnValue = 6;
            goto Cleanup;
        }

        // Do not inline functions with invalid r[sb]p offsets.
        for (UINT32 memOpIndex = 0; memOpIndex < INS_MemoryOperandCount(ins); ++memOpIndex)
        {
            if (INS_MemoryOperandIsRead(ins, memOpIndex) ||
                INS_MemoryOperandIsWritten(ins, memOpIndex))
            {
                REG baseReg = INS_OperandMemoryBaseReg(ins, memOpIndex);
                ADDRDELTA displacement = INS_OperandMemoryDisplacement(ins, memOpIndex);

                if ((baseReg == REG_RSP && displacement < 0) ||
                    (baseReg == REG_RBP && displacement > 0))
                {
                    returnValue = 5;
                    goto Cleanup;
                }
            }
        }
    }

    Cleanup:
    RTN_Close(rtn);
    return returnValue;
}




int FindInliningCandidates()
{
    int returnValue = -1;
    RTN callee;

    for (const auto& pair : rtn_callers)
    {
        callee = RTN_FindByAddress(pair.first);

        if (!RTN_Valid(callee))
        {
            if (KnobDebug)
            {
                cout << "Oops! Received an invalid routine to inline." << endl;
            }
            continue;
        }

        returnValue = IsValidForInlining(callee);
        if (returnValue != 0)
        {
            if (KnobDebug)
            {
                cout << "Oops! Routine can't be inlined (" << returnValue << ")." << endl;
            }
            continue;
        }

        inlining_candidates[pair.first] = pair.second;
        returnValue = 0;

        if (KnobDebug)
        {
            cout << "Yay! " << hex << pair.first << " " << pair.second << " is valid" << endl;
        }
    }

    return returnValue;
}







int find_candidate_rtns_for_translation(IMG img)
{
	int rc;
	RTN target;

	function_xedds_map.clear();
	std::map<ADDRINT, USIZE> rtn_addr_to_rtn_size;
	bool error_init_decode = false ;
	// go over routines and check if they are candidates for translation and mark them for translation:
	
	

	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
	{
		if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
			continue;

		for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
		{

			if (rtn == RTN_Invalid()) {
				cerr << "Warning: invalid routine " << RTN_Name(rtn) << endl;
				continue;
			}

		
			ADDRINT rtn_addr = RTN_Address(rtn);
			if (function_xedds_map.find(rtn_addr) != function_xedds_map.end()) {
				continue;
			}
			std::cout << "Translating RTN: " << RTN_Name(rtn) << endl;
			function_xedds_map[rtn_addr].clear();
			rtn_addr_to_rtn_size[rtn_addr] = RTN_Size(rtn);
			RTN_Open(rtn);
			for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
				ADDRINT ins_addr = INS_Address(ins);
				USIZE ins_size = INS_Size(ins);
				xed_error_enum_t xed_error_code;
				xed_ins_to_translate new_xed(ins_addr, ins_size, xed_error_code);
				if (INS_IsDirectControlFlow(ins)) {
					new_xed.target_addr = INS_DirectControlFlowTargetAddress(ins);
				}
				if (xed_error_code != XED_ERROR_NONE) {
					cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << new_xed.addr << endl;
					//translated_rtn[translated_rtn_num].instr_map_entry = -1;
					error_init_decode = true;
					break;
				}
				/* Adding new_xed to map of vector of xed */
				function_xedds_map[rtn_addr].push_back(new_xed);

			}
		
			
			RTN_Close(rtn);
			if (error_init_decode) {
				return -1;
			}
			std::cout << "Decoding RTN: " << RTN_Name(rtn) << " was successful." << endl;
		} // end for RTN..
	} // end for SEC...
	
	
	
	
	LoadInliningCandidates();
    rc = FindInliningCandidates();				
    if (rc != 0 && KnobDebug)
    {
        cout << "Zut. No routine was chosen for inlining." << endl;
    }

    // Go over all chosen routines and translate them.
    
    for (const auto &pair : inlining_candidates)
    {
        if (skipped_routines.count(pair.second) > 0)
        {
            continue;
        }

        target = RTN_FindByAddress(pair.second);

        if (!RTN_Valid(target))
        {
            cerr << "Warning: invalid routine " << RTN_Name(target) << endl;
            continue;
        }
		//if(RTN_Name(target) == "isempty_RL" || RTN_Name(target) == "BZ2_bzCompress" ){	
		
		if(RTN_Name(target) != "isempty_RL" && RTN_Name(target) != "BZ2_bzCompress" && RTN_Name(target) != "myMalloc" && RTN_Name(target) != "BZ2_bzWriteOpen"  && RTN_Name(target) != "bsFinishWrite" && RTN_Name(target) != "strcmp@plt" && RTN_Name(target) != "BZ2_bzCompressEnd"
			&& RTN_Name(target) != "default_bzalloc" && RTN_Name(target) != ".plt" && RTN_Name(target) != "isempty_RL" && RTN_Name(target) != "default_bzfree" && RTN_Name(target) != "fileExists" && RTN_Name(target) != "mkCell" && RTN_Name(target) != "__libc_csu_init" 
			&& RTN_Name(target) != "applySavedMetaInfoToOutputFile" && RTN_Name(target) != "addFlagsFromEnvVar" && RTN_Name(target) != "fopen_output_safely" && RTN_Name(target) != "strlen@plt" && RTN_Name(target) != "init_RL" && RTN_Name(target) != "flush_RL" && RTN_Name(target) != "malloc@plt" && RTN_Name(target) != "free@plt"
			&& RTN_Name(target) != "saveInputFileMetaInfo"  && RTN_Name(target) != "_start"  && RTN_Name(target) != "BZ2_bsInitWrite" && RTN_Name(target) != "strstr@plt" && RTN_Name(target) != "stat" && RTN_Name(target) != "__do_global_dtors_aux" && RTN_Name(target) != "signal@plt" && RTN_Name(target) != "strncpy@plt" && RTN_Name(target) != "_init"  && RTN_Name(target) != "containsDubiousChars" && RTN_Name(target) != "fclose@plt"
			&& RTN_Name(target) != "bz_config_ok" && RTN_Name(target) != "strcpy@plt" && RTN_Name(target) != "fopen@plt" && RTN_Name(target) != "strncmp@plt" && RTN_Name(target) != "__xstat@plt" && RTN_Name(target) != "fflush@plt"  && RTN_Name(target) != "getenv@plt"  && RTN_Name(target) != "_fini" && RTN_Name(target) != "fdopen@plt" && RTN_Name(target) != "utime@plt" && RTN_Name(target) != "frame_dummy" && RTN_Name(target) != "remove@plt"
			&& RTN_Name(target) != "open@plt" && RTN_Name(target) != "chmod@plt" && RTN_Name(target) != "__libc_start_main@plt" && RTN_Name(target) != "chown@plt" && RTN_Name(target) != "redundant" && RTN_Name(target) != "notAStandardFile" && RTN_Name(target) != "__gmon_start__@plt" && RTN_Name(target) != "fprintf@plt" && RTN_Name(target) != "ioError" && RTN_Name(target) != "fputc@plt" && RTN_Name(target) != "close@plt" && RTN_Name(target) != "countHardLinks" && RTN_Name(target) != "license" 
			&& RTN_Name(target) != "BZ2_bz__AssertH__fail" && RTN_Name(target) != "outOfMemory" && RTN_Name(target) != "__errno_location@plt" && RTN_Name(target) != "fallbackSort" && RTN_Name(target) != "panic" && RTN_Name(target) != "usage")
			{
				continue;
			}
		//std::cout << "**************************" << std::endl;			
        add_rtn_for_translation_2(target);
		
    }

	
	
	

	for (auto itr = function_xedds_map.begin(); itr != function_xedds_map.end(); itr++) {
		if (!itr->second.empty()) {
			std::string rtn_name = RTN_FindNameByAddress(itr->first);
			std::vector<xed_ins_to_translate> reorderd;
			//if (rtn_name != "deregister_tm_clones") {
			/*if(rtn_name != "BZ2_bzWriteOpen"){
				continue;
			}*/
			/*if(rtn_name=="deregister_tm_clones" ||rtn_name=="register_tm_clones" )
			{
				continue;
			}*/
			/* sendMTFValues ,"BZ2_bzCompress"  , register_tm_clones ,deregister_tm_clones */
			/*if(rtn_name != "mainGtU" && rtn_name != "mainQSort3" && rtn_name != "mainSimpleSort" && rtn_name != "mainSort" && rtn_name != "copy_input_until_stop" && rtn_name != "generateMTFValues" && rtn_name != "add_pair_to_block" && rtn_name != "BZ2_blockSort" && rtn_name != "bsW" && rtn_name != "BZ2_hbMakeCodeLengths" && rtn_name != "copy_output_until_stop" && rtn_name != "mmed3"
			&& rtn_name != "BZ2_hbAssignCodes" && rtn_name != "BZ2_bzWrite" && rtn_name != "handle_compress" && rtn_name != "compressStream" && rtn_name != "myfeof" && rtn_name != "makeMaps_e" && rtn_name != "prepare_new_block"
			&& rtn_name != "ferror@plt" && rtn_name != "fgetc@plt" && rtn_name != "ungetc@plt" && rtn_name != "fread@plt" && rtn_name != "BZ2_compressBlock" && rtn_name != "bsPutUChar" && rtn_name != "main" && rtn_name != "bsPutUInt32" && rtn_name != "BZ2_bzWriteClose64" && rtn_name != "compress" && rtn_name != "BZ2_bzCompressInit"
			&& rtn_name != "snocString" && rtn_name != "hasSuffix" && rtn_name != "copyFileName" && rtn_name != "fwrite@plt" && rtn_name != "myMalloc" && rtn_name != "BZ2_bzWriteOpen"  && rtn_name != "bsFinishWrite" && rtn_name != "strcmp@plt" && rtn_name != "BZ2_bzCompressEnd"
			&& rtn_name != "default_bzalloc" && rtn_name != ".plt" && rtn_name != "isempty_RL" && rtn_name != "default_bzfree" && rtn_name != "fileExists" && rtn_name != "mkCell" && rtn_name != "__libc_csu_init" 
			&& rtn_name != "applySavedMetaInfoToOutputFile" && rtn_name != "addFlagsFromEnvVar" && rtn_name != "fopen_output_safely" && rtn_name != "strlen@plt" && rtn_name != "init_RL" && rtn_name != "flush_RL" && rtn_name != "malloc@plt" && rtn_name != "free@plt"
			&& rtn_name != "saveInputFileMetaInfo"  && rtn_name != "_start"  && rtn_name != "BZ2_bsInitWrite" && rtn_name != "strstr@plt" && rtn_name != "stat" && rtn_name != "__do_global_dtors_aux" && rtn_name != "signal@plt" && rtn_name != "strncpy@plt" && rtn_name != "_init"  && rtn_name != "containsDubiousChars" && rtn_name != "fclose@plt"
			&& rtn_name != "bz_config_ok" && rtn_name != "strcpy@plt" && rtn_name != "fopen@plt" && rtn_name != "strncmp@plt" && rtn_name != "__xstat@plt" && rtn_name != "fflush@plt"  && rtn_name != "getenv@plt"  && rtn_name != "_fini" && rtn_name != "fdopen@plt" && rtn_name != "utime@plt" && rtn_name != "frame_dummy" && rtn_name != "remove@plt"
			&& rtn_name != "open@plt" && rtn_name != "chmod@plt" && rtn_name != "__libc_start_main@plt" && rtn_name != "chown@plt" && rtn_name != "redundant" && rtn_name != "notAStandardFile" && rtn_name != "__gmon_start__@plt" && rtn_name != "fprintf@plt" && rtn_name != "ioError" && rtn_name != "fputc@plt" && rtn_name != "close@plt" && rtn_name != "countHardLinks" && rtn_name != "license" 
			&& rtn_name != "BZ2_bz__AssertH__fail" && rtn_name != "outOfMemory" && rtn_name != "__errno_location@plt" && rtn_name != "fallbackSort" && rtn_name != "panic" && rtn_name != "usage" ) {
				continue;
			}*/
			if(rtn_name != "myMalloc" && rtn_name != "BZ2_bzWriteOpen"  && rtn_name != "bsFinishWrite" && rtn_name != "strcmp@plt" && rtn_name != "BZ2_bzCompressEnd"
			&& rtn_name != "default_bzalloc" && rtn_name != ".plt" && rtn_name != "isempty_RL" && rtn_name != "default_bzfree" && rtn_name != "fileExists" && rtn_name != "mkCell" && rtn_name != "__libc_csu_init" 
			&& rtn_name != "applySavedMetaInfoToOutputFile" && rtn_name != "addFlagsFromEnvVar" && rtn_name != "fopen_output_safely" && rtn_name != "strlen@plt" && rtn_name != "init_RL" && rtn_name != "flush_RL" && rtn_name != "malloc@plt" && rtn_name != "free@plt"
			&& rtn_name != "saveInputFileMetaInfo"  && rtn_name != "_start"  && rtn_name != "BZ2_bsInitWrite" && rtn_name != "strstr@plt" && rtn_name != "stat" && rtn_name != "__do_global_dtors_aux" && rtn_name != "signal@plt" && rtn_name != "strncpy@plt" && rtn_name != "_init"  && rtn_name != "containsDubiousChars" && rtn_name != "fclose@plt"
			&& rtn_name != "bz_config_ok" && rtn_name != "strcpy@plt" && rtn_name != "fopen@plt" && rtn_name != "strncmp@plt" && rtn_name != "__xstat@plt" && rtn_name != "fflush@plt"  && rtn_name != "getenv@plt"  && rtn_name != "_fini" && rtn_name != "fdopen@plt" && rtn_name != "utime@plt" && rtn_name != "frame_dummy" && rtn_name != "remove@plt"
			&& rtn_name != "open@plt" && rtn_name != "chmod@plt" && rtn_name != "__libc_start_main@plt" && rtn_name != "chown@plt" && rtn_name != "redundant" && rtn_name != "notAStandardFile" && rtn_name != "__gmon_start__@plt" && rtn_name != "fprintf@plt" && rtn_name != "ioError" && rtn_name != "fputc@plt" && rtn_name != "close@plt" && rtn_name != "countHardLinks" && rtn_name != "license" 
			&& rtn_name != "BZ2_bz__AssertH__fail" && rtn_name != "outOfMemory" && rtn_name != "__errno_location@plt" && rtn_name != "fallbackSort" && rtn_name != "panic" && rtn_name != "usage")
			{
				continue;
			}
		
			
		//	if(rtn_name=="deregister_tm_clones"||rtn_name=="register_tm_clones" || rtn_name=="mainSort" || rtn_name=="BZ2_blockSort" || rtn_name=="compressStream" ||  rtn_name=="compress" ||  rtn_name=="addFlagsFromEnvVar" || rtn_name=="main" || rtn_name=="BZ2_bzCompressInit" || rtn_name=="copy_input_until_stop" || rtn_name=="handle_compress" || rtn_name=="BZ2_bzCompress" || rtn_name=="BZ2_bzWriteOpen"  ) 
		//	{
		//		continue;
		//	}
			if (isElementExistInMap(itr->first, reorderd_rtn_map) && !reorderd_rtn_map[itr->first].empty()){
				std::cout << "Reorder " << rtn_name << ":" << endl;
				reorderd = reorder(itr->second,reorderd_rtn_map[itr->first]);
				if (reorderd.empty()) {
					std::cout << "Reorder is empty." << endl;
					continue;
				}
				char disasm_buf[2048];
				std::cout << "Original translated:" << endl;
				for (auto itt = itr->second.begin(); itt != itr->second.end(); itt++) {
					xed_format_context(XED_SYNTAX_INTEL, &(itt->data), disasm_buf, 2048, static_cast<UINT64>(itt->addr), 0, 0);
					std::cout << "0x" << hex << itt->addr << ": " << disasm_buf;
					if (itt->target_addr != 0) {
						std::cout << "     orig_targ: 0x" << hex << itt->target_addr << endl;
					}
					else {
						std::cout << endl;
					}
				}
				std::cout << "Reorderd translated:" << endl;
				for (auto itt = reorderd.begin(); itt != reorderd.end(); itt++) {
					xed_format_context(XED_SYNTAX_INTEL, &(itt->data), disasm_buf, 2048, static_cast<UINT64>(itt->addr), 0, 0);
					std::cout << "0x" << hex << itt->addr << ": " << disasm_buf;
					if (itt->target_addr != 0) {
						std::cout << "     new orig_targ: 0x" << hex << itt->target_addr << endl;
					}
					else {
						std::cout << endl;
					}
				}
				itr->second.clear();
				itr->second = reorderd;
			}
			std::cout << "Inserting " << rtn_name << " into instr_map and translated_rtn." << endl;
			translated_rtn[translated_rtn_num].rtn_addr = itr->first;
			translated_rtn[translated_rtn_num].rtn_size = rtn_addr_to_rtn_size[itr->first];
			translated_rtn[translated_rtn_num].instr_map_entry = num_of_instr_map_entries;
			translated_rtn[translated_rtn_num].isSafeForReplacedProbe = true;
			for (auto it = itr->second.begin(); it != itr->second.end(); it++) {
				if (it->target_addr != (ADDRINT)0) {
					rc = add_new_instr_entry(&(it->data), it->addr, it->size, it->target_addr);
				}
				else {
					rc = add_new_instr_entry(&(it->data), it->addr, it->size);
				}
				if (rc < 0) {
					cerr << "ERROR: failed during instructon translation." << endl;
					translated_rtn[translated_rtn_num].instr_map_entry = -1;
					return rc;
				}
			}
			translated_rtn_num++;
			std::cout << "Done inserting." << endl;
		}
	}
	return 0;
}


/***************************/
/* int copy_instrs_to_tc() */
/***************************/
int copy_instrs_to_tc()
{
	int cursor = 0;

	for (int i=0; i < num_of_instr_map_entries; i++) {

	  if ((ADDRINT)&tc[cursor] != instr_map[i].new_ins_addr) {
		  cerr << "ERROR: Non-matching instruction addresses: " << hex << (ADDRINT)&tc[cursor] << " vs. " << instr_map[i].new_ins_addr << endl;
	      return -1;
	  }	  

	  memcpy(&tc[cursor], &instr_map[i].encoded_ins, instr_map[i].size);

	  cursor += instr_map[i].size;
	}

	return 0;
}


/*************************************/
/* void commit_translated_routines() */
/*************************************/
inline void commit_translated_routines() 
{
	// Commit the translated functions: 
	// Go over the candidate functions and replace the original ones by their new successfully translated ones:

	for (int i=0; i < translated_rtn_num; i++) {

		//replace function by new function in tc
	
		if (translated_rtn[i].instr_map_entry >= 0) {
				    
			if (translated_rtn[i].rtn_size > MAX_PROBE_JUMP_INSTR_BYTES && translated_rtn[i].isSafeForReplacedProbe) {						

				RTN rtn = RTN_FindByAddress(translated_rtn[i].rtn_addr);

				//debug print:				
				if (rtn == RTN_Invalid()) {
					cerr << "committing rtN: Unknown";
				} else {
					cerr << "committing rtN: " << RTN_Name(rtn);
				}
				cerr << " from: 0x" << hex << RTN_Address(rtn) << " to: 0x" << hex << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl;

						
				if (RTN_IsSafeForProbedReplacement(rtn)) {

					AFUNPTR origFptr = RTN_ReplaceProbed(rtn,  (AFUNPTR)instr_map[translated_rtn[i].instr_map_entry].new_ins_addr);							

					if (origFptr == NULL) {
						cerr << "RTN_ReplaceProbed failed.";
					} else {
						cerr << "RTN_ReplaceProbed succeeded. ";
					}
					cerr << " orig routine addr: 0x" << hex << translated_rtn[i].rtn_addr
							<< " replacement routine addr: 0x" << hex << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl;	

					dump_instr_from_mem ((ADDRINT *)translated_rtn[i].rtn_addr, translated_rtn[i].rtn_addr);												
				}												
			}
		}
	}
}


/****************************/
/* allocate_and_init_memory */
/****************************/ 
int allocate_and_init_memory(IMG img) 
{
	// Calculate size of executable sections and allocate required memory:
	//
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {   
		if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
			continue;


		if (!lowest_sec_addr || lowest_sec_addr > SEC_Address(sec))
			lowest_sec_addr = SEC_Address(sec);

		if (highest_sec_addr < SEC_Address(sec) + SEC_Size(sec))
			highest_sec_addr = SEC_Address(sec) + SEC_Size(sec);

		// need to avouid using RTN_Open as it is expensive...
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {		

			if (rtn == RTN_Invalid())
				continue;

			max_ins_count += RTN_NumIns  (rtn);
			max_rtn_count++;
		}
	}

	max_ins_count *= 4; // estimating that the num of instrs of the inlined functions will not exceed the total nunmber of the entire code.
	
	// Allocate memory for the instr map needed to fix all branch targets in translated routines:
	instr_map = (instr_map_t *)calloc(max_ins_count, sizeof(instr_map_t));
	if (instr_map == NULL) {
		perror("calloc");
		return -1;
	}


	// Allocate memory for the array of candidate routines containing inlineable function calls:
	// Need to estimate size of inlined routines.. ???
	translated_rtn = (translated_rtn_t *)calloc(max_rtn_count, sizeof(translated_rtn_t));
	if (translated_rtn == NULL) {
		perror("calloc");
		return -1;
	}


	// get a page size in the system:
	int pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize == -1) {
      perror("sysconf");
	  return -1;
	}

	ADDRINT text_size = (highest_sec_addr - lowest_sec_addr) * 2 + pagesize * 4;

    int tclen = 2 * text_size + pagesize * 4;   // need a better estimate???

	// Allocate the needed tc with RW+EXEC permissions and is not located in an address that is more than 32bits afar:		
	char * addr = (char *) mmap(NULL, tclen, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if ((ADDRINT) addr == 0xffffffffffffffff) {
		cerr << "failed to allocate tc" << endl;
        return -1;
	}
	
	tc = (char *)addr;
	return 0;
}
