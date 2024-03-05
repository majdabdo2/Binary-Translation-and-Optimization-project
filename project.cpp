/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

 /*! @file
  *  This file contains an ISA-portable PIN tool for counting dynamic instructions
  */

#include "pin.H"
#include <iostream>
#include <map>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include "rtn-translation.cpp"
using std::cerr;
using std::endl;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */
const UINT64 _ONE_= 1;

/* ===================================================================== */
/* Helper functions */
/* ===================================================================== */

std::vector<std::string> split(std::string const& str, const char delim)
{
    std::istringstream split(str);
    std::vector<std::string> tokens;
    for (std::string each; std::getline(split, each, delim); tokens.push_back(each));
    return tokens;
}

size_t find_str_in_vector(const std::vector<std::string>& vector_of_str, std::string str)
{   
    size_t i = 0;
    for (; i < vector_of_str.size(); i++) {
        if (vector_of_str[i] == str) {
            return i;
        }
    }
    return i;
}

ADDRINT hex_in_string_to_addrint(const std::string& str) {
    ADDRINT address;
    std::istringstream addr_in_hex(str);
    addr_in_hex >> std::hex >> address;
    return address;
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool prints out the number of dynamic instructions executed to stderr.\n"
        "\n";

    cerr << KNOB_BASE::StringKnobSummary();

    cerr << endl;

    return -1;
}

/* ===================================================================== */

/* ===================================================================== */
/* Analysis functions */
/* ===================================================================== */
VOID countInstruction(UINT64* ptr_ins) {
    (*ptr_ins)++;
}
VOID countRoutineCalls(UINT64* ptr_call) {
    (*ptr_call)++;
}

VOID count_rtn_call(ADDRINT ptr_ins) {
    (ptr_ins)++;
}

VOID countBranchIteration(ADDRINT loop_address) {
    loop_map[loop_address].countSeen[loop_map[loop_address].countLoopInvoked]++;
    loop_map[loop_address].totalCountSeen++;
}
VOID countBranchInvocation(UINT64* ptr_invoked, std::vector<UINT64>* ptr_countSeenArray) {
    (*ptr_invoked)++;
    (*ptr_countSeenArray).push_back(0);
}


VOID Rtninscount(uint32_t* cnt, uint32_t amount)
{
    (*cnt)+=amount;
}

VOID Branchcount(ADDRINT branchAddress, bool isTaken)
{
    branches[branchAddress].count_seen++;
    branches[branchAddress].count_taken += isTaken ? 1 : 0;
}



VOID Callercount(ADDRINT targetAddress, ADDRINT sourceAddress)
{
     caller_count[targetAddress][sourceAddress]++;
}




/* ===================================================================== */

/*
* Instruction instrument function:
*   For every instruction in the trace, the function will insert analysis docount functions.
*   Per routine, the function will insert instruction counter and routine calls counter.
*   In addition, the function will instrument loops. As jumps backwards symbolise iteration of a loop.
*   Also, count invocation when loops exit, and collect additional info to be analyze at FINI().
*   
*/


void profileInstructionsAndLoops(INS instruction, void* userData) {
    RTN routine = INS_Rtn(instruction);
    if (!RTN_Valid(routine)) {
        return;
    }

    ADDRINT routineAddress = RTN_Address(routine);
    IMG image = IMG_FindByAddress(routineAddress);

    if (IMG_Valid(image) && IMG_IsMainExecutable(image)) {
        rtn routineObject(RTN_Name(routine));

        if (!isRoutineExist(routineAddress)) {
            routine_map.emplace(routineAddress, routineObject);
        }

        if (routineAddress == INS_Address(instruction)) {
            INS_InsertCall(instruction, IPOINT_BEFORE, (AFUNPTR) countInstruction, IARG_PTR,
                           &(routine_map[routineAddress].call_count), IARG_END);
        }

        INS_InsertCall(instruction, IPOINT_BEFORE, (AFUNPTR) countInstruction, IARG_PTR,
                       &(routine_map[routineAddress].ins_count), IARG_END);

        if (INS_IsDirectControlFlow(instruction) && !INS_IsCall(instruction) && !INS_IsSyscall(instruction)) {
            ADDRINT myself = INS_Address(instruction);
            ADDRINT target = INS_DirectControlFlowTargetAddress(instruction);

            if (target < myself) {
                loop loopObject(target, routineAddress);

                if (!isLoopExist(myself)) {
                    loop_map.emplace(myself, loopObject);
                    loop_map[myself].countSeen.push_back(0);
                }

                if (INS_Category(instruction) == XED_CATEGORY_COND_BR) {
                    /* Handles 1st type loops, with single conditional jump backwards. */
                    if (INS_IsValidForIpointTakenBranch(instruction)) {
                        INS_InsertCall(instruction, IPOINT_TAKEN_BRANCH, (AFUNPTR) countBranchIteration, IARG_ADDRINT,
                                       myself, IARG_END);
                    }

                    if (INS_IsValidForIpointAfter(instruction)) {
                        INS_InsertCall(instruction, IPOINT_AFTER, (AFUNPTR) countBranchInvocation, IARG_PTR,
                                       &(loop_map[myself].countLoopInvoked), IARG_PTR, &(loop_map[myself].countSeen),
                                       IARG_END);
                    }
                } else if (INS_Category(instruction) == XED_CATEGORY_UNCOND_BR) {
                    /* Handles 2nd type loops, with a single conditional jump forward
                        and a single unconditional jump backwards to the address of myself.
                    */
                    INS_InsertCall(instruction, IPOINT_BEFORE, (AFUNPTR) countBranchIteration, IARG_ADDRINT, myself,
                                   IARG_END);
                    RTN_Open(routine);
                    INS start = RTN_InsHead(routine);

                    for (; INS_Valid(start) && INS_Address(start) < target; start = INS_Next(start)) { ;
                    }

                    for (INS cond_jump = start; INS_Valid(cond_jump); cond_jump = INS_Next(cond_jump)) {
                        if (INS_IsDirectControlFlow(cond_jump) && !INS_IsCall(cond_jump) &&
                            INS_Category(cond_jump) == XED_CATEGORY_COND_BR
                            && INS_DirectControlFlowTargetAddress(cond_jump) > myself) {
                            if (INS_IsValidForIpointTakenBranch(cond_jump)) {
                                INS_InsertCall(cond_jump, IPOINT_TAKEN_BRANCH, (AFUNPTR) countBranchInvocation,
                                               IARG_PTR, &(loop_map[myself].countLoopInvoked), IARG_PTR,
                                               &(loop_map[myself].countSeen), IARG_END);
                            }
                            break;
                        }
                    }
                    RTN_Close(routine);
                }
            }
        }
    }
}






void analyzeTraceData(TRACE traceData, void* userData) {
    RTN routine = TRACE_Rtn(traceData);
    if (!RTN_Valid(routine)) {
        return;
    }

    ADDRINT routineAddress = RTN_Address(routine);
    IMG img = IMG_FindByAddress(routineAddress);
    if(!IMG_Valid(img) || !IMG_IsMainExecutable(img)) return;

    for (BBL basicBlock = TRACE_BblHead(traceData); BBL_Valid(basicBlock); basicBlock = BBL_Next(basicBlock)) {
//        INS firstInstruction = BBL_InsHead(basicBlock);
        ADDRINT headAddress = INS_Address(BBL_InsHead(basicBlock));
        INS lastInstruction = BBL_InsTail(basicBlock);
        ADDRINT tailAddress = INS_Address(lastInstruction);

        // Update block mappings
        bbl_map[headAddress].endAddress = tailAddress;
        bbl_map[headAddress].rtn_address = routineAddress;

        if(!INS_IsDirectControlFlow(lastInstruction)) continue;

        ADDRINT jumpTarget = INS_DirectControlFlowTargetAddress(lastInstruction);

        if (jumpTarget > tailAddress) {
            // Update jump information
            bbl_map[headAddress].jumpAddress = jumpTarget;

            if (INS_HasFallThrough(lastInstruction)) {
                if (INS_IsValidForIpointTakenBranch(lastInstruction)) {
                    INS_InsertCall(lastInstruction, IPOINT_TAKEN_BRANCH, (AFUNPTR)countInstruction, IARG_PTR, &(bbl_map[headAddress].count_taken), IARG_END);
                }

                INS_InsertCall(lastInstruction, IPOINT_BEFORE, (AFUNPTR)countInstruction, IARG_PTR, &(bbl_map[headAddress].count_total), IARG_END);

                INS nextInstruction = INS_Next(lastInstruction);

                if (INS_Valid(nextInstruction)) {
                    bbl_map[headAddress].fall_address = INS_Address(nextInstruction);
                }
            }
        }

    }

}







VOID analyzeTraceData2(RTN rtn_arg, VOID* v) {
    if(!RTN_Valid(rtn_arg)) return;
    ADDRINT rtn_address = RTN_Address(rtn_arg);
    IMG img = IMG_FindByAddress(rtn_address);
    if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)) {
        return;
    }
    RTN_Open(rtn_arg);
    for (INS ins = RTN_InsHead(rtn_arg); INS_Valid(ins); ins = INS_Next(ins)) {
        if(!INS_IsDirectControlFlow(ins)) continue;
        ADDRINT target = INS_DirectControlFlowTargetAddress(ins);
        if ((target > INS_Address(ins) ) && INS_HasFallThrough(ins)){
            INS end_fall = INS_Next(ins);
            for (; INS_Valid(end_fall) &&  INS_Valid(INS_Next(end_fall)) && (INS_Address(INS_Next(end_fall)) < target); end_fall = INS_Next(end_fall)) {
            }
            if (INS_Valid(end_fall)) {
                /* end_fall is the ins at the end of a fall_through. */
                cond_br_address_to_end_of_fallthrough[INS_Address(ins)] = INS_Address(end_fall);
            }
            else {
                std::cout << endl;
            }

        }

    }
    RTN_Close(rtn_arg);

}








std::vector <std::pair<ADDRINT, bbl>> reordered_rtn(std::map<ADDRINT, bbl> preordered) {
    std::vector <std::pair<ADDRINT, bbl>> result;
    std::vector <std::pair<ADDRINT, bbl>> blind_spots_to_be_filled;
    std::vector <ADDRINT> merged_bbl_to_be_erased;
    std::map<ADDRINT, bool> visited;
    for (auto it = preordered.begin(); it != preordered.end(); it++) {
        if ((std::find(merged_bbl_to_be_erased.begin(), merged_bbl_to_be_erased.end(), it->first) !=
             merged_bbl_to_be_erased.end())) {
            continue;
        }
        auto it_combine = std::next(it);
        for (; it_combine != preordered.end(); it_combine++) {
            if ((std::find(merged_bbl_to_be_erased.begin(), merged_bbl_to_be_erased.end(), it->first) !=
                 merged_bbl_to_be_erased.end())) {
                continue;
            } else if (it->first == it_combine->first) {
                continue;
            } else if (it_combine->first > it->first) {
                if (it->second.merge(it_combine->second)) {
                    merged_bbl_to_be_erased.push_back(it_combine->first);
                }
            } else if (it_combine->second.merge(it->second)) {
                merged_bbl_to_be_erased.push_back(it->first);
            }
        }
    }
    for (auto it = merged_bbl_to_be_erased.begin(); it != merged_bbl_to_be_erased.end(); it++) {
        //std::cout << "THIS WAS DELETED: 0x" << std::hex << *it << endl;
        preordered.erase(*it);
    }
   for (auto it = preordered.begin(); std::next(it) != preordered.end(); it++) {
        auto next = std::next(it);
        
     /*   ADDRINT next_ins_address;
        INS ins;
        INS ins2;
       if(next != preordered.end())
       {
        
       RTN rtn_arg = RTN_FindByAddress(it->second.rtn_address);
       if(RTN_Valid(rtn_arg))
       { 
        RTN_Open(rtn_arg);
		 next_ins_address=INS_Address(INS_Next(RTN_InsHead(rtn_arg)));
		 ins = RTN_InsHead(rtn_arg);
		for (; INS_Valid(INS_Next(ins)) && next_ins_address!=next->first  ; ins = INS_Next(ins))
		{
			if(INS_Address(ins)==it->second.tail_address)
			{
				ins2=INS_Next(ins);
			}
			next_ins_address=INS_Address(INS_Next(ins));
		}
		if ((INS_Address(ins2)) < next->first) {
			bbl possible_missed_cold_code(INS_Address(ins));
			possible_missed_cold_code.rtn_address = it->second.rtn_address;
			blind_spots_to_be_filled.push_back(std::pair<ADDRINT, bbl>(INS_Address(ins2), possible_missed_cold_code));//get ins . get adress!!!
	 	}
		 RTN_Close(rtn_arg);
		}   
	}else
	{
		
	   RTN rtn_arg = RTN_FindByAddress(it->second.rtn_address);
       if(RTN_Valid(rtn_arg))
       { 
        RTN_Open(rtn_arg);
		 next_ins_address=INS_Address(INS_Next(RTN_InsHead(rtn_arg)));
		 ins = RTN_InsHead(rtn_arg);
		for (; INS_Valid(INS_Next(ins)) ; ins = INS_Next(ins))
		{
			if(INS_Address(ins)==it->second.tail_address)
			{
				ins2=INS_Next(ins);
			}
			next_ins_address=INS_Address(INS_Next(ins));
		}
		if ((INS_Address(ins2)) < next->first) {
			bbl possible_missed_cold_code(INS_Address(ins));
			possible_missed_cold_code.rtn_address = it->second.rtn_address;
			blind_spots_to_be_filled.push_back(std::pair<ADDRINT, bbl>(INS_Address(ins2), possible_missed_cold_code));//get ins . get adress!!!
	 	}
		 RTN_Close(rtn_arg);
		}   
		
	}*/

    /*    ADDRINT next_ins_address;
        INS ins;
        INS ins2;
        RTN rtn_arg = RTN_FindByAddress(it->second.rtn_address);
        if(RTN_Valid(rtn_arg))
        {
			    RTN_Open(rtn_arg);
		
        if(next != preordered.end())
        {

            

                ins = RTN_InsHead(rtn_arg);
                next_ins_address=INS_Address(INS_Next(ins));
                for (; INS_Rtn(INS_Next(ins))==rtn_arg && next_ins_address!=next->first  ; ins = INS_Next(ins))
                {
                    if(INS_Address(ins)==it->second.endAddress)
                    {
                        ins2=INS_Next(ins);
                    }
                    next_ins_address=INS_Address(INS_Next(ins));
                }
                if(next_ins_address==next->first) {
                        bbl possible_missed_cold_code(INS_Address(ins));
                        possible_missed_cold_code.rtn_address = it->second.rtn_address;
                        blind_spots_to_be_filled.push_back(std::pair<ADDRINT, bbl>(INS_Address(ins2),
                                                                                   possible_missed_cold_code));//get ins . get adress!!!
                }
            
        }
        else {
            

                ins = RTN_InsHead(rtn_arg);
                next_ins_address = INS_Address(INS_Next(ins));
                for (; INS_Rtn(INS_Next(ins)) == rtn_arg && next_ins_address != next->first; ins = INS_Next(ins)) {
                    if (INS_Address(ins) == it->second.endAddress) {
                        ins2 = INS_Next(ins);
                    }
                    next_ins_address = INS_Address(INS_Next(ins));
                }
                if (INS_Rtn(INS_Next(ins)) != rtn_arg && INS_Address(ins) !=it->second.endAddress) {

                    bbl possible_missed_cold_code(INS_Address(ins));
                    possible_missed_cold_code.rtn_address = it->second.rtn_address;
                    blind_spots_to_be_filled.push_back(std::pair<ADDRINT, bbl>(INS_Address(ins2),
                                                                               possible_missed_cold_code));
                }
        }
        RTN_Close(rtn_arg);
	}*/


           if ((it->second.endAddress + 1) < next->first) {
            bbl possible_missed_cold_code(next->first - _ONE_);
            possible_missed_cold_code.rtn_address = it->second.rtn_address;
            blind_spots_to_be_filled.push_back(std::pair<ADDRINT, bbl>(it->second.endAddress + _ONE_, possible_missed_cold_code));
        }
   }
    
    
    
    for (auto it = blind_spots_to_be_filled.begin(); it != blind_spots_to_be_filled.end(); it++) {
        preordered[it->first] = it->second;
    }
    for (auto it = preordered.begin(); it != preordered.end(); it++) {
        visited[it->first] = false;
    }
    
    
   
    
    //abed new
    //create a map <jump target, jumpCallerAddres> , in other words, maps the target to the one above it
    std::map<ADDRINT,std::pair<ADDRINT,int>> jmpTargetToJmpCaller;
    for(auto currbbl : preordered){
		//bbl tmpp=preordered[currbbl.second.first];
		ADDRINT jump = currbbl.second.jumpAddress;
		if (!(jump != NO_DIRECT_CONTROL_FLOW && preordered.find(jump)!= preordered.end())) {
			continue;
		}

		
		int notTaken= (currbbl.second.count_total - currbbl.second.count_taken);
		int taken=(currbbl.second.count_taken);
		ADDRINT falltmp = currbbl.second.fall_address;

		
		ADDRINT jmpTarget= notTaken > taken? currbbl.second.fall_address : currbbl.second.jumpAddress;
		int priority= notTaken > taken? notTaken : taken;
		
		if (falltmp == NO_DIRECT_CONTROL_FLOW ) {
			jmpTarget=currbbl.second.jumpAddress;
			priority=taken;
		}
		
		
			if(jmpTargetToJmpCaller.find(jmpTarget)==jmpTargetToJmpCaller.end()){
				jmpTargetToJmpCaller[jmpTarget] = {currbbl.first, priority};
			}
			else{
				//ADDRINT source=jmpTargetToJmpCaller[jmpTarget].first;
				int p = jmpTargetToJmpCaller[jmpTarget].second;
				if(p < priority){
					jmpTargetToJmpCaller[jmpTarget]={currbbl.first, priority};
				}
			}
			
		}
		//create a reveresed map, mapping <addrint, addrint>, maps the bbl to the bll that should be next
		std::map<ADDRINT,ADDRINT> meAndMyNext;
		for(auto currbbl2 : jmpTargetToJmpCaller){
			meAndMyNext[currbbl2.second.first] = currbbl2.first;
			}
			
			
			
		std::map<ADDRINT,bool> alreadyVisited;
		std::vector <std::pair<ADDRINT, bbl>> tmpres;
		auto preorderedit= preordered.begin();
				//order all bbls in the tmpres and return it
		while(tmpres.size() < preordered.size() ){
			if( preorderedit == preordered.end()){
				preorderedit=preordered.begin();
				continue;
			}
			//getFather
			//if father visited, continue;
			if(alreadyVisited.find(preorderedit->first) != alreadyVisited.end() && alreadyVisited[preorderedit->first] == true ){
				preorderedit++;
				continue;
			}
			
			//set father to visited
			ADDRINT father=preorderedit->first;
			alreadyVisited[preorderedit->first] = true;
			tmpres.push_back( { father, preordered[father]} );
			if(meAndMyNext.find(father)!= meAndMyNext.end() && alreadyVisited[meAndMyNext[father]]==false ){
				preorderedit = preordered.find(meAndMyNext[father]);
			}
			else{
				preorderedit=preordered.find(father);
				preorderedit++;
			}		
		}
		return tmpres;
	   
      
}






VOID Fini(INT32 code, VOID* v) {
    std::ofstream output_file("reorder-bbl-count.csv", std::ofstream::out);
    std::vector<std::pair<ADDRINT, bbl>> vec;
    std::map<ADDRINT, std::map<ADDRINT, bbl>> rtn_reorder_map;
    for (auto itr = bbl_map.begin(); itr != bbl_map.end(); ++itr) {
        ADDRINT rtn_addr = itr->second.rtn_address;
        if (!isElementExistInMap(rtn_addr, rtn_reorder_map)) {
            rtn_reorder_map[rtn_addr].clear();
        }
        rtn_reorder_map[rtn_addr][itr->first] = itr->second;
    }
    std::vector<std::pair<ADDRINT, rtn>> rtn_array_sorted_by_ins_count;
    for (auto itr = routine_map.begin(); itr != routine_map.end(); ++itr) {
        rtn_array_sorted_by_ins_count.push_back(*itr);
    }
    sort(rtn_array_sorted_by_ins_count.begin(), rtn_array_sorted_by_ins_count.end(),
        [=](std::pair<ADDRINT, rtn>& a, std::pair<ADDRINT, rtn>& b) {return a.second.ins_count > b.second.ins_count; });
        
      
    for(auto rtn_it = rtn_array_sorted_by_ins_count.begin(); rtn_it != rtn_array_sorted_by_ins_count.end(); rtn_it++){
        ADDRINT dominate_caller_addr = rtn_it->second.dominate_call();
        output_file << rtn_it->second.name << ",0x" << std::hex << rtn_it->first << ","
            << std::dec << rtn_it->second.ins_count << "," << rtn_it->second.call_count << ","
            << rtn_it->second.is_recursive << ",0x" << std::hex << dominate_caller_addr << ","
            << std::dec << rtn_it->second.to_translate
            << ",bbl_list_start,";
        std::vector <std::pair<ADDRINT, bbl>> reordered;
        
        if (isElementExistInMap(rtn_it->first, rtn_reorder_map) && !rtn_reorder_map[rtn_it->first].empty()) {
            reordered = reordered_rtn(rtn_reorder_map[rtn_it->first]);
        }
       
        for (size_t i = 0; i < reordered.size(); i++) {
      
            output_file << "0x" << std::hex << reordered[i].first << ",0x" << std::hex << reordered[i].second.endAddress  << ",";
        }
        
        output_file << "bbl_list_end,cond_end_list_start,";
        for (size_t i = 0; i < reordered.size(); i++) {
            ADDRINT possible_cond_br = reordered[i].second.endAddress;
            if (isElementExistInMap(possible_cond_br, cond_br_address_to_end_of_fallthrough)) {
                output_file << "0x" << std::hex << possible_cond_br << ",0x" << std::hex <<
                    cond_br_address_to_end_of_fallthrough[possible_cond_br] << ",";
            }
        }
        
        output_file << "cond_end_list_end" << endl;
        
    }
    
    cond_br_address_to_end_of_fallthrough.clear();
    
    
	ADDRINT rtn_address;

    ofstream to2("inline-rtn-count.csv");
    if (!to2)
    {
        cerr << "ERROR, can't open file: " << "inline-rtn-count.csv" << endl;
        return;
    }

    ADDRINT max_caller = 0;
    UINT64 max_calls = 0;

    for (auto &pair : caller_count)
    {
        max_caller = 0;
        max_calls = 0;

        for (auto &iter : pair.second)
        {
            UINT64 current_count = iter.second;

            if ((current_count <= HOT_CALL_MIN_COUNT) ||
                ((float)current_count / (float)rtn_call_counts[pair.first] < HOT_CALL))
            {
                continue;
            }

            if (max_calls < current_count)
            {
                max_caller = iter.first ;
                max_calls = current_count;
            }
        }

        if (max_calls > 0)
        {
            rtn_address = pair.first;

            to2 << "0x" << std::hex << (rtn_address )
                << ", " << std::dec << rtn_ins_counts[rtn_address]
                << ", " << std::dec << rtn_call_counts[rtn_address]
                << ", " << "0x" << std::hex << max_caller
                << ", " << std::dec << max_calls
                << endl;
        }
    }

    to2.close();


    
    
    
   
    
}







bool get_reorderd_rtn_map(IMG main_img) {
    std::ifstream input_file("reorder-bbl-count.csv");
    if (!input_file.is_open()) {
        /* Failed to open. */
        return false;
    }
    std::string line;
    while (std::getline(input_file, line)) {
        std::vector<std::string> temp_line = split(line, ',');
        ADDRINT rtn_address = hex_in_string_to_addrint(temp_line[1]);
        IMG img = IMG_FindByAddress(rtn_address);
        if (IMG_Valid(img)) {
            if (IMG_IsMainExecutable(img)) {
                if (!isElementExistInMap(rtn_address, reorderd_rtn_map)) {
                    reorderd_rtn_map[rtn_address].clear();
                }
                size_t start_bbl_list = find_str_in_vector(temp_line, "bbl_list_start");
                size_t end_bbl_list = find_str_in_vector(temp_line, "bbl_list_end");
                size_t start_cond_end_list = find_str_in_vector(temp_line, "cond_end_list_start");
                size_t end_cond_end_list = find_str_in_vector(temp_line, "cond_end_list_end");
                for (size_t i = start_bbl_list + 1; i < end_bbl_list; i+= 2) {
                    ADDRINT start_bbl_address = hex_in_string_to_addrint(temp_line[i]);
                    ADDRINT end_bbl_address = hex_in_string_to_addrint(temp_line[i + 1]);
                    reorderd_rtn_map[rtn_address].push_back(std::pair<ADDRINT, ADDRINT>(start_bbl_address, end_bbl_address));
                }
                for (size_t i = start_cond_end_list + 1; i < end_cond_end_list; i += 2) {
                    ADDRINT cond_br_address = hex_in_string_to_addrint(temp_line[i]);
                    ADDRINT end_fall_address = hex_in_string_to_addrint(temp_line[i + 1]);
                    cond_br_address_to_end_of_fallthrough[cond_br_address] = end_fall_address;
                }

            }
        }
    }
    input_file.close();
   
    return true;
}
/* ===================================================================== */




/* ============================================ */
/* Main translation routine                     */
/* ============================================ */

VOID ImageLoad(IMG img, VOID* v)
{
    // debug print of all images' instructions
    //dump_all_image_instrs(img);

    // Step 0: Check the image and the CPU:
    if (!IMG_IsMainExecutable(img))
        return;
   
   
    if (!get_reorderd_rtn_map(img)) {
        return;
    }
  
    int rc = 0;

    // step 2: Check size of executable sections and allocate required memory:	
    rc = allocate_and_init_memory(img);
    if (rc < 0)
        return;

    cout << "after memory allocation" << endl;


    // Step 3: go over all routines and identify candidate routines and copy their code into the instr map IR:
    //rc = find_candidate_rtns_for_translation(img);
    rc = find_candidate_rtns_for_translation(img);
    if (rc < 0)
        return;

    cout << "after identifying candidate routines" << endl;

    // Step 4: Chaining - calculate direct branch and call instructions to point to corresponding target instr entries:
    rc = chain_all_direct_br_and_call_target_entries();
    if (rc < 0)
        return;

    cout << "after calculate direct br targets" << endl;

    // Step 5: fix rip-based, direct branch and direct call displacements:
    rc = fix_instructions_displacements();
    if (rc < 0)
        return;

    cout << "after fix instructions displacements" << endl;


    // Step 6: write translated routines to new tc:
    rc = copy_instrs_to_tc();
    if (rc < 0)
        return;

    cout << "after write all new instructions to memory tc" << endl;

    if (KnobDumpTranslatedCode) {
        cerr << "Translation Cache dump:" << endl;
        dump_tc();  // dump the entire tc

        cerr << endl << "instructions map dump:" << endl;
        dump_entire_instr_map();     // dump all translated instructions in map_instr
    }


    // Step 7: Commit the translated routines:
    //Go over the candidate functions and replace the original ones by their new successfully translated ones:
    if (!KnobDoNotCommitTranslatedCode) {
        commit_translated_routines();
        cout << "after commit translated routines" << endl;
    }
}





void MyTraceFunction(TRACE trace, void* userData)
{
    BBL bbl = TRACE_BblHead(trace);
    INS insTail = BBL_InsTail(bbl);
    ADDRINT insTailAddr = INS_Address(insTail);
    RTN currRtn = TRACE_Rtn(trace);
    ADDRINT targetAddr;
    IMG img;

    if (!RTN_Valid(currRtn))
    {
        return;
    }

    string rtnName = RTN_Name(currRtn);
    ADDRINT currRtnAddr = RTN_Address(currRtn);

    for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        insTail = BBL_InsTail(bbl);
        insTailAddr = INS_Address(insTail);
        currRtn = RTN_FindByAddress(insTailAddr);

        img = IMG_FindByAddress(insTailAddr);
        if (!IMG_IsMainExecutable(img))
        {
            continue;
        }

        // Add the instruction count in the BBL to the routine instruction count.
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)Rtninscount,
                       IARG_FAST_ANALYSIS_CALL,
                       IARG_PTR, &rtn_ins_counts[currRtnAddr],
                       IARG_UINT32, BBL_NumIns(bbl), IARG_END);

        if (!RTN_Valid(currRtn))
        {
            continue;
        }

        if (INS_IsBranch(insTail))
        {
            if (INS_IsDirectBranch(insTail))
            {
                targetAddr = INS_DirectControlFlowTargetAddress(insTail);

                branches[insTailAddr].rtn_addr = RTN_Address(currRtn);
                branches[insTailAddr].rtn_name = rtnName;
                branches[insTailAddr].target_addr = targetAddr;

                INS_InsertCall(insTail, IPOINT_BEFORE, (AFUNPTR)Branchcount,
                               IARG_ADDRINT, insTailAddr,
                               IARG_BRANCH_TAKEN, IARG_END);
            }
        }

        if (INS_IsDirectCall(insTail)) {
            // Get the target address of the call
            targetAddr = INS_DirectControlFlowTargetAddress(insTail);
            
            caller_count[targetAddr][insTailAddr] = 0;

            INS_InsertCall(insTail, IPOINT_BEFORE, (AFUNPTR)Callercount,
                           IARG_ADDRINT, targetAddr,
                           IARG_ADDRINT, insTailAddr,
                           IARG_END);
            }
        }
}









VOID instrument_routine(RTN rtn, VOID* v)
{
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)count_rtn_call,
                   IARG_ADDRINT, RTN_Address(rtn), IARG_END);
    RTN_Close(rtn);
}




















/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
int main(int argc, char* argv[])
{

    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }
    if (KnobInst) {
      
      
        IMG_AddInstrumentFunction(ImageLoad, 0);

        PIN_StartProgramProbed();
    }
    else if (KnobProf) {
        /* JIT Mode */
        
        INS_AddInstrumentFunction(profileInstructionsAndLoops, 0);
        TRACE_AddInstrumentFunction(analyzeTraceData, 0);
        RTN_AddInstrumentFunction(analyzeTraceData2, 0);
        
        
        
        
      
        
        TRACE_AddInstrumentFunction(MyTraceFunction, 0);
        RTN_AddInstrumentFunction(instrument_routine, 0);
        
        
        
          

        PIN_AddFiniFunction(Fini, 0);
        // Never returns
        PIN_StartProgram();
    }
    else {
        PIN_StartProgram();
    }
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
