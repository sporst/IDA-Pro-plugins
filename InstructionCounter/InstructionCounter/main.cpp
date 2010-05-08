/*
* IDA Pro InstructionCounter plugin 1.02
*
* Copyright (c) 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
*/

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <allins.hpp>

#include <string>
#include <map>
#include <vector>
#include <iterator>
#include <algorithm>
#include <numeric>
#include <cstdio>

bool osort(const std::pair<std::string, unsigned int>& lhs, const std::pair<std::string, unsigned int>& rhs)
{
	return lhs.second > rhs.second;
}

unsigned int osum(unsigned int acc, const std::pair<std::string, unsigned int>& lhs)
{
	return acc + lhs.second;
}

int IDAP_init(void)
{
	return PLUGIN_KEEP;
}

void IDAP_term(void)
{
}

void IDAP_run(int arg)
{
	std::map<std::string, unsigned int> opcodes;
	
	msg("Counting...\n");
	
	for (unsigned int f=0;f<get_func_qty();f++)
	{
		func_t* function = getn_func(f);
		
		for (ea_t addr = function->startEA; addr < function->endEA; ++addr)
		{
			flags_t flags = getFlags(addr);
			
			if (isHead(flags) && isCode(flags))
			{
				char mnem[MAXSTR];
//				ua_mnem(addr, mnem, sizeof(mnem) - 1);
				generate_disasm_line(addr, mnem, sizeof(mnem) - 1);
				tag_remove(mnem, mnem, 0);
				
				std::string opcode(mnem);
				
				std::string::size_type pos = opcode.find("  ");
				
				if (pos != std::string::npos)
					opcode = opcode.substr(0, pos);
				
//				msg("%08X - %s\n", addr, cmd.get_canon_mnem());
				
				std::map<std::string, unsigned int>::iterator Iter = opcodes.find(opcode);
				
				if (Iter == opcodes.end())
				{
					opcodes.insert(std::make_pair(opcode, 1));
				}
				else
				{
					Iter->second++;
				}
			}
		}	
	}
	
	std::vector<std::pair<std::string, unsigned int> > sop;
	std::copy(opcodes.begin(), opcodes.end(), std::back_inserter(sop));
	
	std::sort(sop.begin(), sop.end(), osort);
	
	unsigned int total = std::accumulate(sop.begin(), sop.end(), 0, osum);
	
	char* file = askfile_cv(1, "", "Output file", 0);
	
	FILE* of = qfopen(file, "w+");
	
	if (of)
	{
		#if IDP_INTERFACE_VERSION <= 75
		
		qfprintf(of, "Opcode distribution of file: %s\n", get_input_file_path());
		
		#elif IDP_INTERFACE_VERSION >= 76
		
		char input_path[QMAXPATH];
		get_input_file_path(input_path, sizeof(input_path));

		qfprintf(of, "Opcode distribution of file: %s\n", input_path);
		
		#endif
		
		qfprintf(of, "Total opcodes: %i\n\n", total);
		
		unsigned int i=1;
		
		for (std::vector<std::pair<std::string, unsigned int> >::iterator Iter = sop.begin(); Iter != sop.end(); ++Iter)
		{
			float perc = (100.0f * Iter->second) / total;
			
			qfprintf(of, "%04i. %06i %8.2f%%      %s\n", i++, Iter->second, perc, Iter->first.c_str());
		}
		
		qfclose(of);
		
		msg("Done\n");
	}
	else
	{
		msg("Error: Couldn't open file\n");
	}
	
}

// There isn't much use for these yet, but I set them anyway.
char IDAP_comment[] 	= "Creates opcode distribution lists";
char IDAP_help[] 	= "InstructionCounter";

// The name of the plug-in displayed in the Edit->Plugins menu. It 
// can be overridden in the user's plugins.cfg file.
char IDAP_name[] 	= "InstructionCounter";

// The hot-key the user can use to run your plug-in.
char IDAP_hotkey[] 	= "Alt-C";

// The all-important exported PLUGIN object
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,	// IDA version plug-in is written for
	0,		// Flags (see below)
	IDAP_init,	// Initialisation function
	IDAP_term,	// Clean-up function
	IDAP_run,	// Main plug-in body
	IDAP_comment,	// Comment - unused
	IDAP_help,	// As above - unused
	IDAP_name,	// Plug-in name shown in 
			// Edit->Plugins menu
	IDAP_hotkey	// Hot key to run the plug-in
};
