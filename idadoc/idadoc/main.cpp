/*
* idadoc 1.00
*
* Copyright (c) 2006 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
*/

#define USE_STANDARD_FILE_FUNCTIONS

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <allins.hpp>
#include <diskio.hpp>

#include <fstream>
#include <string>
#include <cstdio>
#include <strstream>
#include <list>
#include <vector>
#include <algorithm>

// Error codes
enum BlockErrors
{
	NO_BLOCK_ERROR = 0,
	BLOCK_NOT_FOUND,
	INVALID_BLOCK
};

enum ParseErrors
{
	NO_PARSE_ERROR = 0,
	NO_PARAMETERS_BLOCK,
	INVALID_PARAMETERS_BLOCK,
	INVALID_LONGDESC_BLOCK,
	NO_FUNCTION_BLOCK,
	INVALID_FUNCTION_BLOCK
}; 

enum FunctionParseError
{
	NO_FP_ERROR = 0,
	PARAMETER_ERROR
};

// Some string constants
const std::string PH_FILENAME = "%FILENAME%";
const std::string PH_FUNCTION_START = "%FUNCTIONSTART%";
const std::string PH_FUNCTION_END = "%FUNCTIONEND%";
const std::string PH_LONGDESC_START = "%LONGDESCSTART%";
const std::string PH_LONGDESC_END = "%LONGDESCEND%";
const std::string PH_PARAM_START = "%PARAMSTART%";
const std::string PH_PARAM_END = "%PARAMEND%";
const std::string PH_PARAM_NAME = "%PARAMNAME%";
const std::string PH_PARAM_DESC = "%PARAMDESC%";
const std::string PH_LONGDESC_ADDR = "%LONGDESCADDR%";
const std::string PH_LONGDESC_LINE = "%LONGDESCLINE%";
const std::string PH_DIRECTIVES_START = "%STARTDIRECTIVES%";
const std::string PH_DIRECTIVES_END = "%ENDDIRECTIVES%";

// Holds information for replacing special characters in output files
struct Replacement
{
	std::string rep;
	std::string with;
};
	
// Holds information read from template files
struct TemplateFile
{
	std::string header;
	std::string function;
	std::string footer;
	std::string paramblock;
	std::string ldblock;
	std::list<Replacement> replacements;
};

/**
* Stores name and description of a parameter
**/
struct Param
{
	std::string name;
	std::string desc;
};

// Stores anterior lines
struct ExtraLine
{
	ea_t ea;
	std::string line;
};

// Stores information that was read from a function
struct FunctionComment
{
	std::string description;
	std::list<ExtraLine> longdesc;
	std::vector<Param> params;
	std::string ret;
	std::list<std::string> references;
};

int IDAP_init(void)
{
	return PLUGIN_KEEP;
}

void IDAP_term(void)
{
}

/**
* Tests whether a file exists or not
* @param filename Name of the file
* @return A flag that say whether the file exists
**/
bool fileExists(const std::string& filename)
{
	std::ifstream file(filename.c_str());
	return file != 0;
}

/**
* Returns the file size of a file
* @param file Filestream
* @return Length of the file
**/
unsigned int getFileSize(std::ifstream& file)
{
	file.seekg(0, std::ios::end);
	unsigned int length = file.tellg();
	file.seekg(0, std::ios::beg);
	
	return length;
}

/**
* Reads an ASCII file into a string
* @param The name of the file
* @param output The output string that will be filled by the function
* @return Returns true or false depending on whether reading the file was successful
**/
bool readTextFile(const std::string& filename, std::string& output)
{
	std::ifstream file(filename.c_str(), std::ios_base::binary);
	
	if (!file)
	{
		return false;
	}
	
	unsigned int length = getFileSize(file);
	
	char* data = new char[length + 1];
	data[length] = 0;
	
	file.read(data, length);
	
	if (!file)
	{
		return false;
	}
	
	output = data;
	
	delete[] data;
	
	return true;
}

/**
* Attempts to locate and extract a block starting with one string and ending with another
* @param code Code of the template file
* @param out Output string where the extracted string will be stored
* @param start String that starts a block
* @param end String that ends a block
* @return An error code that says if the function was successful.
**/
BlockErrors findBlock(const std::string& code, std::string& out, const std::string& start, const std::string& end)
{
	std::string::size_type fstart = code.find(start);
	
	if (fstart == std::string::npos)
	{
		return INVALID_BLOCK;
	}
	
	std::string::size_type fend = code.find(end);
	
	if (fend == std::string::npos)
	{
		return INVALID_BLOCK;
	}
	
	if (end > start)
	{
		return INVALID_BLOCK;
	}
	
	out = code.substr(fstart + start.length(), fend - fstart - start.length());
	
	return NO_BLOCK_ERROR;
}

/**
* Attempts to find the function block
* @param templcode Code of the template file
* @param tf Template file structure where the parsing results are stored
* @return An error code that says if the function was successful.
**/
BlockErrors findFunctionBlock(const std::string& templcode, TemplateFile& tf)
{
	return findBlock(templcode, tf.function, PH_FUNCTION_START, PH_FUNCTION_END);
}

/**
* Attempts to find the long Parameters block
* @param templcode Code of the template file
* @param tf Template file structure where the parsing results are stored
* @return An error code that says if the function was successful.
**/
BlockErrors findParamBlock(const std::string& templcode, TemplateFile& tf)
{
	return findBlock(templcode, tf.paramblock, PH_PARAM_START, PH_PARAM_END);
}

/**
* Attempts to find the long description block
* @param templcode Code of the template file
* @param tf Template file structure where the parsing results are stored
* @return An error code that says if the function was successful.
**/
BlockErrors findLongDescriptionBlock(const std::string& templcode, TemplateFile& tf)
{
	return findBlock(templcode, tf.ldblock, PH_LONGDESC_START, PH_LONGDESC_END);
}

/**
* Parses replace directives of the form "old new". Note that the "replace"
* keyword must be removed from parameter directive already.
* @param directive Directive to parse
* @param rep List of replacements found directive will be added to
* @return True or false depending on whether parsing was succesful or not
**/
bool parseReplaceDirective(const std::string& directive, std::list<Replacement>& rep)
{
	// Locate the space between the two directive parameters
	std::string::size_type pos = directive.find_first_not_of(" ");
	pos = directive.find_first_of(" ");

	if (pos == std::string::npos)
	{
		return false;
	}
	
	// Tokenize the string and store it
	Replacement r;
	r.rep = directive.substr(0, pos);
	r.with = directive.substr(pos + 1);
	
	rep.push_back(r);
	
	return true;
}

bool fnl(const Replacement& r)
{
	return r.rep == "%NEWLINE%";
}

std::string findNewline(const std::list<Replacement>& rep)
{
	std::list<Replacement>::const_iterator Iter = std::find_if(rep.begin(), rep.end(), fnl);
	
	return Iter != rep.end() ? Iter->with : "";
}

/**
* Parses newline directives of the form "foo". Note that the "newline"
* keyword must be removed from parameter directive already.
* @param directive Directive to parse
* @param rep List of replacements found directive will be added to
* @return True or false depending on whether parsing was succesful or not
**/
bool parseNewlineDirective(const std::string& directive, std::list<Replacement>& rep)
{
	Replacement r;
	r.rep = "%NEWLINE%";
	r.with = directive;
	rep.push_back(r);
	
	return true;
}

/**
* Parses directives
* @param directive Line containing a directive
* @param tf TemplateFile object where found information is stored
* @return True or false depending on whether parsing was succesful or not
**/
bool parseDirective(const std::string& directive, TemplateFile& tf)
{
	if (directive.find("replace ") == 0)
	{
		// Handle replace directive
		return parseReplaceDirective(directive.substr(8), tf.replacements);
	}
	else if (directive.find("newline ") == 0)
	{
		return parseNewlineDirective(directive.substr(8), tf.replacements);
	}
	
	return false;
}

/**
* Removes a single trailing CR/LF character from a string
* @param line The line to sanitize
**/
void sanitizeLine(std::string& line)
{
	if (line.length() > 0)
	{
		switch(line[line.length() - 1])
		{
			case 0x0A:
			case 0x0D:
			line = line.substr(0, line.length() - 1);
		}
	}
}

/**
* Locates and parses directives from the template file
* @param templcode Code of the template file
* @param tf TemplateFile object where found information is stored
* @return True or false depending on whether parsing was succesful or not
**/
bool handleDirectives(const std::string& templcode, TemplateFile& tf)
{
	std::string directives;
	
	// An error occured
	if (findBlock(templcode, directives, PH_DIRECTIVES_START, PH_DIRECTIVES_END) != NO_BLOCK_ERROR)
	{
		return false;
	}
	
	// Handle the individual lines of the block
	std::strstream ss;
	
	ss << directives;
	
	std::string s;
	
	while (std::getline(ss, s))
	{
		sanitizeLine(s);
		parseDirective(s, tf);
	}
	
	return true;
}

/**
* Attempts to parse a specified template file and checks for some
* necessary patterns.
* @param templcode Code of the template file
* @param tf Template file structure where the parsing results are stored
* @return An error code that says if the function was successful.
**/
ParseErrors parseTemplateFile(const std::string& templcode, TemplateFile& tf)
{
	// Attempt to locate the parameters block
	switch(findParamBlock(templcode, tf))
	{
		case BLOCK_NOT_FOUND: return NO_PARAMETERS_BLOCK;
		case INVALID_BLOCK: return INVALID_PARAMETERS_BLOCK;
	}
	
	// The long description block is optional
	if (findLongDescriptionBlock(templcode, tf) == INVALID_BLOCK)
	{
		return INVALID_LONGDESC_BLOCK;
	}	
	
	// Attempt to locate the function block
	switch (findFunctionBlock(templcode, tf))
	{
		case BLOCK_NOT_FOUND: return NO_FUNCTION_BLOCK;
		case INVALID_BLOCK: return INVALID_FUNCTION_BLOCK;
	}
	
	// No need to check for validity again
	std::string::size_type fstart = templcode.find(PH_FUNCTION_START);
	std::string::size_type fend = templcode.find(PH_FUNCTION_END);
	
	// Extract header and footer from template code
	tf.header = templcode.substr(0, fstart);
	tf.footer = templcode.substr(fend + PH_FUNCTION_END.length() + 1);
	
	return NO_PARSE_ERROR;
}

/**
* Replaces all occurences of a substring in a string with another string
* @param output String that will be changed
* @param src Substring to be replaced
* @param dest New substring
* @return True if at least one substring was successfully replaced
**/
bool replaceString(std::string& output, const std::string& src, const std::string& dest)
{
	if (src == "")
	{
		return false;
	}
	
	std::string::size_type pos = 0;
	
	bool ret = false;
	
	while ((pos = output.find(src, pos)) != std::string::npos)
	{
		output.replace(pos, src.length(), dest);
		pos += dest.length();
		
		ret = true;
	}
	
	return ret;
}

/**
* Turns an unsigned int into an 8-byte long hex string
* @param x The number to convert
* @return The hex string
**/
std::string int2hex(unsigned int x)
{
	char buffer[9];
	qsnprintf(buffer, 8, "%08X", x, 8);
	
	return buffer;
}

/**
* Parses a line containing a @return command
* @param line Line to parse
* @param ret Output string that contains the return comment
**/
void parseReturnCmd(const std::string& line, std::string& ret)
{
	ret = line.substr(line.find("@return ") + strlen("@return "));
}

/**
* Parses a line containing a @param command
* @param line Line to parse
* @param params List where parsed parameter information will be stored
* @return True if no error occured. False if there's a parsing error.
**/
bool parseParam(const std::string& line, std::vector<Param>& params)
{
	std::string p = line.substr(line.find("@param ") + strlen("@param "));

	// Tokenize further by 
	std::string::size_type pos = p.find(" ");
	
	if (pos != std::string::npos)
	{
		Param param;
		
		param.name = p.substr(0, pos);
		param.desc = p.substr(pos);
		
		params.push_back(param);
		
		return true;
	}
	
	return false;
}

enum ParseState
{
	ParseComment = 0,
	ParseParam,
	ParseReturn
};

/**
* @param function Information about a function
* @param fc Output struct where the found information was stored
* @return An error flag saying what happened in the function
**/
FunctionParseError parseFunctionComment(func_t* function, FunctionComment& fc, const std::string& newline)
{
	// Get the function comment
	std::string cmt = get_func_cmt(function, false);
	
	std::strstream ss;
	
	ss << cmt;
	
	std::string s;
	
	ParseState ps = ParseComment;
	
	// TODO: Multiple lines in return or param commands
	
	// Iterate over all lines in the function comment
	while (std::getline(ss, s))
	{
		sanitizeLine(s);
		
		if (s.find("@param ") == 0)
		{
			ps = ParseParam;
			
			// @param command found
			if (!parseParam(s, fc.params))
			{
				return PARAMETER_ERROR;
			}
		}
		else if (s.find("@return") == 0)
		{
			ps = ParseReturn;
			
			// @return command found
			parseReturnCmd(s, fc.ret);
		}
		else if (ps == ParseComment)
		{
			// Nothing => Normal description line
			if (fc.description.size() != 0) fc.description += newline;
			fc.description += s;
		}
		else if (ps == ParseParam)
		{
			fc.params[fc.params.size() - 1].desc += newline + s;
		}
		else if (ps == ParseReturn)
		{
			fc.ret += newline;
			fc.ret += s;
		}
	}
	
	return NO_FP_ERROR;
}

/**
* Replaces the long description block of a function with actual information
* @param block Code of the function block
* @param ldBlock Code of a long description block
* @param lines List of lines that contain the information
**/
void replaceLongDescBlock(std::string& block, const std::string& ldBlock, const std::list<ExtraLine>& lines)
{
	std::string::size_type beg = block.find(PH_LONGDESC_START);
	std::string::size_type end = block.find(PH_LONGDESC_END);
	
	std::string ret = "";
	
	// Iterates over all lines and adds the extra information to the block
	for (std::list<ExtraLine>::const_iterator Iter = lines.begin(); Iter != lines.end(); ++Iter)
	{
		ret += ldBlock;
		
		replaceString(ret, PH_LONGDESC_ADDR, int2hex(Iter->ea));
		replaceString(ret, PH_LONGDESC_LINE, Iter->line);
	}
	
	block.replace(beg, end + PH_LONGDESC_END.length() - beg, ret);
}

/**
* Replaces the parameter block of a function with actual information
* @param block Code of the function block
* @param ldBlock Code of a long description block
* @param lines List of lines that contain the information
**/
void replaceParamBlock(std::string& block, const std::string& paramBlock, const std::vector<Param>& params)
{
	std::string::size_type beg = block.find(PH_PARAM_START);
	std::string::size_type end = block.find(PH_PARAM_END);
	
	std::string ret = "";
	
	// Iterates over all parameters and adds the extra information to the block
	for (std::vector<Param>::const_iterator Iter = params.begin(); Iter != params.end(); ++Iter)
	{
		ret += paramBlock;
		
		replaceString(ret, PH_PARAM_NAME, Iter->name);
		replaceString(ret, PH_PARAM_DESC, Iter->desc);
	}
	
	block.replace(beg, end + PH_PARAM_END.length() - beg, ret);
}

/**
* Retrieves a a list of the names of all functions that reference a certain function
* @param ea Address of a function
* @return List of references
**/
std::list<std::string> getReferences(ea_t ea)
{
	std::list<std::string> refs;
	
	xrefblk_t xb;
	for ( bool ok=xb.first_to(ea, XREF_ALL); ok; ok=xb.next_to() )
	{
		if (xb.iscode)
		{
			// Get function name
			char fname[MAXSTR + 1];
			get_func_name(xb.from, fname, MAXSTR);
			
			if (std::find(refs.begin(), refs.end(), fname) == refs.end())
			{
				refs.push_back(fname);
			}
		}
		else
		{
			break;
		}
	}
	
	return refs;
}

/**
* Reads all anterior lines you can find between two addresses
* @param beg Start addres
* @param end End address
* @param newline The special newline character from the template file
* @return List of all anterior lines starting with the character @
**/
std::list<ExtraLine> getAnteriorLines(ea_t beg, ea_t end, const std::string& newline)
{
	// TODO: This is going to be tricky when there are function chunks

	std::list<ExtraLine> ldesc;
	char fname[MAXSTR + 1];
	
	// Loop through all addresses in the function
	for (int i=beg;i!=end;i++)
	{
		int cline = 0;
		
		std::string ld;
		
		// Get anterior lines
		while (ExtraGet(i, E_PREV + cline, fname, MAXSTR) != -1)
		{
			// Get the lines starting with @
			if (fname[0] == '@')
			{
				if (ld.size())
				{
					ld += newline;
				}
				
				ld += (fname + 1);
			}
			
			++cline;
		}
		
		// Add only non-empty lines
		if (ld != "")
		{
			ExtraLine el;
			el.ea = i;
			el.line = ld;
			
			ldesc.push_back(el);
		}
	}
	
	return ldesc;
}

/**
* Replaces special characters in a string
* @param str A string with special characters
* @param reps A list of replacement rules
**/
void applyReplacements(std::string& str, const std::list<Replacement>& reps)
{
	for (std::list<Replacement>::const_iterator Iter = reps.begin(); Iter != reps.end(); ++Iter)
	{
		replaceString(str, Iter->rep, Iter->with);
	}
}

/**
* Creates an output block for a function
* @param function Function to be processed
* @param tf Information from the template file that's used to create the function block
* @return The created function block
**/
std::string createBlock(func_t* function, const TemplateFile& tf)
{
	// Get function name
	char fname[MAXSTR + 1];
	get_func_name(function->startEA, fname, MAXSTR);
	
	std::string block = tf.function;
	
	FunctionComment fc;
	
	std::string newline = findNewline(tf.replacements);
	
	// Get information from the function comment
	parseFunctionComment(function, fc, newline);
	
	// Get functions referencing the current function
	fc.references = getReferences(function->startEA);
	
	// Build the long description from the anterior lines
	fc.longdesc = getAnteriorLines(function->startEA, function->endEA, newline);
	
	std::string refs;
	
	unsigned int i=0;
	
	// Add the refs to the block
	for (std::list<std::string>::iterator Iter = fc.references.begin(); Iter != fc.references.end(); ++Iter)
	{
		refs += *Iter;
		
		if (i++ != fc.references.size() - 1) refs += " - ";
	}
	
	std::string startEA = int2hex(function->startEA);
	std::string endEA = int2hex(function->endEA);
	std::string funcname = fname;
	
	//
	applyReplacements(refs, tf.replacements);
	applyReplacements(funcname, tf.replacements);
	applyReplacements(startEA, tf.replacements);
	applyReplacements(endEA, tf.replacements);
	applyReplacements(fc.description, tf.replacements);
	applyReplacements(fc.ret, tf.replacements);
	applyReplacements(fc.ret, tf.replacements);
	
	for (std::list<ExtraLine>::iterator Iter = fc.longdesc.begin(); Iter != fc.longdesc.end(); ++Iter)
	{
		applyReplacements(Iter->line, tf.replacements);
	}
	
	// Replace a bunch of placeholders with actual data
	replaceString(block, "%REFERENCES%", refs);
	replaceString(block, "%FUNCTIONNAME%", funcname);
	replaceString(block, "%STARTEA%", startEA);
	replaceString(block, "%ENDEA%", endEA);
	replaceString(block, "%DESCRIPTION%", fc.description);
	replaceString(block, "%RETURNDESC%", fc.ret);
	
	replaceParamBlock(block, tf.paramblock, fc.params);
	replaceLongDescBlock(block, tf.ldblock, fc.longdesc);
			
	return block;
}

/**
* Writes the generated information to a file
* @param filename Name of the file to write to.
* @param tf Information from the template file
* @param blocks List of function blocks
* @return True if writing was successful; false otherwise.
**/
bool writeOutputFile(const std::string& filename, const TemplateFile& tf, const std::list<std::string>& blocks)
{
	// Make sure we're not overwriting an important file
	if (fileExists(filename))
	{
		if (askyn_cv(1, "Do you really want to overwrite the file?", 0) != 1)
		{
			return false;
		}
	}
	
	std::ofstream file(filename.c_str(), std::ios::binary);
	
	if (!file)
	{
		return false;
	}
	
	// Write the header
	file.write(tf.header.c_str(), tf.header.length());
	
	if (!file)
	{
		return false;
	}
	
	// Write the function blocks
	for (std::list<std::string>::const_iterator Iter = blocks.begin(); Iter != blocks.end(); ++Iter)
	{
		file.write(Iter->c_str(), Iter->length());
		
		if (!file)
		{
			return false;
		}
	}
	
	// Write the footer
	file.write(tf.footer.c_str(), tf.footer.length());
	
	if (!file)
	{
		return false;
	}
	
	return true;
}

/**
* Removes the directives block from the template file code
* @param templcode Code of the template file
**/
void removeDirectivesBlock(std::string& templcode)
{
	std::string::size_type beg = templcode.find(PH_DIRECTIVES_START);
	std::string::size_type end = templcode.find(PH_DIRECTIVES_END);
	
	if (beg != std::string::npos && end != std::string::npos && beg < end)
	{
		templcode.replace(beg, end - beg + PH_DIRECTIVES_END.length(), "");
	}
}

void IDAP_run(int arg)
{
	extern bool tests();
	tests();

	msg("Starting...\n");
	
	// Get plugin directory
	const char* pluginDirectory = idadir("plugins");
	
	const char* filename = askfile_cv(1, "*.tpl", "Please select a template file", 0);
	
	if (!filename)
	{
		msg("Cancelled\n");
		return;
	}
	
	std::string templfile = filename;

	// Read template file
	if (!fileExists(templfile))
	{
		msg("Error: Couldn't open template file.\n");
		return;
	}
	
	std::string templcode;
	if (!readTextFile(templfile, templcode))
	{
		msg("Error: Couldn't read template file.\n");
		return;
	}
	
	// Extract function template
	TemplateFile tf;
	
	// Get name of the input file
	char input_path[QMAXPATH];
	get_input_file_path(input_path, sizeof(input_path));
	
	handleDirectives(templcode, tf);
	removeDirectivesBlock(templcode);
	
	std::string inputFile = input_path;
	applyReplacements(inputFile, tf.replacements);
	
	// Insert the name of the IDB input file into the output file
	replaceString(templcode, PH_FILENAME, inputFile);
	
	// Check whether the template file is valid
	switch (parseTemplateFile(templcode, tf))
	{
		case NO_PARAMETERS_BLOCK:
		{
			msg("Error: No parameters block found.\n");
			return;
		}
		case INVALID_PARAMETERS_BLOCK:
		{
			msg("Error: Invalid parameters block found.\n");
			return;
		}
		case NO_FUNCTION_BLOCK:
		{
			msg("Error: No functions block found.\n");
			return;
		}
		case INVALID_FUNCTION_BLOCK:
		{
			msg("Error: Invalid functions block found.\n");
			return;
		}
	}
	
	std::list<std::string> fblocks;
	
	// Iterate over all functions and extract necessary information
	for (unsigned int f=0;f<get_func_qty();f++)
	{
		func_t* function = getn_func(f);
		
		// Get function comments
		msg("%d\n", f);
		char* fcmt = get_func_cmt(function, false);
		
		if (fcmt)
		{
			// Turn function comments into output code
			
			std::string fblock = createBlock(function, tf);
			
			if (fblock != "")
			{
				fblocks.push_back(fblock);
			}
		}
	}
	
	filename = askfile_cv(1, "*.*", "Please choose a file", 0);
	
	if (!filename)
	{
		return;
	}
	
	// Write output file
	if (!writeOutputFile(filename, tf, fblocks))
	{
		return;
	}
	
	msg("Done\n");
}

// There isn't much use for these yet, but I set them anyway.
char IDAP_comment[] 	= "Creates documentation";
char IDAP_help[] 	= "idadoc";

// The name of the plug-in displayed in the Edit->Plugins menu. It 
// can be overridden in the user's plugins.cfg file.
char IDAP_name[] 	= "idadoc";

// The hot-key the user can use to run your plug-in.
char IDAP_hotkey[] 	= "";

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
