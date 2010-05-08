#define USE_DANGEROUS_FUNCTIONS

#include <windows.h>

#define USE_STANDARD_FILE_FUNCTIONS

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <allins.hpp>
#include <diskio.hpp>
#include <entry.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <strlist.hpp>
#include <dbg.hpp>

#include <fstream>
#include <string>
#include <cstdio>
#include <strstream>
#include <list>
#include <vector>
#include <algorithm>
#include <iterator>

template<typename S, typename T>
std::string read(S (*f)(char* buffer, T size))
{
	char buffer[200];

	f(buffer, sizeof(buffer));

	return buffer;
}

template<typename S, typename T, typename U, typename V>
std::string read2(S (*f)(U p1, V p2, char* buffer, T size), U p1, V p2)
{
	char buffer[200];

	f(p1, p2, buffer, sizeof(buffer));

	return buffer;
}

class Instruction;

class Offset
{
private:
	ea_t offset;

	std::vector<std::string> getExtraLines(unsigned int type) const
	{
		std::vector<std::string> extraLines;

		char buffer[1000];

		unsigned int cline = 0;

		while (ExtraGet(offset, type + cline, buffer, sizeof(buffer)))
		{
			extraLines.push_back(buffer);

			cline++;
		}

		return extraLines;
	}

public:
	Offset(ea_t offset) : offset(offset) { }

	ea_t getAddress() const { return offset; }

	bool isEnabled() const { return ::isEnabled(offset); }

	// Read ASCII

	// Read Unicode

	uchar getByte() const { return get_byte(offset); }

	void setByte(uchar value) const { patch_byte(offset, value); refresh_idaview_anyway(); }

	ushort getWord() const { return get_word(offset); }

	void setWord(ushort value) const { patch_word(offset, value); refresh_idaview_anyway(); }

	ulong get3Byte() const { return get_3byte(offset); }

	ulong getDword() const { return get_long(offset); }

	void setDword(ulong value) const { patch_long(offset, value); refresh_idaview_anyway(); }

	ulonglong getQword() const { return get_qword(offset); }

	uchar getOriginalByte() const { return get_original_byte(offset); }

	ushort getOriginalWord() const { return get_original_word(offset); }

	ulong getOriginalDword() const { return get_original_long(offset); }

	bool isHead() const { return ::isHead(getFlags()); }

	bool isTail() const { return ::isTail(getFlags()); }

	bool isNotTail() const { return ::isNotTail(getFlags()); }

	bool isCode() const { return ::isCode(getFlags()); }

	bool isData() const { return ::isData(getFlags()); }

	bool isUnknown() const { return ::isUnknown(getFlags()); }

	bool isFlow() const { return ::isFlow(getFlags()); }

	void doByte(unsigned int len) const { ::doByte(offset, len); }

	void doWord(unsigned int len) const { ::doWord(offset, len); }

	void doDword(unsigned int len) const { ::doDwrd(offset, len); }

	void doQword(unsigned int len) const { ::doQwrd(offset, len); }

	void doOword(unsigned int len) const { ::doOwrd(offset, len); }

	void doTByte(unsigned int len) const { ::doTbyt(offset, len); }

	void doFloat(unsigned int len) const { ::doFloat(offset, len); }

	void doDouble(unsigned int len) const { ::doDouble(offset, len); }

	void doPackedReal(unsigned int len) const { ::doPackReal(offset, len); }

	void doAscii(unsigned int len) const { ::doASCI(offset, len); }

	void doThreeByte(unsigned int len) const { ::do3byte(offset, len); }

	bool isByte() const { return ::isByte(offset); }

	bool isWord() const { return ::isWord(offset); }

	bool isDword() const { return ::isDwrd(offset); }

	bool isQword() const { return ::isQwrd(offset); }

	bool isOword() const { return ::isOwrd(offset); }

	bool isTByte() const { return ::isTbyt(offset); }

	bool isFloat() const { return ::isFloat(offset); }

	bool isDouble() const { return ::isDouble(offset); }

	bool isPackedReal() const { return ::isPackReal(offset); }

	bool isAscii() const { return ::isASCII(offset); }

	bool isThreeByte() const { ::is3byte(offset); }

	flags_t getFlags() const { return ::getFlags(offset); }

	bool hasExtraLines() const { return hasExtra(getFlags()); }

	bool hasComment() const { return has_cmt(getFlags()); }

	bool hasReferences() const { return hasRef(getFlags()); }

	std::string getName() const { return read2(&get_name, BADADDR, offset); }

	void setName(const std::string& name) const { set_name(offset, name.c_str()); refresh_idaview_anyway(); }

	bool hasName() const { return has_name(getFlags()); }

	bool hasDummyName() const { return has_dummy_name(getFlags()); }

	bool hasAutoName() const { return has_auto_name(getFlags()); }

	bool hasUserName() const { return has_user_name(getFlags()); }

	bool hasAnyName() const { return has_any_name(getFlags()); }

	bool isFunctionStart() const { return isFunc(getFlags()); }

	bool isInsideFunction() const { return get_func(offset) != 0; }

	std::string getComment() const { return read2(&get_cmt, offset, false); }

	std::string getRepeatableComment() const { return read2(&get_cmt, offset, true); }

	std::vector<std::string> getAnteriorLines() const { return getExtraLines(E_PREV); }

	std::vector<std::string> getPosteriorLines() const { return getExtraLines(E_NEXT); }

	bool hasIncomingCodeReferences() const
	{
		return get_first_cref_to(offset) != BADADDR;
	}

	unsigned int countIncomingCodeReferences() const
	{
		unsigned int incomingCodeReferences = 0;

		ea_t curr = get_first_cref_to(offset);

		while (curr != BADADDR)
		{
			++incomingCodeReferences;
			curr = get_next_cref_to(offset, curr);
		}

		return incomingCodeReferences;
	}

	std::vector<Offset> getIncomingCodeReferences() const
	{
		std::vector<Offset> incomingCodeReferences;

		ea_t curr = get_first_cref_to(offset);

		while (curr != BADADDR)
		{
			incomingCodeReferences.push_back(Offset(curr));
			curr = get_next_cref_to(offset, curr);
		}

		return incomingCodeReferences;
	}

	std::vector<Offset> getIncomingDataReferences() const
	{
		std::vector<Offset> incomingDataReferences;

		ea_t curr = get_first_dref_to(offset);

		while (curr != BADADDR)
		{
			incomingDataReferences.push_back(Offset(curr));
			curr = get_next_dref_to(offset, curr);
		}

		return incomingDataReferences;
	}

	std::vector<Offset> getOutgoingDataReferences() const
	{
		std::vector<Offset> outgoingDataReferences;

		ea_t curr = get_first_dref_from(offset);

		while (curr != BADADDR)
		{
			outgoingDataReferences.push_back(Offset(curr));
			curr = get_next_dref_from(offset, curr);
		}

		return outgoingDataReferences;
	}

	std::vector<Offset> getOutgoingCodeReferences() const
	{
		std::vector<Offset> outgoingCodeReferences;

		ea_t curr = get_first_cref_from(offset);

		while (curr != BADADDR)
		{
			outgoingCodeReferences.push_back(curr);
			curr = get_next_cref_from(offset, curr);
		}

		return outgoingCodeReferences;
	}

};

bool operator<(const Offset& lhs, const Offset& rhs)
{
	return lhs.getAddress() < rhs.getAddress();
}

class Instruction
{
private:
	Offset offset;

public:
	Instruction(Offset offset) : offset(offset) { }

	Offset getOffset() { return offset; }
};

class Function
{
private:
	func_t* function;

public:
	Function(func_t* function) : function(function) { }

	std::string getName() const { char buffer[200] = {0}; return get_func_name(function->startEA, buffer, sizeof(buffer)); }

	void setName(const std::string& name) const { getAddress().setName(name); }

	Offset getAddress() const { return Offset(function->startEA); }

	std::string getComment() const { return get_func_cmt(function, false); }

	void setComment(const std::string& comment) const { set_func_cmt(function, comment.c_str(), false); }

	std::string getRepeatableComment() const { return get_func_cmt(function, true); }

	void setRepeatableComment(const std::string& comment) const { set_func_cmt(function, comment.c_str(), true); }

	bool containsOffset(const Offset& offset) const { return func_contains(function, offset.getAddress()); }

//	FunctionChunkIterator begin();
//	FunctionChunkIterator end();

//	FunctionChunkIterator begin() const;
//	FunctionChunkIterator end() const;

//	Vector<Instruction> getInstructions() const; 
};

class FunctionIterator : public std::iterator< std::forward_iterator_tag, Function, unsigned int > 
{
private:
	unsigned int index;

public:
	FunctionIterator(unsigned int index) : index(index) { }

	Function begin();
	Function end();

	FunctionIterator& operator++() { ++index; return *this; }
	FunctionIterator operator++(int) { FunctionIterator oldIterator(index); ++index; return oldIterator; }

	Function operator*() { return Function(getn_func(index)); }

	Function* operator->() { return &Function(getn_func(index)); }

	bool operator==(const FunctionIterator& rhs)
	{
		return index == rhs.index;
	}

	bool operator!=(const FunctionIterator& rhs)
	{
		return !(*this == rhs);
	}
};

class InstructionIterator : public std::iterator< std::forward_iterator_tag, Function, unsigned int > 
{
private:
	ea_t offset;

	void nextInstruction()
	{
		do
		{
			offset = next_head(offset, BADADDR);

			if (offset == BADADDR)
			{
				break;
			}

			if (isCode(getFlags(offset)))
			{
				break;
			}

		} while (true);
	}

public:
	InstructionIterator(ea_t offset) : offset(offset) { }

	Instruction begin();
	Instruction end();

	InstructionIterator& operator++()
	{
		nextInstruction();

		return *this;
	}

	InstructionIterator operator++(int)
	{
		InstructionIterator oldIterator(offset);
		
		nextInstruction();
		
		return oldIterator;
	}

	Instruction operator*() { return Instruction(Offset(offset)); }

	Instruction* operator->() { return &Instruction(Offset(offset)); }

	bool operator==(const InstructionIterator& rhs)
	{
		return offset == rhs.offset;
	}

	bool operator!=(const InstructionIterator& rhs)
	{
		return !(*this == rhs);
	}
};

class IdaString
{
private:
	string_info_t str;

public:
	IdaString(unsigned int index)
	{
		get_strlist_item(index, &str);
	}

	Offset getOffset() const { return Offset(str.ea); }

	ea_t getAddress() const { return str.ea; }

	unsigned int getType() const { return str.type; }

	unsigned int getLength() const { return str.length; }
};

class StringListIterator
{
private:
	unsigned int index;

public:
	StringListIterator(unsigned int index) : index(index) { }
};

class StringList
{
public:

	IdaString operator[](unsigned int index)
	{
		return IdaString(index);
	}

	unsigned int size() const { return get_strlist_qty(); }

	StringListIterator begin() { return StringListIterator(0); }
	StringListIterator end() { return StringListIterator(size() - 1); }
};

class Breakpoint
{
private:
	bpt_t breakpoint;
public:
	Breakpoint(const bpt_t& breakpoint) : breakpoint(breakpoint) { }

	ea_t getAddress() { return breakpoint.ea; }
};

class Debugger
{
	public:
		void startProcess(const std::string& path, const std::string& arguments, const std::string& directory)
		{
			start_process(path.c_str(), arguments.c_str(), directory.c_str());
		}

		void setBreakpoint(ea_t offset, bool wait = false)
		{
			if (wait)
			{
				add_bpt(offset);
			}
			else
			{
				request_add_bpt(offset);
			}
		}

		void removeBreakpoint(ea_t offset)
		{
			request_del_bpt(offset);
		}

		void addEventCallback(hook_cb_t* callback, void* userData)
		{
			hook_to_notification_point(HT_DBG, callback, userData);
		}

		void removeEventCallback(hook_cb_t* callback, void* userData)
		{
			unhook_from_notification_point(HT_DBG, callback, userData);
		}

		void suspendProcess(bool wait = false)
		{
			if (wait)
			{
				suspend_process();
			}
			else
			{
				request_suspend_process();
			}
		}

		bool isSuspended() const
		{
			return get_process_state() == DSTATE_SUSP;
		}

		bool isActive() const
		{
			return dbg != 0 && get_process_state() != DSTATE_NOTASK;
		}

		bool flush()
		{
			return run_requests();
		}

		void resumeProcess(bool wait = false)
		{
			if (wait)
			{
				continue_process();
			}
			else
			{
				request_continue_process();
			}
		}

		unsigned int getNumberOfBreakpoints()
		{
			return get_bpt_qty();
		}

		Breakpoint getBreakpoint(unsigned int index)
		{
			bpt_t breakpoint;

			getn_bpt(index, &breakpoint);

			return Breakpoint(breakpoint);
		}

		static const unsigned int EVENT_BREAKPOINT;
		static const unsigned int EVENT_PROCESS_EXIT;
		static const unsigned int EVENT_PROCESS_SUSPENDED;
};

const unsigned int Debugger::EVENT_BREAKPOINT = dbg_bpt;
const unsigned int Debugger::EVENT_PROCESS_EXIT = dbg_process_exit;
const unsigned int Debugger::EVENT_PROCESS_SUSPENDED = dbg_suspend_process;

class IdaFile
{
	public:
		FunctionIterator begin() { return FunctionIterator(0); }
		FunctionIterator end() { return FunctionIterator(getNumberOfFunctions()); }

		FunctionIterator begin() const { return FunctionIterator(0); }
		FunctionIterator end() const { return FunctionIterator(getNumberOfFunctions()); }

		Function operator[](unsigned int index) { return Function(getn_func(index)); }

		InstructionIterator beginInstructions() { return InstructionIterator(0); }
		InstructionIterator endInstructions() { return InstructionIterator(BADADDR); }

		std::string getName() const { return read(&get_root_filename); }

		std::string getInputfilePath() const { return read(&get_input_file_path); }

		Offset getScreenEA() const { return Offset(get_screen_ea()); }

		unsigned int getNumberOfFunctions() const { return get_func_qty(); }

		unsigned int getCRC32() const { return retrieve_input_file_crc32(); }

		std::string getProcessorName() const { return inf.procName; }

		unsigned short getFileType() const { return inf.filetype; }

		Offset getStartOffset() const { return Offset(inf.beginEA); }

		Offset getFirstOffset() const { return Offset(inf.minEA); }

		Offset getLastOffset() const { return Offset(inf.maxEA); }

		unsigned int getNumberOfEntryPoints() const { return get_entry_qty(); }

		std::vector<Offset> getEntryPoints() const { std::vector<Offset> entryPoints; for (unsigned int i=0;i<getNumberOfEntryPoints(); i++) { entryPoints.push_back(Offset(get_entry(get_entry_ordinal(i)))); } return entryPoints; }

		StringList getStringList() const { return StringList(); }

		Debugger getDebugger() const { return Debugger(); }
};

void printX(const Function& f)
{
	msg("%s\n", f.getName().c_str());
}

bool hasOtherReferences(Offset offset, const std::vector<Offset>& offsets)
{
	for (std::vector<Offset>::const_iterator Iter = offsets.begin(); Iter != offsets.end(); ++Iter)
	{
		if (Iter->getAddress() != offset.getAddress())
		{
			return true;
		}
	}

	return false;
}

void iterateBasicBlocks(const InstructionIterator& begin, const InstructionIterator& end, void (*callback)(const Offset&))
{
	Offset lastOffset = 0;

	bool init = true;

	for (InstructionIterator Iter = begin; Iter != end; ++Iter)
	{
		// We place breakpoints on instructions that meet the following conditions:
		//
		// - They must have incoming code references that do not come from the previous instruction
		// OR
		// - The previous offset must have outgoing code references to more than the current offset

		Offset currentOffset = Iter->getOffset();

		std::vector<Offset> currentReferences = currentOffset.getIncomingCodeReferences();

		std::vector<Offset> lastOutgoingReferences = lastOffset.getOutgoingCodeReferences();

		if (currentOffset.isCode() && get_func(currentOffset.getAddress()) && (init || get_func(currentOffset.getAddress())->startEA == currentOffset.getAddress() || hasOtherReferences(lastOffset, currentReferences) || hasOtherReferences(currentOffset, lastOutgoingReferences)))
		{
			init = false;

			callback(currentOffset);
		}

		lastOffset = currentOffset;
	}
}

void iterateBasicBlocks(void (*callback)(const Offset&))
{
	IdaFile file;
	iterateBasicBlocks(file.beginInstructions(), file.endInstructions(), callback);
}

