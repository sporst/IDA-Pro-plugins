#define USE_DANGEROUS_FUNCTIONS
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>

#include <map>
#include <sstream>
#include <algorithm>
#include <iomanip>

#include "hotch.hpp"
#include "helpers.hpp"

/**
* Sets a breakpoint at the given offset.
**/
void setBreakpoint(const Offset& offset)
{
//	msg("Setting breakpoint on address %08X...\n", offset.getAddress());

	IdaFile file;

	file.getDebugger().setBreakpoint(offset.getAddress(), true);
}

/**
* Sets breakpoints on all basic blocks.
**/
void setBreakpoints()
{
	msg("Setting breakpoints on all basic blocks...\n");

	iterateBasicBlocks(setBreakpoint);
}

/**
* Removes a breakpoint from the given offset.
**/
void removeBreakpoint(const Offset& offset)
{
	IdaFile file;

	file.getDebugger().removeBreakpoint(offset.getAddress());
}

/**
* Removes breakpoints from all basic blocks.
**/
void removeBreakpoints()
{
	iterateBasicBlocks(removeBreakpoint);

	run_requests();
}

/**
* Predicated function that is used to sort times blocks by their total hits.
**/
bool sortByHits(const TimedBlock* lhs, const TimedBlock* rhs)
{
	return lhs->getHits() > rhs->getHits();
}

/**
* Predicated function that is used to sort times blocks by their total time.
**/
bool sortByTime(const TimedBlock* lhs, const TimedBlock* rhs)
{
	return lhs->getTime() > rhs->getTime();
}

/**
* Predicated function that is used to sort times blocks by their average time.
**/
bool sortByAverageTime(const TimedBlock* lhs, const TimedBlock* rhs)
{
	if (lhs->getHits() == 0 || rhs->getHits() == 0)
	{
		return false;
	}

	return (lhs->getTime() / lhs->getHits()) > (rhs->getTime() / rhs->getHits());
}

/**
* Calculates the total time spent on a list of blocks.
**/
time_t totalTime(const std::list<TimedBlock*>& blocks)
{
	time_t tt = 0;

	for (std::list<TimedBlock*>::const_iterator Iter = blocks.begin(); Iter != blocks.end(); ++Iter)
	{
		TimedBlock* bb = *Iter;

		tt += bb->getTime();
	}

	return tt;
}

/**
* Calculates the total number of hits in a list of hits.
**/
unsigned int totalHits(const std::list<TimedBlock*>& blocks)
{
	unsigned int th = 0;

	for (std::list<TimedBlock*>::const_iterator Iter = blocks.begin(); Iter != blocks.end(); ++Iter)
	{
		TimedBlock* bb = *Iter;

		th += bb->getHits();
	}

	return th;
}

/**
* Creates a new <td> cell with the information given in the parameters.
**/
template<typename T>
void createCell(std::ostringstream& ss, T value, const std::string& alignment, const std::string& suffix = "")
{
	ss << "<td style=\"text-align:" << alignment << "\">";
	ss << value << suffix;
	ss << "</td>";
}

/**
* Creates a new <tr> tag with the class determined by the counter.
**/
void createRow(std::ostringstream& ss, unsigned int counter)
{
	ss << "<tr class=\"";
	ss << (counter % 2 ? "evenLine" : "oddLine");
	ss << "\">";
}

/**
* Generates a HTML table that is used to display function events sorted by a given sorter.
**/
std::string generateFunctionTable(std::list<TimedBlock*>& functionResults, bool (*sorter)(const TimedBlock*, const TimedBlock*))
{
	functionResults.sort(sorter);

	time_t totalTime = ::totalTime(functionResults);
	unsigned int totalHits = ::totalHits(functionResults);

	std::ostringstream ss;

	unsigned int counter = 1;

	for (std::list<TimedBlock*>::const_iterator Iter = functionResults.begin(); Iter != functionResults.end(); ++Iter)
	{
		TimedBlock* bb = *Iter;

		if (bb->getHits() == 0)
		{
			// We can not break here because it's not guaranteed that useful events come later,
			// depending on the exact sort algorithm.
			continue;
		}

		createRow(ss, counter);

		createCell(ss, counter, "center");
		createCell(ss, bb->getParentFunction().getName(), "left");

		ss << "<td style=\"text-align:center\">";
		ss << "0x" << std::uppercase << std::hex << bb->getParentFunction().getAddress().getAddress() << std::nouppercase;
		ss << "</td>";

		ss << std::dec << std::fixed << std::setprecision(2);
		createCell(ss, bb->getTime(), "right", " ms");

		createCell(ss, 100.0 * bb->getTime() / totalTime, "right", " %");
		createCell(ss, bb->getHits(), "right");
		createCell(ss, 100.0 * bb->getHits() / totalHits, "right", " %");
		createCell(ss, 1.0 * bb->getTime() / bb->getHits(), "right", " ms");

		ss << "</tr>";

		++counter;
	}

	return ss.str();
}

/**
* Creates a list of all events.
**/
std::string generateEventsTable(const std::list<Event>& events)
{
	std::ostringstream ss;

	unsigned int counter = 1;

	char timeBuffer[100] = {0};
	char timeline[26];

	for (std::list<Event>::const_iterator Iter = events.begin(); Iter != events.end(); ++Iter)
	{
		createRow(ss, counter);

		createCell(ss, counter, "center");

		_timeb eventTime = Iter->getTime();
		ctime_s( timeline, 26, & ( eventTime.time ) );

		sprintf(timeBuffer, "%.8s.%hu", timeline + 11, eventTime.millitm);

		createCell(ss, timeBuffer, "center");

		ss << "<td style=\"text-align:center\">";
		ss << "0x" << std::uppercase << std::hex << Iter->getAddress().getAddress() << std::dec << std::nouppercase;
		ss << "</td>";

		createCell(ss, Iter->getParentFunction().getName(), "left");

		++counter;
	}

	return ss.str();
}

/**
* Generates a HTML table that is used to display block events sorted by a given sorter.
**/
std::string generateBlocksTable(std::list<TimedBlock*>& blockResults, bool (*sorter)(const TimedBlock*, const TimedBlock*))
{
	blockResults.sort(sorter);

	time_t totalTime = ::totalTime(blockResults);
	unsigned int totalHits = ::totalHits(blockResults);

	std::ostringstream ss;

	unsigned int counter = 1;

	for (std::list<TimedBlock*>::const_iterator Iter = blockResults.begin(); Iter != blockResults.end(); ++Iter)
	{
		TimedBlock* bb = *Iter;

		// Skip the blocks that were not hit.
		if (bb->getHits() == 0)
		{
			// We can not break here because it's not guaranteed that useful events come later,
			// depending on the exact sort algorithm.
			continue;
		}

		createRow(ss, counter);

		createCell(ss, counter, "center");

		ss << "<td style=\"text-align:center\">";
		ss << "0x" << std::uppercase << std::hex << bb->getOffset().getAddress() << std::nouppercase;
		ss << "</td>";

		ss << std::dec << std::fixed << std::setprecision(2);
		createCell(ss, bb->getParentFunction().getName(), "left");
		createCell(ss, bb->getTime(), "right", " ms");

		createCell(ss, 100.0 * bb->getTime() / totalTime, "right", " %");
		createCell(ss, bb->getHits(), "right");
		createCell(ss, 100.0 * bb->getHits() / totalHits, "right", " %");

		ss << "</tr>";

		++counter;
	}

	return ss.str();
}

/**
* Checks whether a block was hit or not.
**/
bool wasHit(const TimedBlock* block)
{
	return block->getHits() != 0;
}

/**
* Counts the number of blocks in a list of blocks that were hit.
**/
unsigned int countHitBlocks(const std::list<TimedBlock*>& blocks)
{
	return std::count_if(blocks.begin(), blocks.end(), wasHit);
}

/**
* Creates the output HTML file.
**/
void writeOutput(const std::list<Event>& list, std::list<TimedBlock*>& blockResults, std::list<TimedBlock*>& functionResults)
{
	msg("Generating the output file...\n");

	std::string pluginDir = ::idadir("plugins");
	std::string hotchDir = pluginDir + "/hotch";

	char filename[40] = {0};

	sprintf(filename, "results.html");
//	sprintf(filename, "results-%d.html", currentTime);

	std::string templateString;
	
	if (!readTextFile(hotchDir + "/template.htm", templateString))
	{
		msg("Could not read template file\n");
		return;
	}

	IdaFile file;

	unsigned int functions = file.getNumberOfFunctions();
	unsigned int hitFunctions = countHitBlocks(functionResults);
	unsigned int unhitFunctions = functions - hitFunctions;

	unsigned int blocks = file.getDebugger().getNumberOfBreakpoints();
	unsigned int hitBlocks = countHitBlocks(blockResults);
	unsigned int unhitBlocks = blocks - hitBlocks;	

	replaceString(templateString, "%FILENAME%", file.getInputfilePath());
	replaceString(templateString, "%NUMBER_OF_FUNCTIONS%", toString(functions));
	replaceString(templateString, "%NUMBER_OF_HIT_FUNCTIONS%", toString(hitFunctions));
	replaceString(templateString, "%NUMBER_OF_HIT_FUNCTIONS_PERCENTAGE%", floatToString(100.0 * hitFunctions / functions));
	replaceString(templateString, "%NUMBER_OF_NOT_HIT_FUNCTIONS%", toString(unhitFunctions));
	replaceString(templateString, "%NUMBER_OF_NOT_HIT_FUNCTIONS_PERCENTAGE%", floatToString(100.0 * unhitFunctions / functions));
	replaceString(templateString, "%NUMBER_OF_BLOCKS%", toString(blocks));
	replaceString(templateString, "%NUMBER_OF_HIT_BLOCKS%", toString(hitBlocks));
	replaceString(templateString, "%NUMBER_OF_HIT_BLOCKS_PERCENTAGE%", floatToString(100.0 * hitBlocks / blocks));
	replaceString(templateString, "%NUMBER_OF_NOT_HIT_BLOCKS%", toString(unhitBlocks));
	replaceString(templateString, "%NUMBER_OF_NOT_HIT_BLOCKS_PERCENTAGE%", floatToString(100.0 * unhitBlocks / blocks));
	replaceString(templateString, "%FUNCTIONS_BY_HITS%", generateFunctionTable(functionResults, sortByHits));
	replaceString(templateString, "%FUNCTIONS_BY_TIME%", generateFunctionTable(functionResults, sortByTime));
	replaceString(templateString, "%FUNCTIONS_BY_AVERAGE_TIME%", generateFunctionTable(functionResults, sortByAverageTime));
	replaceString(templateString, "%BLOCKS_BY_HITS%", generateBlocksTable(blockResults, sortByHits));
	replaceString(templateString, "%BLOCKS_BY_TIME%", generateBlocksTable(blockResults, sortByTime));
	replaceString(templateString, "%ALL_EVENTS%", generateEventsTable(list));

	writeOutput(hotchDir + "/" + filename, templateString);
}

/**
* Creates a map that is used to count function hits and how much time
* is spent in each function.
**/
std::map<Offset, TimedBlock*> initFunctionMap()
{
	std::map<Offset, TimedBlock*> timedFunctions;

	IdaFile file = IdaFile();

	for (FunctionIterator Iter = file.begin(); Iter != file.end(); ++Iter)
	{
		Offset functionOffset = Iter->getAddress();

		timedFunctions[functionOffset] = new TimedBlock(functionOffset);
	}

	return timedFunctions;
}

/**
* Takes the active breakpoints to create a map that is used to count
* breakpoint hits and how much time is spent in blocks.
**/
std::map<Offset, TimedBlock*> initBlockMap()
{
	std::map<Offset, TimedBlock*> timedBlocks;

	IdaFile file = IdaFile();
	Debugger debugger = file.getDebugger();

	// Initialize the time of each basic block to 0
	for (unsigned int i=0;i<debugger.getNumberOfBreakpoints();i++)
	{
		Breakpoint bp = debugger.getBreakpoint(i);

		Offset breakpointAddress = bp.getAddress();

		timedBlocks[breakpointAddress] = new TimedBlock(breakpointAddress);
	}

	return timedBlocks;
}

/**
* Calculates the block/function hits and the time spent in each block/function using the data
* from the event list.
**/
void analyzeEventList(const std::list<Event>& list, std::map<Offset, TimedBlock*> timedBlocks, std::map<Offset, TimedBlock*> timedFunctions)
{
	msg("Analyzing the profiler event list...\n");

	_timeb lastTime;
	Offset lastOffset(0);

	// We calculate the time spent in each basic block
	for (std::list<Event>::const_iterator Iter = list.begin(); Iter != list.end(); ++Iter)
	{
		_timeb currentTime = Iter->getTime();
		Offset currentOffset = Iter->getAddress();

		// Increase the hit counter at the basic block defined by the breakpoint.
		timedBlocks[currentOffset]->hit();

		// If the start of a function is hit, the hit counter of the function increases.
		if (currentOffset.isFunctionStart())
		{
			if (timedFunctions.find(currentOffset) == timedFunctions.end())
			{
				msg("Internal Error: Invalid function I (%08X)\n", currentOffset.getAddress());
			}

			timedFunctions[currentOffset]->hit();
		}

		// Skip the time calculation of the first event because we don't know how much time was spent
		// on this block.
		if (Iter == list.begin())
		{

			lastTime = currentTime;
			lastOffset = currentOffset;

			continue;
		}

		unsigned int difference = (currentTime.time - lastTime.time) * 1000 + currentTime.millitm - lastTime.millitm;

		if (timedBlocks.find(lastOffset) == timedBlocks.end())
		{
			msg("Internal Error: Invalid block\n");
		}

		// The time spent between the last breakpoint and the current breakpoint
		// is added to the block that was hit previously.
		timedBlocks[lastOffset]->addTime(difference);

		// The time spent in a function is increased whenever a breakpoint inside a function is followed
		// by another breakpoint hit (either inside or outside the function).
		Function lastFunction = timedBlocks[lastOffset]->getParentFunction();
		Offset lastFunctionOffset = lastFunction.getAddress();

		if (timedFunctions.find(lastFunctionOffset) == timedFunctions.end())
		{
			msg("Internal Error: Invalid function II\n");
		}

		timedFunctions[lastFunctionOffset]->addTime(difference);

		lastTime = currentTime;
		lastOffset = currentOffset;
	}
}

int debuggerCallback(void *user_data, int notification_code, va_list va);

/**
* When the process shuts down, the event list is analyzed and the profiling results are written
* to the output file.
**/
void handleExitProcess(UserData* userData)
{
	IdaFile file = IdaFile();

	std::list<Event>& list = userData->getEventList().getList();

	std::map<Offset, TimedBlock*> timedBlocks = initBlockMap();
	std::map<Offset, TimedBlock*> timedFunctions = initFunctionMap();

	analyzeEventList(list, timedBlocks, timedFunctions);

	std::list<TimedBlock*> blockResults = projectSecond(timedBlocks);
	std::list<TimedBlock*> functionResults = projectSecond(timedFunctions);

	writeOutput(list, blockResults, functionResults);

	for (std::map<Offset, TimedBlock*>::iterator Iter = timedBlocks.begin(); Iter != timedBlocks.end(); ++Iter)
	{
		delete Iter->second;
	}

	removeBreakpoints();

	// Remove the debugger notification callback and get rid of the old userData
	file.getDebugger().removeEventCallback(debuggerCallback, userData);

	delete userData;
}

/**
* Debugger callback that handles events that are necessary for profiling.
**/
int debuggerCallback(void *user_data, int notification_code, va_list va)
{
	UserData* userData = (UserData*)user_data;
	IdaFile file;
	Debugger debugger = file.getDebugger();

	if (notification_code == Debugger::EVENT_BREAKPOINT)
	{
		// Get the Thread ID
		thread_id_t tid = va_arg(va, thread_id_t);

		// Get the address of where the breakpoint was hit
		ea_t addr = va_arg(va, ea_t);

		_timeb timebuffer;
		_ftime64_s( &timebuffer );
		userData->getEventList().addEvent(Event(addr, timebuffer));

		debugger.resumeProcess(true);
	}
	else if (notification_code == Debugger::EVENT_PROCESS_SUSPENDED)
	{
		setBreakpoints();

		msg("Resuming target process...\n");

		debugger.resumeProcess(true);
	}
	else if (notification_code == Debugger::EVENT_PROCESS_EXIT)
	{
		handleExitProcess(userData);
	}

	return 0;
}


void IDAP_run(int)
{
	IdaFile file;

	msg("Starting to profile %s\n", file.getName().c_str());

	Debugger debugger = file.getDebugger();

	debugger.addEventCallback(&debuggerCallback, new UserData);

	if (debugger.isActive() && !debugger.isSuspended())
	{
		// If the target process is already running, suspend it to set the breakpoints

		msg("Suspending the target process...\n");
		debugger.suspendProcess(true);
	}
	else if (debugger.isActive() && debugger.isSuspended())
	{
		// If the target is already suspended, set the breakpoints and resume the process.

		setBreakpoints();

		debugger.resumeProcess(true);
	}
	else
	{
		// If the debugger is not yet running, set the breakpoints and start the process.

		setBreakpoints();

		msg("Starting target process\n");

		debugger.startProcess(file.getInputfilePath(), "", "");
	}
}

int IDAP_init(void)
{
	return PLUGIN_KEEP;
}

void IDAP_term(void)
{
}

// There isn't much use for these yet, but I set them anyway.
char IDAP_comment[] 	= "Profiling Plugin";
char IDAP_help[] 	= "Profiling Plugin";

// The name of the plug-in displayed in the Edit->Plugins menu. It 
// can be overridden in the user's plugins.cfg file.
char IDAP_name[] 	= "Hotch 1.0.0";

// The hot-key the user can use to run your plug-in.
char IDAP_hotkey[] 	= "CTRL-ALT-H";

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
