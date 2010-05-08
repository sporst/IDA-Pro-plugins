#ifndef HOTCH_HPP
#define HOTCH_HPP

#include <sys/timeb.h>

#include "libida.hpp"

class Event
{
private:
	Offset offset;
	_timeb time;

public:
	Event(Offset offset, _timeb time) : offset(offset), time(time) { }

	Offset getAddress() const
	{
		return offset;
	}

	_timeb getTime() const
	{
		return time;
	}

	Function getParentFunction() const { return Function(get_func(offset.getAddress())); }
};

class EventList
{
private:
	std::list<Event> events;
public:
	void addEvent(const Event& event)
	{
		events.push_back(event);
	}

	std::list<Event> getList()
	{
		return events;
	}
};

class UserData
{
private:
	EventList eventList;

public:
	ea_t lastOffset;

	UserData() : lastOffset(0) { }

	EventList& getEventList()
	{
		return eventList;
	}
};

class TimedBlock
{
private:
	Offset offset;
	unsigned int accumulatedTime;
	unsigned int hits;

public:
	TimedBlock(const Offset& offset) : offset(offset), accumulatedTime(0), hits(0) { }

	unsigned int getHits() const
	{
		return hits;
	}

	unsigned int getTime() const { return accumulatedTime; }

	void hit() { ++hits; }

	void addTime(unsigned int time) { accumulatedTime += time; }

	Offset getOffset() { return offset; }

	Function getParentFunction() const { return Function(get_func(offset.getAddress())); }
};

#endif
