#ifndef HELPERS_HPP
#define HELPERS_HPP

#include <sstream>
#include <fstream>
#include <string>
#include <list>
#include <map>

unsigned int getFileSize(std::ifstream& file);
bool readTextFile(const std::string& filename, std::string& output);
bool replaceString(std::string& output, const std::string& src, const std::string& dest);
void writeOutput(const std::string& filename, const std::string& output);

template<typename T>
std::string toString(const T& x)
{
    std::ostringstream streamOut;
    
    streamOut << x;
    
    return streamOut.str();
}

template<typename T>
std::string floatToString(const T& x, unsigned int precision = 2)
{
    std::ostringstream streamOut;
    
	streamOut << std::fixed << std::setprecision(precision);
    streamOut << x;
    
    return streamOut.str();
}

template<typename S, typename T>
T getSecond(const std::pair<S, T> p)
{
	return p.second;
}

template<typename S, typename T>
std::list<T> projectSecond(std::map<S, T>& m)
{
	std::list<T> result(m.size());

	std::transform(m.begin(), m.end(), result.begin(), getSecond<S, T>);

	return result;
}

#endif
