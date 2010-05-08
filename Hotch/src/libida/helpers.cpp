#include "helpers.hpp"

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

void writeOutput(const std::string& filename, const std::string& output)
{
	std::ofstream file(filename.c_str(), std::ios::binary);

	file.write(output.c_str(), output.length());
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

