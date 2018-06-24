import lief
import xml.etree.ElementTree as ET
import argparse
import hashlib
import prettytable
import time
import datetime
import constants
import re
import string
import os

class Import:
	def __init__(self, lib, fct):
		self.lib = lib
		self.fct = fct
		self.blacklisted = False
		self.group = None

	def __str__(self):
		return self.lib + ": " + self.fct + ", blacklisted: " + str(self.blacklisted) + " with group: " + str(self.group)

class Resource:
	def __init__(self, type, name, language, md5, content):
		self.type = type
		self.name = name
		self.language = language
		self.md5 = md5
		self.content = content
		
	def __str__(self):
		return str(self.name) + " of type " + str(self.type) + ", language " + str(self.language) + " has md5 " + str(self.md5)

class PeAnalyzer:
	imports = None
	resources = None

	def __init__(self, file):
		self.file = file
		if lief.is_pe(file):
			self.peFile = lief.parse(file)
		else:
			self.peFile = None
		self.strings = None
	
	def printIndicators(self, indicators, score, maxScore, table, all = False, jsonDict = None, root = None):
		jsonResults = []
		if not root is None:
			indicatorsXml = ET.SubElement(root, "indicators")
			indicatorsXml = root.find("indicators")
		
		# check file name
		if self.peFile.name != self.file.split("/")[-1]: # TODO: Check if that's correct
			print("\tName: " + self.peFile.name + " differs from file name " + self.file.split("/")[-1])
	
		# Suspicious sizes: File, Optional header, file header, certificate
		# TODO: Read severity from indicators.xml?
		thresholdRoot = ET.parse("xml/thresholds.xml").getroot()
		mins = thresholdRoot.find('thresholds').find('minimums')
		maxs = thresholdRoot.find('thresholds').find('maximums')
		
		min = int(mins.find('Image').text)
		max = int(maxs.find('Image').text)
		maxScore += int(indicators['1207'].severity)
		if not (min <= self.peFile.optional_header.sizeof_image <= max):
			score += int(indicators['1207'].severity)
			str = "The value of 'SizeOfImage' (%d) is suspicious" % (self.peFile.optional_header.sizeof_image)
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1207'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1207'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1207'].severity])
		elif all:
			print(constants.GREEN + "\tSize of image is reasonable (%d bytes)" % self.peFile.optional_header.sizeof_image + constants.RESET)
			
		#min = int(mins.find('file-header').text)
		#max = int(maxs.find('file-header').text)
		#if min <= self.peFile.dos_header.header_size_in_paragraphs <= max: # TODO: This seems to be incorrect
		#	print(constants.GREEN + "\tSize of File Header is reasonable (%d bytes)" % self.peFile.sizeof_headers + constants.RESET)	
		#else:
		#	print(constants.RED + "\tSize %d bytes of File Header is outide reasonable range (%d - %d bytes)" % (self.peFile.sizeof_headers, min, max) + constants.RESET)
		
		min = int(mins.find('optional-header').text)
		max = int(maxs.find('optional-header').text)
		
		maxScore += int(indicators['1004'].severity)
		if not (min <= self.peFile.header.sizeof_optional_header <= max): # Not sure if that's correct
			score += int(indicators['1004'].severity)
			str = "The size (%d bytes) of the optional-header is suspicious" % (self.peFile.header.sizeof_optional_header)
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1004'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1004'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1004'].severity])
		elif all:
			print(constants.GREEN + "\tSize of Optional Header is reasonable (%d bytes)" % self.peFile.header.sizeof_optional_header + constants.RESET)
		
		# Content of certificate??, expired issuer, expired subject, no digital certificate
		if not self.peFile.has_signature and jsonDict is None and root is None:
			print(constants.RED + "\tThe PE file has no digital signature" + constants.RESET)
		elif self.peFile.has_signature:
			maxScore += int(indicators['1039'].severity)
			for cert in self.peFile.signature.certificates:
				cert_from = datetime.datetime.fromtimestamp(cert.valid_from)
				cert_to = datetime.datetime.fromtimestamp(cert.valid_to)
				if cert_from > datetime.datetime.now() or cert_to < datetime.datetime.now():
					score += int(indicators['1039'].severity)
					str = "Digital certificate is used which is not valid (from: %s to: %s)" + (str(cert_from), str(cert_to))
					if not jsonDict is None:
			 			jsonResults.append({"indicator": str, "severity" : indicators['1039'].severity})
					elif not root is None:
						indicatorXml = ET.SubElement(indicatorsXml, "indicator")
						indicatorXml.set("severity", indicators['1039'].severity)
						indicatorXml.text = str
					else:
						table.add_row([constants.RED + str + constants.RESET, indicators['1039'].severity])
			# TODO: We should check if the signature is valid but this seems to be ugly
		
		# Self-extractable file??
		# Managed by .NET??
		# References debug symbols
		
		# Code-less file
		min = int(mins.find('Code').text)
		maxScore += int(indicators['1027'].severity)
		if min > self.peFile.optional_header.sizeof_code:
			score += int(indicators['1027'].severity)
			str = "The file is code-less"
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1027'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1027'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1027'].severity])
		elif all:
			print(constants.GREEN + "\tThe file has valid code size" + constants.RESET)
		
		# No manifest
		maxScore += int(indicators['1043'].severity)
		if self.peFile.has_resources and not self.peFile.resources_manager.has_manifest:
			score += int(indicators['1043'].severity)
			str = "The file has no Manifest"
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1043'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1043'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1043'].severity])
		elif all:
			print(constants.GREEN + "\tThe file has a Manifest" + constants.RESET)
		
		# Entrypoint things
		lastSection = False
		maxScore += int(indicators['1035'].severity)
		
		not_exe_entry_point = 0
		for section in self.peFile.sections:
			lastSection = False
			start = self.peFile.optional_header.imagebase + section.virtual_address
			if start < self.peFile.entrypoint < start + section.size:
				# Entrypoint is in this section
				lastSection = True
				if not section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE):
					# Section is not marked as executable
					score += int(indicators['1035'].severity)
					str = "Entrypoint (%s) in section %s which is not executable" % (hex(self.peFile.entrypoint), section.name)
					if not jsonDict is None:
			 			jsonResults.append({"indicator": str, "severity" : indicators['1035'].severity})
					elif not root is None:
						indicatorXml = ET.SubElement(indicatorsXml, "indicator")
						indicatorXml.set("severity", indicators['1035'].severity)
						indicatorXml.text = str
					else:
						table.add_row([constants.RED + str + constants.RESET, indicators['1035'].severity])
					not_exe_entry_point += 1
		
		if all and not_exe_entry_point == 0:
			print(constants.GREEN + "\tNo non-executable entrypoint found" + constants.RESET)
		
		maxScore += int(indicators['1605'].severity)
		if lastSection:
			# The section of the entry point was the last section in the PE file
			score += int(indicators['1605'].severity)
			str = "Entrypoint is in last section"
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1605'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1605'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1605'].severity])
		
		maxScore += int(indicators['1037'].severity)
		if self.peFile.optional_header.imagebase > self.peFile.entrypoint > self.peFile.optional_header.imagebase + self.peFile.optional_header.sizeof_image:
			# Entry point outside file
			score  += int(indicators['1037'].severity)
			str = "Entrypoint (%s) is outside the file." % (hex(self.peFile.entrypoint))
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1037'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1037'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1037'].severity])
		elif all:
			print(constants.GREEN + "\tEntrypoint (%s) located inside the file." % (hex(self.peFile.entrypoint)) + constants.RESET)

		maxScore += int(indicators['1211'].severity)
		if self.peFile.entrypoint == 0:
			score  += int(indicators['1211'].severity)
			str = "The address of the entry-point is zero"
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1211'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1211'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1211'].severity])
		elif all:
			print(constants.GREEN + "\tThe address of the entry-point is not zero" + constants.RESET)
			
		
		# TODO: Invalid file checksum, checksum computed different to checksum

		
		# File ratio of resources
		maxScore += int(indicators['1232'].severity)
		if self.peFile.has_resources:
			rsrc_directory = self.peFile.data_directory(lief.PE.DATA_DIRECTORY.RESOURCE_TABLE)
			if rsrc_directory.has_section:
				min = int(mins.find('ProcentResource').text)
				max = int(maxs.find('ProcentResource').text)
				maxScore += int(indicators['1220'].severity)
				percentage = (rsrc_directory.section.size / self.peFile.optional_header.sizeof_image ) * 100
				if not (min <= percentage <= max):
					score += int(indicators['1220'].severity)
					str = "The file-ratio (%d) of the resources is suspicious" % (percentage)
					if not jsonDict is None:
						jsonResults.append({"indicator": str, "severity" : indicators['1220'].severity})
					elif not root is None:
						indicatorXml = ET.SubElement(indicatorsXml, "indicator")
						indicatorXml.set("severity", indicators['1220'].severity)
						indicatorXml.text = str
					else:
						table.add_row([constants.RED + str + constants.RESET, indicators['1220'].severity])
				elif all:
					print(constants.GREEN + "\tThe file-ratio (%d) of the resources seems reasonable" % (percentage) + constants.RESET)
		else:
			score += int(indicators['1232'].severity)
			str = "The file is resource-less"
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1232'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1232'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1232'].severity])

		# PE file uses control flow guard
		maxScore += int(indicators['1050'].severity)
		if self.peFile.optional_header.has(lief.PE.DLL_CHARACTERISTICS.GUARD_CF):
			score += int(indicators['1211'].severity)
			str = "The file implements Control Flow Guard (CFG)"
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1050'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1050'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1050'].severity])
		elif all:
			print(constants.GREEN + "\tThe file does not implement Control Flow Guard (CFG)" + constants.RESET)
					

		# PE file is a WDM device driver
		maxScore += int(indicators['1056'].severity)
		if self.peFile.optional_header.has(lief.PE.DLL_CHARACTERISTICS.WDM_DRIVER):
			score += int(indicators['1056'].severity)
			str = "The file is a Device Driver"
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1056'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1056'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1056'].severity])
		elif all:
			print(constants.GREEN + "\tThe file is not a Device Driver" + constants.RESET)

		# PE file makes use of DEP protection
		maxScore += int(indicators['1100'].severity)
		maxScore += int(indicators['1101'].severity)
		if self.peFile.optional_header.has(lief.PE.DLL_CHARACTERISTICS.NX_COMPAT):
			score += int(indicators['1100'].severity)
			str = "The file opts for Data Execution Prevention (DEP)"
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1100'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1100'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1100'].severity])
		else:
			score += int(indicators['1101'].severity)
			str = "The file ignores Data Execution Prevention (DEP)"
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1101'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1101'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1101'].severity])
		
		# PE file makes use of ASLR
		maxScore += int(indicators['1102'].severity)
		maxScore += int(indicators['1103'].severity)
		if self.peFile.optional_header.has(lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE):
			score += int(indicators['1102'].severity)
			str = "The file opts for Address Space Layout Randomization (ASLR)"
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1102'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1102'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1102'].severity])
		else:
			score += int(indicators['1103'].severity)
			str = "The file ignores Address Space Layout Randomization (ASLR)"
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1103'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1103'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1103'].severity])
		
		# PE file does not use of structured error handling (SEH)
		maxScore += int(indicators['1105'].severity)
		if self.peFile.optional_header.has(lief.PE.DLL_CHARACTERISTICS.NO_SEH):
			score += int(indicators['1105'].severity)
			str = "The file ignores Structured Exception Handling (SEH)"
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1105'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1105'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1105'].severity])
		
		# PE file does not use GS
		maxScore += int(indicators['1106'].severity)
		maxScore += int(indicators['1107'].severity)
		if self.peFile.has_configuration:
			if self.peFile.load_configuration.security_cookie == 0:
				score += int(indicators['1107'].severity)
				str = "The file ignores cookies on the stack (GS)"
				if not jsonDict is None:
					jsonResults.append({"indicator": str, "severity" : indicators['1107'].severity})
				elif not root is None:
					indicatorXml = ET.SubElement(indicatorsXml, "indicator")
					indicatorXml.set("severity", indicators['1107'].severity)
					indicatorXml.text = str
				else:
					table.add_row([constants.RED + str + constants.RESET, indicators['1107'].severity])
			else:
				score += int(indicators['1106'].severity)
				str = "The file opts for cookies on the stack (GS)"
				if not jsonDict is None:
					jsonResults.append({"indicator": str, "severity" : indicators['1106'].severity})
				elif not root is None:
					indicatorXml = ET.SubElement(indicatorsXml, "indicator")
					indicatorXml.set("severity", indicators['1106'].severity)
					indicatorXml.text = str
				else:
					table.add_row([constants.RED + str + constants.RESET, indicators['1106'].severity])
		
		# PE file does not use code integrity
		maxScore += int(indicators['1109'].severity)
		if self.peFile.has_configuration:
			if isinstance(self.peFile.load_configuration, lief.PE.LoadConfigurationV2) and self.peFile.load_configuration.code_integrity.catalog == 0xFFFF:
				score += int(indicators['1109'].severity)
				str = "The file ignores Code Integrity"
				if not jsonDict is None:
					jsonResults.append({"indicator": str, "severity" : indicators['1109'].severity})
				elif not root is None:
					indicatorXml = ET.SubElement(indicatorsXml, "indicator")
					indicatorXml.set("severity", indicators['1109'].severity)
					indicatorXml.text = str
				else:
					table.add_row([constants.RED + str + constants.RESET, indicators['1109'].severity])
			elif all:
				print(constants.GREEN + "\tThe file opts for Code Integrity" + constants.RESET)

		# Get the pdb debug file name
		data_dir = self.peFile.data_directory(lief.PE.DATA_DIRECTORY.DEBUG)
		maxScore += int(indicators['1152'].severity)
		maxScore += int(indicators['1153'].severity)
		if data_dir.size != 0:
			dbg_file_name_lst = self.peFile.get_content_from_virtual_address(self.peFile.optional_header.imagebase + data_dir.rva, data_dir.size - 24)
			dbg_file_name = "".join(chr(c) for c in dbg_file_name_lst)
			score += int(indicators['1152'].severity)
			str = "The file references a debug symbols file (path: %s)" % (dbg_file_name)
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1152'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1152'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1152'].severity])
			if dbg_file_name.split(".")[-1] != ".pdb":
				score += int(indicators['1153'].severity)
				str = "The debug file name extension %s is suspicous" % (dbg_file_name.split(".")[-1])
				if not jsonDict is None:
					jsonResults.append({"indicator": str, "severity" : indicators['1152'].severity})
				elif not root is None:
					indicatorXml = ET.SubElement(indicatorsXml, "indicator")
					indicatorXml.set("severity", indicators['1152'].severity)
					indicatorXml.text = str
				else:
					table.add_row([constants.RED + str + constants.RESET, indicators['1152'].severity])
		
		# Suspicious debug timestamp
		maxScore += int(indicators['1157'].severity)
		if self.peFile.has_debug:
			dbg_time = datetime.datetime.fromtimestamp(self.peFile.debug.timestamp)
			if dbg_time > datetime.datetime.now(): # TODO: Check if there are more criteria
				score += int(indicators['1157'].severity)
				str = "The age (%s) of the debug file is suspicious" % (str(dbg_time))
				if not jsonDict is None:
					jsonResults.append({"indicator": str, "severity" : indicators['1157'].severity})
				elif not root is None:
					indicatorXml = ET.SubElement(indicatorsXml, "indicator")
					indicatorXml.set("severity", indicators['1157'].severity)
					indicatorXml.text = str
				else:
					table.add_row([constants.RED + str + constants.RESET, indicators['1157'].severity])
		
		# Check entropy of the sections, number of shared sections
		min = int(mins.find('Entropy').text)
		max = int(maxs.find('Entropy').text)
		sharedSect = 0
		suspicious_entropies = 0
		for sect in self.peFile.sections:
			if (not min < sect.entropy < max) and jsonDict is None and root is None:
				print(constants.RED + "\tThe entropy %d of section %s is suspicious" % (sect.entropy, sect.name) + constants.RESET)
				suspicious_entropies += 1
			if sect.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_SHARED):
				sharedSect += 1
		if all and suspicious_entropies == 0:
			print(constants.GREEN + "\tAll sections entropies seem reasonable" + constants.RESET)
			
		min = int(mins.find('SharedSections').text)
		max = int(maxs.find('SharedSections').text)
		maxScore += int(indicators['1213'].severity)
		if not min <= sharedSect <= max:
			score += int(indicators['1213'].severity)
			str = "The shared section(s) (%d) reached the max (%d) threshold" % (sharedSect, max)
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1213'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1213'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1213'].severity])
		elif all:
			print(constants.GREEN + "\tShared section(s) (%d) below the max (%d) threshold" % (sharedSect, max) + constants.RESET)
		
		# Check if first section is writable or last section is executable
		maxScore += int(indicators['1223'].severity)
		if list(self.peFile.sections)[0].has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE):
			score += int(indicators['1223'].severity)
			str = "The first section (name:%s) is writable" % (self.peFile.sections[0].name)
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1223'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1223'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1223'].severity])
		elif all:
			print(constants.GREEN + "\tThe first section (name:%s) is not writable" % (self.peFile.sections[0].name) + constants.RESET)
		
		maxScore += int(indicators['1222'].severity)
		if list(self.peFile.sections)[-1].has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE):
			score += int(indicators['1222'].severity)
			str = "The last section (name:%s) is executable" % (self.peFile.sections[-1].name) 
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1222'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1222'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1222'].severity])
		elif all:
			print(constants.GREEN + "\tThe last section (name:%s) is not executable" % (self.peFile.sections[-1].name) + constants.RESET)
		
		# Size of initialized data
		min = int(mins.find('InitializedData').text)
		max = int(maxs.find('InitializedData').text)
		maxScore += int(indicators['1208'].severity)
		if not min < self.peFile.optional_header.sizeof_initialized_data < max:
			score += int(indicators['1208'].severity)
			str = "The size of initialized data reached the max (%d bytes) threshold" % self.peFile.optional_header.sizeof_initialized_data
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1208'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1208'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1208'].severity])
		elif all:
			print(constants.GREEN + "\tThe size of initialized data (%d bytes) is reasonable" % self.peFile.optional_header.sizeof_initialized_data + constants.RESET)
	
		
		# TODO: File references missing library
		
		# Check imphash
		self.checkImphashes()
		
		# More then one executable sections
		exe_sections = 0
		for section in self.peFile.sections:
			if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE):
				exe_sections += 1
		
		maxScore += int(indicators['2246'].severity) # Same as 1246
		if not int(mins.find('ExecutableSections').text) <= exe_sections <= int(maxs.find('ExecutableSections').text):
			score += int(indicators['2246'].severity)
			str = "The executable has %d executable sections" % exe_sections
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['2246'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['2246'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['2246'].severity])
		elif all:
			print(constants.GREEN + "\tThe executable has %d executable sections" % exe_sections + constants.RESET)
	
		# executable and writable sections
		maxScore += int(indicators['2215'].severity)
		count_exe_write_sec = 0
		for section in self.peFile.sections:
			if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE) and section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE):
				count_exe_write_sec += 1
		
		if count_exe_write_sec > 0:
			score += int(indicators['2215'].severity)
			str = "The executable has section(s) that are both executable and writable"
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['2215'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['2215'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['2215'].severity])	
		elif all:
			print(constants.GREEN + "\tThe executable has %d section(s) that is/are both executable and writable" % count_exe_write_sec + constants.RESET)
		
		# common passwords
		if self.strings is None:
			self.searchAllStrings()
		
		stringsXml = ET.parse("xml/strings.xml").getroot()
		password_checks = 0
		# TODO: Maybe use regex instead of checking if the string is in the list of strings?
		for r in stringsXml.find('psw').findall('item'):
			if r.text in self.strings:
				password_checks += 1
		
		maxScore += int(indicators['1637'].severity)
		if not (int(mins.find('Passwords').text) <= password_checks <= int(maxs.find('Passwords').text)):
			score += int(indicators['1637'].severity)
			str = "The executable contains %d default passwords." % password_checks
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1637'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1637'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1637'].severity])
		elif all:
			print(constants.GREEN + "\tThe executable contains %d default passwords." % password_checks + constants.RESET)
		
		# Compiled with Delphi
		maxScore += int(indicators['1121'].severity)
		if "Delphi" in self.strings:
			score += int(indicators['1121'].severity)
			str = "The file has been compiled with Delphi"
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1121'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1121'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1121'].severity])
		elif all:
			print(constants.GREEN + "\t The file has not been compiled with Delphi" + constants.RESET)
		
		# Size of code greater than size of code section
		code_sec_size = 0
		for section in self.peFile.sections:
			if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.CNT_CODE):
				code_sec_size += section.size
		
		maxScore += int(indicators['1623'].severity)
		if self.peFile.optional_header.sizeof_code > code_sec_size:
			score += int(indicators['1623'].severity)
			str = "The size of code (%i bytes) is bigger than the size (%i bytes) of code sections" % (self.peFile.optional_header.sizeof_code, code_sec_size)
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1623'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1623'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1623'].severity])		
		elif all:
			print(constants.GREEN + "\tThe size of code (%i bytes) matches the size of code sections" % self.peFile.optional_header.sizeof_code)
		
		# Suspicious section names
		standardSectionNames = [".text", ".bss", ".rdata", ".data", ".idata", ".reloc", ".rsrc"]
		suspiciousSections = 0
		for section in self.peFile.sections:
			if not section.name in standardSectionNames and jsonDict is None and root is None:
				print(constants.RED + "\tSuspicious section name %s" % (section.name) + constants.RESET)
				suspiciousSections += 1
		
		min = int(mins.find('BlackListedSectionNames').text)
		max = int(maxs.find('BlackListedSectionNames').text)
		maxScore += int(indicators['2248'].severity)
		if not min <= suspiciousSections < max:
			score += int(indicators['2248'].severity)
			str = "The file has (%i) blacklisted section name(s)" % suspiciousSections
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['2248'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['2248'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['2248'].severity])
		
		# Missing DOS-Stub
		maxScore += int(indicators['1260'].severity)
		if len(self.peFile.dos_stub) == 0:
			score += int(indicators['1260'].severity)
			str = "The dos-stub is missing"
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1260'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1260'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1260'].severity])
		elif all:
			print(constants.GREEN + "\tThe dos-stub is present" + constants.RESET)

		# Number of anti-debugging functions
		min = int(mins.find('AntidebugFunctions').text)
		max = int(maxs.find('AntidebugFunctions').text)
		antiDbgFunctions = len(self.getAntiDebugFcts())
		
		maxScore += int(indicators['2270'].severity) # Same as 1270
		if not (min <= antiDbgFunctions <= max):
			score += int(indicators['2270'].severity)
			str = "The file imports (%d) antidebug function(s)" % antiDbgFunctions
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['2270'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['2270'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['2270'].severity])
		elif all:
			print(constants.GREEN + "\tThe file imports (%d) antidebug function(s), less than min threshold (%d)" % (antiDbgFunctions, min) + constants.RESET)
		

		# Keyboard functions
		keyboardFcts, keys = self.getKeyboardFcts()
		maxScore += int(indicators['1635'].severity)
		if len(keyboardFcts) > 0:
			score += int(indicators['1635'].severity)
			str = "The file references (%i) keyboard functions" % len(keyboardFcts)
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1635'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1635'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1635'].severity])
		if keys > 0:
			score += int(indicators['1635'].severity)
			str = "The file references (%i) keyboard keys like a Keylogger" % keys
			if not jsonDict is None:
				jsonResults.append({"indicator": str, "severity" : indicators['1635'].severity})
			elif not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "indicator")
				indicatorXml.set("severity", indicators['1635'].severity)
				indicatorXml.text = str
			else:
				table.add_row([constants.RED + str + constants.RESET, indicators['1635'].severity])
		if all and not (len(keyboardFcts) > 0 or keys > 0):
			print(constants.GREEN + "\tThe file does not references keyboard keys or functions" + constants.RESET)
			
		if not jsonDict is None:
			jsonDict["indicators"] = {}
			jsonDict["indicators"]["indicators"] = jsonResults
			
		return score, maxScore, jsonDict, root
	
	def getKeyboardFcts(self):
		if self.imports is None:
			self.__getImports()
		root = ET.parse("xml/functions.xml").getroot()
		
		# Get all the blacklisted functions and libraries by name
		keyboardFcts = []
		for lib in root.find('libs').findall('lib'):
			if lib.find('fcts') is None:
				if 'group' in lib.attrib and lib.attrib['group'] == '22':
					f = list(filter(lambda i: i.lib == lib.attrib['name'], self.imports))
					keyboardFcts += f
				continue
			for fct in lib.find('fcts'):
				if 'group' in fct.attrib and fct.attrib['group'] == '22':
					f = list(filter(lambda i: i.lib == lib.attrib['name'] and i.fct == fct.text, self.imports))
					keyboardFcts += f
		
		if self.strings is None:
			self.searchAllStrings()
		keys = 0
		stringsXml = ET.parse("xml/strings.xml").getroot()
		for r in stringsXml.find('keys').findall('key'):
			if r.text in self.strings:
				keys += 1
		return keyboardFcts, keys
		
	def getAntiDebugFcts(self):
		if self.imports is None:
			self.__getImports()
		root = ET.parse("xml/functions.xml").getroot()
		
		# Get all the blacklisted functions and libraries by name
		antiDbgFunctions = []
		for lib in root.find('libs').findall('lib'):
			if lib.find('fcts') is None:
				if 'group' in lib.attrib and lib.attrib['group'] == '16':
					f = list(filter(lambda i: i.lib == lib.attrib['name'], self.imports))
					antiDbgFunctions += f
				continue
			for fct in lib.find('fcts'):
				if 'group' in fct.attrib and fct.attrib['group'] == '16':
					f = list(filter(lambda i: i.lib == lib.attrib['name'] and i.fct == fct.text, self.imports))
					antiDbgFunctions += f
		f = list(filter(lambda i: i.lib == 'kernel32.dll' and i.fct == 'IsDebuggerPresent', self.imports))
		antiDbgFunctions += f
		return antiDbgFunctions
		
	def checkFeatures(self, indicators, score, maxScore, table = None, jsonDict = None, root = None):
		if self.imports is None:
			self.__getImports()
		
		jsonResults = []
		if not root is None:
			indicatorsXml = ET.SubElement(root, "indicators")
			indicatorsXml = root.find("indicators")
		
		maxScore += int(indicators['1265'].severity)
		if not self.checkImportNumber():
			score += int(indicators['1265'].severity)
			str = constants.RED + "The count (%d) of imports is suspicious" % len(self.imports) + constants.RESET
			if not table is None:
				table.add_row([str, indicators['1265'].severity])
			if not jsonDict is None:
				jsonResults.append({"indicator": "The count (%d) of imports is suspicious" % len(self.imports), "severity": indicators['1265'].severity})
			if not root is None:
				indicatorXml = ET.SubElement(indicatorsXml, "function")
				indicatorXml.set("severity", indicators['1265'].severity)
				indicatorXml.text = "The count (%d) of imports is suspicious" % len(self.imports)	
		
		featureSet = set()
		# TODO: we can also print it as table with the severity (and sum up the severity over all things)
		for feature in ET.parse("xml/features.xml").getroot().find('features').findall('features'):
			maxScore += int(indicators[feature.attrib["id"]])
			for lib in feature.find('libs').findall('lib'):
				for fct in lib.find('fcts').findall('fct'):
					if lib.attrib["name"] == "" and fct.text == "":
						continue
					matchingImps = filter(lambda imp: lib.attrib["name"] in imp.lib and fct.text in imp.fct, self.imports)
					if len(matchingImps) > 0:
						id = fct.attrib["id"]
						featureSet.add(id)
		
		for k, indicator in indicators.items():
			if k in featureSet and indicator.enable == "1":
				score += int(indicator.severity)
				str = constants.RED + indicator.text + constants.RESET
				if not table is None:
					table.add_row([str, indicator.severity])
				if not jsonDict is None:
					jsonResults.append({"indicator": str, "severity": indicator.severity})
				if not root is None:
					indicatorXml = ET.SubElement(indicatorsXml, "function")
					indicatorXml.set("severity", indicator.severity)
					indicatorXml.text = indicator.text
		
		if not jsonDict is None:
			jsonDict["indicators"]["functions"] = jsonResults
		
		return score, maxScore, jsonDict, root
	
	def __getImports(self):
		self.imports = []
		for i in self.peFile.imports:
			for e in i.entries:
				self.imports.append(Import(i.name.lower(), e.name))

	def checkImportNumber(self):
		'''
		Extract the min/max number of imports and check if the number of imports in the PE
		file is in that range
		'''
		if self.imports is None:
			self.__getImports()
		root = ET.parse("xml/thresholds.xml").getroot()
		min = int(root.find('thresholds').find('minimums').find('Imports').text)
		max = int(root.find('thresholds').find('maximums').find('Imports').text)
		real = len(self.imports)
		return min < real < max

	def __read_groups(self):
		root = ET.parse("xml/translations.xml").getroot()
		groups = {'--': "undefined"}
		for group in root.find('groups').findall('group'):
			groups[group.attrib['id']] = group.text
		return groups
	
	def checkImphashes(self):
		'''
		Parses the xml/functions.xml file and checks the imphash of the binary
		'''
		imphash = lief.PE.get_imphash(self.peFile).lower()
		root = ET.parse("xml/functions.xml").getroot()
		for hash in root.find('imphashes').findall('imphash'):
			if imphash == hash.text.lower():
				print(constants.RED + "\tFound matching imphash (%s) for the file" % imphash + constants.RESET)

	def blacklistedImports(self):
		'''
		Parses the xml/functions.xml file and checks the functions blacklisted in the
		file against the imports found in the PE file. Returns the list of all matches.
		
		TODO: Support the md5 hashes
		TODO: Support the families
		TODO: Support the imphashes
		'''
		if self.imports is None:
			self.__getImports()
		root = ET.parse("xml/functions.xml").getroot()
		
		groups = self.__read_groups()
		
		# Get all the blacklisted functions and libraries by name
		self.suspiciousFunctions = []
		for lib in root.find('libs').findall('lib'):
			if lib.find('fcts') is None:
				f = list(filter(lambda i: i.lib == lib.attrib['name'], self.imports))
				for function in f:
					if 'group' in lib.attrib:
						function.group = groups[lib.attrib['group']]
					else:
						function.group = groups["--"]
					function.blacklisted = True
				self.suspiciousFunctions += f
				continue
			for fct in lib.find('fcts'):
				f = list(filter(lambda i: i.lib == lib.attrib['name'] and i.fct == fct.text, self.imports))
				for function in f:
					if 'group' in fct.attrib:
						function.group = groups[fct.attrib['group']]
					else:
						function.group = groups["--"]
					function.blacklisted = True
				self.suspiciousFunctions += f
		# TODO: We can replace the suspicious functions with filtering for imports which are blacklisted
		return self.suspiciousFunctions, self.imports

	def printImportInformation(self):
		
		reasonableNumber = self.checkImportNumber()
		if not reasonableNumber:
			print(constants.RED + "Suspicious number of imports (%d)" % len(self.imports) + constants.RESET)
		elif all:
			print(constants.GREEN + "Number of imports is in a reasonable range (%d)" % len(self.imports), constants.RESET)
		
		self.blacklistedImports()
		if len(self.suspiciousFunctions):
			print(constants.RED + "The following %d out of %d imports are blacklisted:" % (len(self.suspiciousFunctions), len(self.imports)) + constants.RESET)
			table = prettytable.PrettyTable()
			table.field_names = ["Library", "Function", "Group"]
			
			for imp in self.suspiciousFunctions:
				table.add_row([imp.lib, imp.fct, imp.group])
			
			resultString = str(re.sub(r'(^|\n)', r'\1\t', str(table)))
			print(resultString)
		else:
			print(constants.GREEN + "None of the imports is blacklisted.", constants.RESET)

	def getImportXml(self, root):
		self.blacklistedImports()
		
		imports = ET.SubElement(root, "Imports")
		summary = ET.SubElement(imports, "summary")
		ET.SubElement(summary, "blacklisted").text = str(len(self.suspiciousFunctions))
		ET.SubElement(summary, "total").text = str(len(self.imports))
		blacklisted = ET.SubElement(imports, "blacklisted")
		# TODO: We can also show all functions and tell which ones are blacklisted
		for imp in self.suspiciousFunctions:
			fct = ET.SubElement(blacklisted, "function")
			fct.set("library", imp.lib)
			fct.set("group", imp.group)
			fct.set("blacklisted", str(imp.blacklisted))
			fct.text = imp.fct
		
		return root
	
	def getImportJson(self, jsonDict):
		self.blacklistedImports()
		
		res = {"summary": {"blacklisted": str(len(self.suspiciousFunctions)), "total": str(len(self.imports))}}
		res["blacklisted"] = []
		for imp in self.suspiciousFunctions:
			res["blacklisted"].append({"library": imp.lib, "group": imp.group, "blacklisted": str(imp.blacklisted), "function": imp.fct})
		
		jsonDict["Imports"] = res
		return jsonDict

	def __getResources(self):
		self.resources = []
		if self.peFile.has_resources:
			for resourceType in self.peFile.resources.childs:
				for resource in resourceType.childs:
					for lang in resource.childs:
						name = resource.name if resource.has_name else hex(resource.id)
						md5 = hashlib.md5(bytes(lang.content))
						self.resources.append(Resource(resourceType.id, name, lang.id, md5, bytes(lang.content)))
		
		return self.resources

	def blacklistedResources(self):
		'''
		Parses the xml/resources.xml file and returns the list of blacklisted resources that
		are used by the PE file to analyze.
		'''
		# Get the MD5 of resources used by the PE file
		#resourceMD5 = [hashlib.md5(r.data).hexdigest().upper() for r in self.peFile.resources]
		if self.resources is None:
			self.__getResources()
		
		resourceMD5 = [res.md5 for res in self.resources]
		# Get the program name from translations file
		translations = ET.parse("xml/translations.xml").getroot().find('knownResources')
		dict = {}
		for t in translations:
			dict[t.attrib['id']] = t.text
		
		# Get the blacklisted MD5 hashes and which ones are used in the PE file
		resources = ET.parse("xml/resources.xml").getroot().find('resources')
		self.blacklistedRes = []
		for r in resources:
			if r.text in resourceMD5:
				self.blacklistedRes.append(dict[r.attrib['id']])
		
		return self.blacklistedRes

	def __get_languages(self):
		langs = ET.parse("xml/languages.xml").getroot().find('languages')
		languages = {}
		for lang in langs:
			languages[int(lang.attrib['id'], 16)] = lang.text
		return languages

	def addResourcesXml(self, root):
		if self.resources is None:
			self.__getResources()
		if self.blacklistedRes is None:
			self.blacklistedResources()
		resources = ET.SubElement(root, "Resources")
		summary = ET.SubElement(resources, "summary")
		ET.SubElement(summary, "blacklisted").text = str(len(self.blacklistedRes))
		ET.SubElement(summary, "total").text = str(len(self.resources))
		
		blacklisted = ET.SubElement(resources, "blacklisted")
		for res in self.blacklistedRes:
			fct = ET.SubElement(blacklisted, "resource-type")
			fct.text = res
		
		languages = self.__get_languages()
		
		allResources = ET.SubElement(resources, "resource-list")
		for resource in self.resources:
			name = resource.name #resource.name_str if resource.name_str else hex(esource.name)
			res = ET.SubElement(allResources, "resource")
			res.set("type", str(resource.type))
			res.set("name", str(resource.name))
			res.set("language", languages[resource.language])
			res.text = resource.md5.hexdigest().upper()
		
		return root
	
	def addResourcesJson(self, jsonDict):
		if self.resources is None:
			self.__getResources()
		if self.blacklistedRes is None:
			self.blacklistedResources()
		
		res = {"summary": {"blacklisted": str(len(self.blacklistedRes)), "total": str(len(self.resources))}}
		
		res["blacklisted"] = self.blacklistedRes
		
		languages = self.__get_languages()
		
		res["resource-list"] = []
		for resource in self.resources:
			res["resource-list"].append({"type": str(resource.type), "name": str(resource.name),
				"language": languages[resource.language], "md5": resource.md5.hexdigest().upper()})
		
		jsonDict["Resources"] = res
		return jsonDict

	def showAllResources(self):
		if self.resources is None:
			self.__getResources()
		if self.blacklistedRes is None:
			self.blacklistedResources()
		
		# Get languages from file
		languages = self.__get_languages()
		
		# We could also get the type from translations.xml xml/resources, they differ sometimes
		# and in translations.xml we have a "severity" value
		table = prettytable.PrettyTable()
		table.field_names = ["Type", "Name", "MD5", "Language"]
		print("List of all resources: ")
		for resource in self.resources:
			res_type = resource.type
			name = resource.name
			md5 = resource.md5
			language = resource.language
			table.add_row([constants.RES_TO_STR(res_type), name, md5.hexdigest().upper(), languages[language]])
		
		resultString = str(re.sub(r'(^|\n)', r'\1\t', str(table)))
		print(resultString)
	
	def dumpResourcesToFile(self):
		if self.resources is None:
			self.__getResources()
		
		os.makedirs("./resources", exist_ok=True)
		
		for resource in self.resources:
			resFile = open("./resources/" + resource.name, "wb")
			resFile.write(resource.content)

	def addHeaderInformationXml(self, root):
		header = ET.SubElement(root, "FileHeader")
		signature = ET.SubElement(header, "signature")
		signature.text = "".join(["{0:02x}".format(x) for x in self.peFile.header.signature])
		machine = ET.SubElement(header, "machine")
		machine.text = constants.MACHINE_TYPE[self.peFile.header.machine]
		sections = ET.SubElement(header, "numberOfSections")
		sections.text = hex(self.peFile.header.numberof_sections)
		timeDateStamp = ET.SubElement(header, "numberOfSections")
		timeDateStamp.text = str(datetime.datetime.fromtimestamp(self.peFile.header.time_date_stamps))
		pointerToSymbolTable = ET.SubElement(header, "pointerToSymbolTable")
		pointerToSymbolTable.text = hex(self.peFile.header.pointerto_symbol_table)
		numberOfSymbols = ET.SubElement(header, "numberOfSymbols")
		numberOfSymbols.text = str(self.peFile.header.numberof_symbols)
		sizeOfOptionalHeader = ET.SubElement(header, "sizeOfOptionalHeader")
		sizeOfOptionalHeader.text = str(self.peFile.header.sizeof_optional_header)
		characteristics = ET.SubElement(header, "characteristics")
		characteristics.text = hex(self.peFile.header.characteristics)
		PE32 = ET.SubElement(header, "PE32")
		PE32.text = str(self.peFile.dos_header.magic == 267)

		return root
	
	def addHeaderInformationJson(self, jsonDict):
		res = {}
		res["signature"] = "".join(["{0:02x}".format(x) for x in self.peFile.header.signature])
		res["machine"] = constants.MACHINE_TYPE[self.peFile.header.machine]
		res["numberOfSections"] = hex(self.peFile.header.numberof_sections)
		res["numberOfSections"] = str(datetime.datetime.fromtimestamp(self.peFile.header.time_date_stamps))
		res["pointerToSymbolTable"] = hex(self.peFile.header.pointerto_symbol_table)
		res["numberOfSymbols"] = str(self.peFile.header.numberof_symbols)
		res["sizeOfOptionalHeader"] = str(self.peFile.header.sizeof_optional_header)
		res["characteristics"] = hex(self.peFile.header.characteristics)
		res["PE32"] = str(self.peFile.dos_header.magic == 267)
		jsonDict["FileHeader"] = res
		return jsonDict

	def printHeaderInformation(self):
		table = prettytable.PrettyTable()
		table.field_names = ["Property", "Value"]
		table.align["Property"] = "l"
		table.align["Value"] = "l"
		
		table.add_row(["Signature", "".join(["{0:02x}".format(x) for x in self.peFile.header.signature])])
		machine = self.peFile.header.machine
		table.add_row(["Machine", constants.MACHINE_TYPE[machine]])
		sections = self.peFile.header.numberof_sections
		table.add_row(["Number of sections", sections])
		timeDateStamp = datetime.datetime.fromtimestamp(self.peFile.header.time_date_stamps)
		if timeDateStamp > datetime.datetime.now():
			# The compile date is in the future
			table.add_row(["timeDateStamp", constants.RED + str(timeDateStamp) + constants.RESET])
		else:
			table.add_row(["timeDateStamp", timeDateStamp])
		pointerToSymbolTable = self.peFile.header.pointerto_symbol_table
		table.add_row(["pointerToSymbolTable", hex(pointerToSymbolTable)])
		numberOfSymbols = self.peFile.header.numberof_symbols
		table.add_row(["numberOfSymbols", numberOfSymbols])
		# TODO Check that optional header size is within thresholds
		sizeOfOptionalHeader = self.peFile.header.sizeof_optional_header
		table.add_row(["sizeOfOptionalHeader", sizeOfOptionalHeader])
		characteristics = self.peFile.header.characteristics
		table.add_row(["characteristics", hex(characteristics)])
		PE32 = (self.peFile.dos_header.magic == 267)
		table.add_row(["Processor 32-bit", PE32])
		if timeDateStamp > datetime.datetime.now():
			print("File Header: %sSuspicious value for TimeDateStamp (%s)%s" % (constants.RED, str(timeDateStamp) ,constants.RESET))
		else:
			print("File Header:")
		resultString = str(re.sub(r'(^|\n)', r'\1\t', str(table)))
		print(resultString)
		
	def printSections(self):
		table = prettytable.PrettyTable()
		table.field_names = ["Name", "Size", "Virtual Size", "Offset", "Virtual address", "Entropy", "Permissions"]
		
		for section in self.peFile.sections:
			rights = ""
			rights += "R" if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_READ) else "-"
			rights += "W" if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE) else "-"
			rights += "X" if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE) else "-"
			table.add_row([section.name, section.size, section.virtual_size, section.offset, section.virtual_address, section.entropy, rights])
		
		resultString = str(re.sub(r'(^|\n)', r'\1\t', str(table)))
		print(resultString)
		
	def addTLSXml(self, root):
		tls = ET.SubElement(root, "TlsCallbacks")
		if not self.peFile.has_tls:
			return
		callback_elem = ET.SubElement(tls, "callback-addr")
		table_entry_address = self.peFile.tls.addressof_callbacks
		callback = self.peFile.get_content_from_virtual_address(table_entry_address, 4)
		callback = '0x' + "".join(["{0:02x}".format(x) for x in callback[::-1]])
		while int(callback, 16) !=0:
			callback_elem.text = callback
			table_entry_address +=4
			callback = self.peFile.get_content_from_virtual_address(table_entry_address, 4)
			callback = '0x' + "".join(["{0:02x}".format(x) for x in callback])
		
		return root
	
	def addTLSJson(self, jsonDict):
		jsonDict["TlsCallbacks"] = []
		if not self.peFile.has_tls:
			return jsonDict
		table_entry_address = self.peFile.tls.addressof_callbacks
		callback = self.peFile.get_content_from_virtual_address(table_entry_address, 4)
		callback = '0x' + "".join(["{0:02x}".format(x) for x in callback[::-1]])
		while int(callback, 16) !=0:
			jsonDict["TlsCallbacks"].append(callback)
			table_entry_address +=4
			callback = self.peFile.get_content_from_virtual_address(table_entry_address, 4)
			callback = '0x' + "".join(["{0:02x}".format(x) for x in callback])
		
		return jsonDict

	def printTLS(self):
		if not self.peFile.has_tls:
			print(constants.GREEN + "No TLS callbacks found." + constants.RESET)
			return
		print(constants.RED + "List of TLS callbacks found: " + constants.RESET)
		table_entry_address = self.peFile.tls.addressof_callbacks
		callback = self.peFile.get_content_from_virtual_address(table_entry_address, 4)
		callback = '0x' + "".join(["{0:02x}".format(x) for x in callback[::-1]])
		while int(callback, 16) !=0:
			print('\t' + callback)
			table_entry_address +=4
			callback = self.peFile.get_content_from_virtual_address(table_entry_address, 4)
			callback = '0x' + "".join(["{0:02x}".format(x) for x in callback])
	
	def searchAllStrings(self):
		self.strings = set()
		for sect in self.peFile.sections:
			s = ""
			for byte in sect.content:
				if chr(byte) in string.printable:
					s += chr(byte)
				else:
					if len(s) > 3:
						self.strings.add(s)
					s = ""
	
	def findURLS(self):
		if self.strings is None:
			self.searchAllStrings()
		
		# Adapted from https://gist.github.com/uogbuji/705383
		GRUBER_URLINTEXT_PAT = re.compile(r'(?i)\b((?:(https?|ftp|mailto|file|data|irc)://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?\xab\xbb\u201c\u201d\u2018\u2019]))')
		urls = []
		for s in self.strings:
			url = GRUBER_URLINTEXT_PAT.findall(s)
			if len(url) > 0:
				urls.append(url[0][0])
		# TODO: We would have to check the URLs against a database (e.g. VirusTotal, Google Safe Browsing, ...)
		return urls
	
	def getBlacklistedStrings(self, printToConsole = True):
		if self.strings is None:
			self.searchAllStrings()
		
		table = prettytable.PrettyTable()
		table.field_names = ["String", "Group"]
		stringsXml = ET.parse("xml/strings.xml").getroot()
		blacklisted = 0
		# TODO: Maybe use regex instead of checking if the string is in the list of strings?
		for r in stringsXml.find('psw').findall('item'):
			if r.text in self.strings:
				table.add_row([r.text, "Passwords"])
				blacklisted += 1
		for r in stringsXml.find('avs').findall('av'):
			if r.text in self.strings:
				table.add_row([r.text, "Anti-Virus detection"])
				blacklisted += 1
		for r in stringsXml.find('regexs').findall('regex'):
			if r.text in self.strings:
				table.add_row([r.text, "Regular expressions"])
				blacklisted += 1
		for r in stringsXml.find('privs').findall('priv'):
			if r.text in self.strings:
				table.add_row([r.text, "Privileges"])
				blacklisted += 1
		for r in stringsXml.find('oids').findall('oid'):
			if r.text in self.strings:
				table.add_row([r.text, "oids"])
				blacklisted += 1
		for r in stringsXml.find('agents').findall('agent'):
			if r.text in self.strings:
				table.add_row([r.text, "Agents"])
				blacklisted += 1
		for r in stringsXml.find('exts').findall('ext'):
			if r.text in self.strings:
				table.add_row([r.text, "File extensions"])
				blacklisted += 1
		for r in stringsXml.find('sddls').findall('sddl'):
			if r.text in self.strings:
				table.add_row([r.text, "SDDLs"])
				blacklisted += 1
		allFolders = [f for fs in stringsXml.findall('folders') for f in fs.findall('folder')]
		for r in allFolders:
			if r.text in self.strings:
				if r.attrib['name'] is not None:
					table.add_row([r.text, "Folders (%s)" % r.attrib['name']])
				else:
					table.add_row([r.text, "Folders"])
				blacklisted += 1
		for r in stringsXml.find('guids').findall('guid'):
			if r.text in self.strings:
				table.add_row([r.text, "GUIDs"])
				blacklisted += 1
		for r in stringsXml.find('regs').findall('reg'):
			if r.text in self.strings:
				table.add_row([r.text, "Registry"])
				blacklisted += 1
		for r in stringsXml.find('oss').findall('os'):
			if r.text in self.strings:
				table.add_row([r.text, "Operating Systems"])
				blacklisted += 1
		for r in stringsXml.find('products').findall('product'):
			if r.text in self.strings:
				table.add_row([r.text, "Sandbox products"])
				blacklisted += 1
		for r in stringsXml.find('sids').findall('sid'):
			if r.text in self.strings:
				table.add_row([r.text, "SIDs"])
				blacklisted += 1
		for r in stringsXml.find('protocols').findall('protocol'):
			if r.text in self.strings:
				table.add_row([r.text, "Protocols"])
				blacklisted += 1
		for r in stringsXml.find('utilities').findall('item'):
			if r.text in self.strings:
				table.add_row([r.text, "Utilities"])
				blacklisted += 1
		keys = 0
		for r in stringsXml.find('keys').findall('key'):
			if r.text in self.strings:
				table.add_row([r.text, "Keyboard keys"])
				blacklisted += 1
				keys += 1
		for r in stringsXml.find('oss').findall('os'):
			if r.text in self.strings:
				table.add_row([r.text, "Operating Systems"])
				blacklisted += 1
		for r in stringsXml.find('events').findall('event'):
			if r.text in self.strings:
				table.add_row([r.text, "Events"])
				blacklisted += 1
		insults = 0
		for r in stringsXml.find('insults').findall('insult'):
			if r.text in self.strings:
				table.add_row([r.text, "Insult"])
				blacklisted += 1
				insults += 1
		for r in stringsXml.find('dos_stub').findall('item'):
			if r.text in self.strings:
				table.add_row([r.text, "DOS stubs"])
				blacklisted += 1
		# TODO: To me, these don't seem to be bad. Maybe we should remove them??
		for r in stringsXml.find('strings').findall('item'):
			if r.text in self.strings:
				table.add_row([r.text, "Further strings"])
				blacklisted += 1
		
		if printToConsole:
			if insults > 0:
				print(constants.RED + "%d insults found in the file" % (insults) + constants.RESET)
			else:
				print(constants.GREEN + "No insults found in the file" + constants.RESET)
			
			if keys > 0:
				print(constants.RED + "%d keyboard keys are used by the file" % (keys) + constants.RESET)
			else:
				print(constants.GREEN + "No keyboard keys are used in the file" + constants.RESET)
			
			if blacklisted > 0:
				print(constants.RED + "The following %d out of %d strings are blacklisted:" % (blacklisted, len(self.strings)) + constants.RESET)
				resultString = str(re.sub(r'(^|\n)', r'\1\t', str(table)))
				print(resultString)
			else:
				print(constants.GREEN + "No blacklisted strings found" + constants.RESET)
		
		return blacklisted, insults, keys
	
	def printAllStrings(self):
		if self.strings is None:
			self.searchAllStrings()
		res = ""
		for s in self.strings:
			res += s + "\n"
		return res
	
	def addAllStringsXml(self, root):
		if self.strings is None:
			self.searchAllStrings()
		
		strings = ET.SubElement(root, "Strings")
		for s in self.strings:
			ET.SubElement(strings, "str").text = s
			
		return root
	
	def addAllStringsJson(self, jsonDict):
		if self.strings is None:
			self.searchAllStrings()
		jsonDict["Strings"] = [str(s) for s in self.strings]
		return jsonDict
	
	def printExports(self):
		if not self.peFile.has_exports: # Max threshold 3000?
			print(constants.GREEN + "The binary has no exports" + constants.RESET)
			return
		
		table = prettytable.PrettyTable()
		table.field_names = ["Name", "Address"]
		for entry in self.peFile.get_export().entries:
			table.add_row([entry.name, hex(entry.address)])
		
		print("Exports of the binary:")
		resultString = str(re.sub(r'(^|\n)', r'\1\t', str(table)))
		print(resultString)
	
	def addExportsXml(self, root):
		exports = ET.SubElement(root, "Exports")
		if not self.peFile.has_exports:
			return root
		
		for entry in self.peFile.get_export().entries:
			exp = ET.SubElement(exports, "export")
			exp.text = entry.name
			exp.attrib['address'] = hex(entry.address)
		
		return root
	
	def addExportsJson(self, jsonDict):
		jsonDict["Exports"] = []
		if not self.peFile.has_exports:
			return jsonDict
		
		for entry in self.peFile.get_export().entries:
			jsonDict["Exports"].append({"address": hex(entry.address), "name": entry.name})
		
		return jsonDict
	
	def printRelocations(self):
		if not self.peFile.has_relocations:
			print(constants.GREEN + "The binary uses no relocations" + constants.RESET)
			return
		
		table = prettytable.PrettyTable()
		table.field_names = ["Virtual address", "Position", "Type", "Size"]
		for reloc in self.peFile.relocations:
			for entry in reloc.entries:
				table.add_row([hex(reloc.virtual_address), hex(entry.position), hex(entry.type), str(entry.size)])
		
		print("Relocations of the binary:")
		resultString = str(re.sub(r'(^|\n)', r'\1\t', str(table)))
		print(resultString)
	
	def addRelocationsXml(self, root):
		relocations = ET.SubElement(root, "Relocations")
		if not self.peFile.has_relocations:
			return root
		
		for reloc in self.peFile.relocations:
			for entry in reloc.entries:
				relocation = ET.SubElement(exports, "relocation")
				relocation.text = hex(entry.position)
				relocation.attrib['va'] = hex(reloc.virtual_address)
				relocation.attrib['type'] = hex(entry.type)
				relocation.attrib['size'] = str(entry.size)
		
		return root
	
	def addRelocationsJson(self, jsonDict):
		if not self.peFile.has_relocations:
			jsonDict["Relocations"] = {}
			return jsonDict
		
		res = []
		for reloc in self.peFile.relocations:
			for entry in reloc.entries:
				res.append({"position": hex(entry.position), "va": hex(reloc.virtual_address),
					"type": hex(entry.type), "size": str(entry.size)})
		
		jsonDict["Relocations"] = res
		return jsonDict

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='PE file analyzer')
	parser.add_argument("-f", "--file", help="The file to analyze", required=True, dest="file")
	args = parser.parse_args()
	
	peAnalyzer = PeAnalyzer(args.file)	
	peAnalyzer.printImportInformation()
	blacklistedResources = peAnalyzer.blacklistedResources()
	print(constants.RED + "Blacklisted resources found: " + str(blacklistedResources) if len(blacklistedResources) > 0 else constants.GREEN + "No blacklisted resources found", constants.RESET)
	# TODO: Check resource types and corresponding thresholds in thresholds.xml
	
	peAnalyzer.showAllResources()
	peAnalyzer.printHeaderInformation()
	peAnalyzer.printTLS()
	#print(peAnalyzer.printAllStrings())
	peAnalyzer.getBlacklistedStrings()
	peAnalyzer.printExports()
	peAnalyzer.printRelocations()
	
	
