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

class Import:
	def __init__(self, lib, fct):
		self.lib = lib
		self.fct = fct
		self.blacklisted = False
		self.group = None

	def __str__(self):
		return self.lib + ": " + self.fct + ", blacklisted: " + str(self.blacklisted) + " with group: " + str(self.group)

class Resource:
	def __init__(self, type, name, language, md5):
		self.type = type
		self.name = name
		self.language = language
		self.md5 = md5
		
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
	
	def printIndicators(self):
		if self.peFile.name != self.file.split("/")[-1]: # TODO: Check if that's correct
			print("\tName: " + self.peFile.name + " differs from file name " + self.file.split("/")[-1])
		
		# Suspicious sizes: File, Optional header, file header, certificate
		# TODO: Read severity from indicators.xml?
		root = ET.parse("xml/thresholds.xml").getroot()
		mins = root.find('thresholds').find('minimums')
		maxs = root.find('thresholds').find('maximums')
		min = int(mins.find('Image').text)
		max = int(maxs.find('Image').text)
		if min <= self.peFile.optional_header.sizeof_image <= max:
			print(constants.GREEN + "\tSize of image is reasonable (%d bytes)" % self.peFile.optional_header.sizeof_image + constants.RESET)	
		else:
			print(constants.RED + "\tSize %d bytes of image is outside reasonable range (%d - %d bytes)" % (self.peFile.optional_header.sizeof_image, min, max) + constants.RESET)
		
		min = int(mins.find('file-header').text)
		max = int(maxs.find('file-header').text)
		#if min <= self.peFile.dos_header.header_size_in_paragraphs <= max: # TODO: This seems to be incorrect
		#	print(constants.GREEN + "\tSize of File Header is reasonable (%d bytes)" % self.peFile.sizeof_headers + constants.RESET)	
		#else:
		#	print(constants.RED + "\tSize %d bytes of File Header is outide reasonable range (%d - %d bytes)" % (self.peFile.sizeof_headers, min, max) + constants.RESET)
		
		min = int(mins.find('optional-header').text)
		max = int(maxs.find('optional-header').text)
		if min <= self.peFile.header.sizeof_optional_header <= max: # Not sure if that's correct
			print(constants.GREEN + "\tSize of Optional Header is reasonable (%d bytes)" % self.peFile.header.sizeof_optional_header + constants.RESET)	
		else:
			print(constants.RED + "\tSize %d bytes of Optional Header is outide reasonable range (%d - %d bytes)" % (self.peFile.header.sizeof_optional_header, min, max) + constants.RESET)
		
		# Content of certificate??, expired issuer, expired subject, no digital certificate
		if not self.peFile.has_signature:
			print(constants.RED + "\tThe PE file has no digital signature" + constants.RESET)
		else:
			for cert in self.peFile.signature.certificates:
				cert_from = datetime.datetime.fromtimestamp(cert.valid_from)
				cert_to = datetime.datetime.fromtimestamp(cert.valid_to)
				if cert_from > datetime.datetime.now() or cert_to < datetime.datetime.now():
					print(constants.RED + "\tDigital certificate is used which is not valid (from: %s to: %s)" + (str(cert_from), str(cert_to)) + constants.RESET)
			# TODO: We should check if the signature is valid but this seems to be ugly
		
		# Self-extractable file??
		# Managed by .NET??
		# References debug symbols
		
		# Code-less file
		min = int(mins.find('Code').text)
		if min > self.peFile.optional_header.sizeof_code:
			print(constants.RED + "\tThe file is code-less" + constants.RESET)
		
		# No manifest
		if not self.peFile.resources_manager.has_manifest:
			print(constants.RED + "\tThe file has no Manifest" + constants.RESET)
		
		# Entrypoint things
		lastSection = False
		for section in self.peFile.sections:
			lastSection = False
			start = self.peFile.optional_header.imagebase + section.virtual_address
			if start < self.peFile.entrypoint < start + section.size:
				# Entrypoint is in this section
				lastSection = True
				if not section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE):
					# Section is not marked as executable
					print(constants.RED + "\tEntrypoint (%s) in section %s which is not executable" % (hex(self.peFile.entrypoint), section.name) + constants.RESET)
		
		if lastSection:
			# The section of the entry point was the last section in the PE file
			print(constants.RED + "\tEntrypoint is in last section" + constants.RESET)
		
		if self.peFile.optional_header.imagebase > self.peFile.entrypoint > self.peFile.optional_header.imagebase + self.peFile.optional_header.sizeof_image:
			# Entry point outside file
			print(constants.RED + "\tEntrypoint (%s) is outside the file." % (hex(self.peFile.entrypoint)) + constants.RESET)
		
		if self.peFile.entrypoint == 0:
			print(constants.RED + "\tThe address of the entry-point is zero" + constants.RESET)
		
		# Invalid file checksum, checksum computed different to checksum
		# File ratio of resources
		if self.peFile.has_resources:
			rsrc_directory = self.peFile.data_directory(lief.PE.DATA_DIRECTORY.RESOURCE_TABLE)
			if rsrc_directory.has_section:
				min = int(mins.find('ProcentResource').text)
				max = int(maxs.find('ProcentResource').text)
				percentage = (rsrc_directory.section.size / self.peFile.optional_header.sizeof_image ) * 100
				if not (min <= percentage <= max):
					print(constants.RED + "\tThe file-ratio (%d) of the resources is suspicious" % (percentage) + constants.RESET)
		
		# PE file uses control flow guard
		if self.peFile.optional_header.has(lief.PE.DLL_CHARACTERISTICS.GUARD_CF):
			print(constants.RED + "\tThe file implements Control Flow Guard (CFG)" + constants.RESET)
		
		# PE file is a WDM device driver
		if self.peFile.optional_header.has(lief.PE.DLL_CHARACTERISTICS.WDM_DRIVER):
			print(constants.RED + "\tThe file is a Device Driver" + constants.RESET)
		
		# PE file makes use of DEP protection
		if self.peFile.optional_header.has(lief.PE.DLL_CHARACTERISTICS.NX_COMPAT):
			print(constants.RED + "\tThe file opts for Data Execution Prevention (DEP)" + constants.RESET)
		else:
			print(constants.RED + "\tThe file ignores Data Execution Prevention (DEP)" + constants.RESET)
		
		# PE file makes use of ASLR
		if self.peFile.optional_header.has(lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE):
			print(constants.RED + "\tThe file opts for Address Space Layout Randomization (ASLR)" + constants.RESET)
		else:
			print(constants.RED + "\tThe file ignores Address Space Layout Randomization (ASLR)" + constants.RESET)
		
		# PE file does not use of structured error handling (SEH)
		if self.peFile.optional_header.has(lief.PE.DLL_CHARACTERISTICS.NO_SEH):
			print(constants.RED + "\tThe file ignores Structured Exception Handling (SEH)" + constants.RESET)
		
		# PE file does not use GS
		if self.peFile.has_configuration:
			if self.peFile.load_configuration.security_cookie == 0:
				print(constants.RED + "\tThe file ignores cookies on the stack (GS)" + constants.RESET)
			else:
				print(constants.RED + "\tThe file opts for cookies on the stack (GS)" + constants.RESET)
		
		# PE file does not use code integrity
		if self.peFile.has_configuration:
			if isinstance(self.peFile.load_configuration, lief.PE.LoadConfigurationV2) and self.peFile.load_configuration.code_integrity.catalog == 0xFFFF:
				print(constants.RED + "\tThe file ignores Code Integrity" + constants.RESET)
		
		# Get the pdb debug file name
		data_dir = self.peFile.data_directory(lief.PE.DATA_DIRECTORY.DEBUG)
		if data_dir.size != 0:
			dbg_file_name_lst = self.peFile.get_content_from_virtual_address(data_dir.rva, self.peFile.optional_header.imagebase + self.peFile.data_dir.size - 24)
			dbg_file_name = "".join(chr(c) for c in dbg_file_name_lst)
			print(constants.RED + "\tThe file references a debug symbols file (path: %s)" % (dbg_file_name) + constants.RESET)
			if dbg_file_name.split(".")[-1] != ".pdb":
				print(constants.RED + "\tThe debug file name extension %s is suspicous" % (dbg_file_name.split(".")[-1]) + constants.RESET)
		
		# Suspicious debug timestamp
		if self.peFile.has_debug:
			dbg_time = datetime.datetime.fromtimestamp(self.peFile.debug.timestamp)
			if dbg_time > time.now(): # TODO: There are more criteria for sure.
				print(constants.RED + "The age (%s) of the debug file is suspicious" % (str(dbg_time)) + constants.RESET)
		
		# Check entropy of the sections, number of shared sections
		min = int(mins.find('Entropy').text)
		max = int(maxs.find('Entropy').text)
		sharedSect = 0
		for sect in self.peFile.sections:
			if not min < sect.entropy < max:
				print(constants.RED + "\tThe entropy %d of section %s is suspicious" % (sect.entropy, sect.name) + constants.RESET)
			
			if sect.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_SHARED):
				sharedSect += 1
		
		min = int(mins.find('SharedSections').text)
		max = int(maxs.find('SharedSections').text)
		if not min < sharedSect < max:
			print(constants.RED + "\tThe shared section(s) (%d) reached the max (%d) threshold" % (sharedSect, max) + constants.RESET)
		
		# Check if first section is writable or last section is executable
		if list(self.peFile.sections)[0].has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE):
			print(constants.RED + "\tThe first section (name:%s) is writable" % (self.peFile.sections[0].name) + constants.RESET)
		
		if list(self.peFile.sections)[-1].has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE):
			print(constants.RED + "\tThe last section (name:%s) is executable" % (self.peFile.sections[0].name) + constants.RESET)
		
		# Size of initialized data
		min = int(mins.find('InitializedData').text)
		max = int(maxs.find('InitializedData').text)
		if not min < self.peFile.optional_header.sizeof_initialized_data < max:
			print(constants.RED + "The size of initialized data reached the max (%d bytes) threshold" % self.peFile.optional_header.sizeof_initialized_data + constants.RESET)
	
		# File references missing library
		
		# Check imphash
		self.checkImphashes()
	
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
				print(constants.RED + "Found matching imphash (%s) for the file" % imphash + constants.RESET)

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
					function.group = groups[lib.attrib['group']]
					function.blacklisted = True
				self.suspiciousFunctions += f
				continue
			for fct in lib.find('fcts'):
				f = list(filter(lambda i: i.lib == lib.attrib['name'] and i.fct == fct.text, self.imports))
				for function in f:
					function.group = groups[fct.attrib['group']]
					function.blacklisted = True
				self.suspiciousFunctions += f
		# TODO: We can replace the suspicious functions with filtering for imports which are blacklisted
		return self.suspiciousFunctions, self.imports

	def printImportInformation(self):
		
		reasonableNumber = self.checkImportNumber()
		if reasonableNumber:
			print(constants.GREEN + "Number of imports is in a reasonable range (%d)" % len(self.imports), constants.RESET)
		else:
			print(constants.RED + "Suspicious number of imports (%d)" % len(self.imports) + constants.RESET)
		
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
						self.resources.append(Resource(resourceType.id, name, lang.id, md5))
		
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
		blacklisted = ET.SubElement(resources, "blacklisted")
		
		languages = self.__get_languages()
		
		allResources = ET.SubElement(resources, "resource-list")
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
		if not self.peFile.has_tls:
			return
		jsonDict["TlsCallbacks"] = []
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
		jsonDict["Strings"] = self.strings
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
	
	
