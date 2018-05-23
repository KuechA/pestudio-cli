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
		self.peFile = lief.parse(file)
		self.strings = None

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
		pattern = re.compile(r"[A-Za-z0-9]{4,}")
		ranges = ((ord('A'), ord('Z')), (ord('a'), ord('z')), (ord('0'), ord('9')))
		self.strings = []
		print(string.printable)
		for sect in self.peFile.sections:
			s = ""
			for byte in sect.content:
				if chr(byte) in string.printable:
					s += chr(byte)
				else:
					if len(s) > 3:
						self.strings.append(s)
					s = ""
	
	def printAllStrings(self):
		if self.strings is None:
			self.searchAllStrings()
		for s in self.strings:
			print(s)
	
	def addAllStringsXml(self, root):
		if self.strings is None:
			self.searchAllStrings()
		
		strings = ET.SubElement(root, "Strings")
		for s in self.strings:
			ET.SubElement(strings, "str").text = s
			
		return root

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
	peAnalyzer.printAllStrings()
	
	
