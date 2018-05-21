import pepy
import xml.etree.ElementTree as ET
import argparse
import hashlib
import prettytable
import time
import datetime
import constants
import re

class PeAnalyzer:
	def __init__(self, file):
		self.peFile = pepy.parse(file)

	def checkImportNumber(self):
		'''
		Extract the min/max number of imports and check if the number of imports in the PE
		file is in that range
		'''
		root = ET.parse("xml/thresholds.xml").getroot()
		min = int(root.find('thresholds').find('minimums').find('Imports').text)
		max = int(root.find('thresholds').find('maximums').find('Imports').text)
		real = len(self.peFile.get_imports())
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
		self.imports = [{'lib': i.name.lower(), 'fct': i.sym} for i in self.peFile.get_imports()]
		root = ET.parse("xml/functions.xml").getroot()
		
		groups = self.__read_groups()
		
		# Get all the blacklisted functions and libraries by name
		self.suspiciousFunctions = []
		for lib in root.find('libs').findall('lib'):
			if lib.find('fcts') is None:
				f = list(filter(lambda i: i['lib'] == lib.attrib['name'], self.imports))
				for function in f:
					function['group'] = groups[lib.attrib['group']]
				self.suspiciousFunctions += f
				continue
			for fct in lib.find('fcts'):
				f = list(filter(lambda i: i['lib'] == lib.attrib['name'] and i['fct'] == fct.text, self.imports))
				for function in f:
					function['group'] = groups[fct.attrib['group']]
				self.suspiciousFunctions += f
		
		return self.suspiciousFunctions, self.imports

	def printImportInformation(self):
		self.blacklistedImports()
		
		reasonableNumber = self.checkImportNumber()
		if reasonableNumber:
			print("Number of imports is in a reasonable range (%d)" % len(self.imports))
		else:
			print(constants.RED + "Suspicious number of imports (%d)" % len(self.imports) + constants.RESET)
		
		if len(self.suspiciousFunctions):
			print(constants.RED + "The following %d out of %d imports are blacklisted:" % (len(self.suspiciousFunctions), len(self.imports)) + constants.RESET)
			table = prettytable.PrettyTable()
			table.field_names = ["Library", "Function", "Group"]
			
			for imp in self.suspiciousFunctions:
				table.add_row([imp['lib'], imp['fct'], imp['group']])
			
			resultString = str(re.sub(r'(^|\n)', r'\1\t', str(table)))
			print(resultString)
		else:
			print("None of the imports is blacklisted.")

	def getImportXml(self, root):
		self.blacklistedImports()
		
		imports = ET.SubElement(root, "Imports")
		summary = ET.SubElement(imports, "summary")
		ET.SubElement(summary, "blacklisted").text = str(len(self.suspiciousFunctions))
		ET.SubElement(summary, "total").text = str(len(self.imports))
		blacklisted = ET.SubElement(imports, "blacklisted")
		for imp in self.suspiciousFunctions:
			fct = ET.SubElement(blacklisted, "function")
			fct.set("library", imp['lib'])
			fct.set("group", imp['group'])
			fct.text = imp['fct']
		
		return root

	def blacklistedResources(self):
		'''
		Parses the xml/resources.xml file and returns the list of blacklisted resources that
		are used by the PE file to analyze.
		'''
		# Get the MD5 of resources used by the PE file
		resourceMD5 = [hashlib.md5(r.data).hexdigest().upper() for r in self.peFile.get_resources()]
		
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
		resources = ET.SubElement(root, "Resources")
		summary = ET.SubElement(resources, "summary")
		ET.SubElement(summary, "blacklisted").text = str(len(self.blacklistedRes))
		ET.SubElement(summary, "total").text = str(len(self.peFile.get_resources()))
		
		blacklisted = ET.SubElement(resources, "blacklisted")
		for res in self.blacklistedRes:
			fct = ET.SubElement(blacklisted, "resource-type")
			fct.text = res
		
		languages = self.__get_languages()
		
		allResources = ET.SubElement(resources, "resource-list")
		for resource in self.peFile.get_resources():
			type = resource.type_as_str()
			name = resource.name_str if resource.name_str else resource.name
			md5 = hashlib.md5(resource.data).hexdigest()
			language = languages[resource.lang]
			res = ET.SubElement(allResources, "resource")
			res.set("type", type)
			res.set("name", hex(name))
			res.set("language", language)
			res.text = md5
		
		return root

	def showAllResources(self):
		# Get languages from file
		languages = self.__get_languages()
		
		# We could also get the type from translations.xml xml/resources, they differ sometimes
		# and in translations.xml we have a "severity" value
		table = prettytable.PrettyTable()
		table.field_names = ["Type", "Name", "MD5", "Language"]
		for resource in self.peFile.get_resources():
			type = resource.type_as_str()
			name = resource.name_str if resource.name_str else hex(resource.name)
			md5 = hashlib.md5(resource.data).hexdigest()
			language = languages[resource.lang]
			table.add_row([type, name, md5, language])
		
		resultString = str(re.sub(r'(^|\n)', r'\1\t', str(table)))
		print(resultString)

	def addHeaderInformationXml(self, root):
		header = ET.SubElement(root, "FileHeader")
		signature = ET.SubElement(header, "signature")
		signature.text = hex(self.peFile.signature)
		machine = ET.SubElement(header, "machine")
		machine.text = constants.MACHINE_TYPE[self.peFile.machine]
		sections = ET.SubElement(header, "numberOfSections")
		sections.text = hex(self.peFile.numberofsections)
		timeDateStamp = ET.SubElement(header, "numberOfSections")
		timeDateStamp.text = str(datetime.datetime.fromtimestamp(self.peFile.timedatestamp))
		pointerToSymbolTable = ET.SubElement(header, "pointerToSymbolTable")
		pointerToSymbolTable.text = hex(self.peFile.pointertosymboltable)
		numberOfSymbols = ET.SubElement(header, "numberOfSymbols")
		numberOfSymbols.text = str(self.peFile.numberofsymbols)
		sizeOfOptionalHeader = ET.SubElement(header, "sizeOfOptionalHeader")
		sizeOfOptionalHeader.text = str(self.peFile.sizeofoptionalheader)
		characteristics = ET.SubElement(header, "characteristics")
		characteristics.text = hex(self.peFile.characteristics)
		PE32 = ET.SubElement(header, "PE32")
		PE32.text = str(self.peFile.magic == 267)
		
		return root

	def printHeaderInformation(self):
		table = prettytable.PrettyTable()
		table.field_names = ["Property", "Value"]
		table.align["Property"] = "l"
		table.align["Value"] = "l"
		
		signature = self.peFile.signature
		table.add_row(["Signature", hex(signature)])
		machine = self.peFile.machine
		table.add_row(["Machine", constants.MACHINE_TYPE[machine]])
		sections = self.peFile.numberofsections
		table.add_row(["Number of sections", sections])
		timeDateStamp = datetime.datetime.fromtimestamp(self.peFile.timedatestamp)
		if timeDateStamp > datetime.datetime.now():
			# The compile date is in the future
			table.add_row(["timeDateStamp", constants.RED + str(timeDateStamp) + constants.RESET])
		else:
			table.add_row(["timeDateStamp", timeDateStamp])
		pointerToSymbolTable = self.peFile.pointertosymboltable
		table.add_row(["pointerToSymbolTable", hex(pointerToSymbolTable)])
		numberOfSymbols = self.peFile.numberofsymbols
		table.add_row(["numberOfSymbols", numberOfSymbols])
		sizeOfOptionalHeader = self.peFile.sizeofoptionalheader
		table.add_row(["sizeOfOptionalHeader", sizeOfOptionalHeader])
		characteristics = self.peFile.characteristics
		table.add_row(["characteristics", characteristics])
		PE32 = (self.peFile.magic == 267)
		table.add_row(["Processor 32-bit", PE32])
		if timeDateStamp > datetime.datetime.now():
			print("File Header: %sSuspicious value for TimeDateStamp (%s)%s" % (constants.RED, str(timeDateStamp) ,constants.RESET))
		else:
			print("File Header:")
		resultString = str(re.sub(r'(^|\n)', r'\1\t', str(table)))
		print(resultString)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='PE file analyzer')
	parser.add_argument("-f", "--file", help="The file to analyze", required=True, dest="file")
	args = parser.parse_args()
	
	peAnalyzer = PeAnalyzer(args.file)	
	peAnalyzer.printImportInformation()
	blacklistedResources = peAnalyzer.blacklistedResources()
	print("Blacklisted resources found: " + str(blacklistedResources) if len(blacklistedResources) > 0 else "No blacklisted resources found")
	# TODO: Check resource types and corresponding thresholds in thresholds.xml
	peAnalyzer.showAllResources()
	
	peAnalyzer.printHeaderInformation()
