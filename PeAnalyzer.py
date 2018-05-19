import pepy
import xml.etree.ElementTree as ET
import argparse
import hashlib
import prettytable

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
		return min < real < max, real

	def blacklistedImports(self):
		'''
		Parses the xml/functions.xml file and checks the functions blacklisted in the
		file against the imports found in the PE file. Returns the list of all matches.
		
		TODO: Support the group attribute in the function file
		TODO: Support the md5 hashes
		TODO: Support the families
		TODO: Support the imphashes
		'''
		imports = [{'lib': i.name.lower(), 'fct': i.sym} for i in self.peFile.get_imports()]
		root = ET.parse("xml/functions.xml").getroot()
		
		# Get all the blacklisted functions and libraries by name
		suspiciousFunctions = []
		for lib in root.find('libs').findall('lib'):
			if lib.find('fcts') is None:
				f = list(filter(lambda i: i['lib'] == lib.attrib['name'], imports))
				suspiciousFunctions += f
				continue
			for fct in lib.find('fcts'):
				f = list(filter(lambda i: i['lib'] == lib.attrib['name'] and i['fct'] == fct.text, imports))
				suspiciousFunctions += f
		
		return suspiciousFunctions, imports

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
		matches = []
		for r in resources:
			if r.text in resourceMD5:
				matches.append(dict[r.attrib['id']])
		
		return matches

	def showAllResources(self):
		# Get languages from file
		langs = ET.parse("xml/languages.xml").getroot().find('languages')
		languages = {}
		for lang in langs:
			languages[int(lang.attrib['id'], 16)] = lang.text
		
		# We could also get the type from translations.xml xml/resources, they differ sometimes
		table = prettytable.PrettyTable()
		table.field_names = ["Type", "Name", "MD5", "Language"]
		for resource in self.peFile.get_resources():
			type = resource.type_as_str()
			name = resource.name_str if resource.name_str else resource.name
			md5 = hashlib.md5(resource.data).hexdigest()
			language = languages[resource.lang]
			table.add_row([type, name, md5, language])
		
		print(table)
		

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='PE file analyzer')
	parser.add_argument("-f", "--file", help="The file to analyze", required=True, dest="file")
	args = parser.parse_args()
	
	peAnalyzer = PeAnalyzer(args.file)
	
	suspicious, imp = peAnalyzer.checkImportNumber()
	print("Number of imports is as expected" if suspicious else "Suspicious number of imports (%d)" % imp)
	
	blacklistedImports, imports = peAnalyzer.blacklistedImports()
	print("%d out of %d imports are blacklisted" % (len(blacklistedImports), len(imports)))
	# TODO: The blacklisted lib/fct can be found in features.xml to get a text description of what it does
	
	blacklistedResources = peAnalyzer.blacklistedResources()
	print("Blacklisted resources found: " + str(blacklistedResources) if len(blacklistedResources) > 0 else "No blacklisted resources found")
	# TODO: Check resource types and corresponding thresholds in thresholds.xml
	
	peAnalyzer.showAllResources()
