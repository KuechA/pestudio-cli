import pepy
import xml.etree.ElementTree as ET
import argparse

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
		tree = ET.parse("xml/functions.xml")
		root = tree.getroot()
		
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

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='PE file analyzer')
	parser.add_argument("-f", "--file", help="The file to analyze", required=True, dest="file")
	args = parser.parse_args()
	
	peAnalyzer = PeAnalyzer(args.file)
	suspicious, imp = peAnalyzer.checkImportNumber()
	print("Number of imports is as expected" if suspicious else "Suspicious number of imports (%d)" % imp)
	blacklisted, imports = peAnalyzer.blacklistedImports()
	print("%d out of %d imports are blacklisted" % (len(blacklisted), len(imports)))
