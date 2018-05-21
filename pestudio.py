#!/usr/bin/python3

import argparse
from SignatureMatcher import SignatureMatcher
from PeAnalyzer import PeAnalyzer
from VirusTotalClient import VirusTotalClient
import prettytable
import re
import constants

def parseCommandLineArguments():
	parser = argparse.ArgumentParser(description='PE file analyzer. If no file is specifies, the interactive mode is entered.')
	parser.add_argument("-f", "--file", help="The file to analyze", required=False, dest="file")
	parser.add_argument("-v", "--virusTotal", help="Submit the file to virus total and get their score.", action="store_true", dest="virusTotal")
	parser.add_argument("--header", help="Show information from header.", action="store_true", dest="header")
	parser.add_argument("-i", "--imports", help="Check the imports against known malicious functions.", action="store_true", dest="imports")
	parser.add_argument("-r", "--resources", help="Check the resources for blacklisted values.", action="store_true", dest="resources")
	parser.add_argument("-s", "--signatures", help="Check for known signatures (e.g. packers).", action="store_true", dest="signatures")
	return parser.parse_args()

def interactiveMode():
	print("No file has been specified. Entering interactive mode...")

def checkFile(args):
	if args.virusTotal:
		vt = VirusTotalClient(args.file)
		resource = vt.sendRequest()
		if resource is not None:
			report = vt.getReport(resource)
			print(vt.parseReport(report))
	
	peAnalyzer = PeAnalyzer(args.file)
	
	if args.header:
		peAnalyzer.printHeaderInformation()
	
	if args.imports:
		suspicious, imp = peAnalyzer.checkImportNumber()
		print("Number of imports is in a reasonable range (%d)" % imp if suspicious else "Suspicious number of imports (%d)" % imp)
		
		blacklistedImports, imports = peAnalyzer.blacklistedImports()
		if len(blacklistedImports):
			print(constants.RED + "The following %d out of %d imports are blacklisted:" % (len(blacklistedImports), len(imports)) + constants.RESET)
			table = prettytable.PrettyTable()
			table.field_names = ["Library", "Function", "Group"]
			
			for imp in blacklistedImports:
				table.add_row([imp['lib'], imp['fct'], imp['group']])
			
			resultString = str(re.sub(r'(^|\n)', r'\1\t', str(table)))
			print(resultString)
		else:
			print("None of the imports is blacklisted")
	
	if args.resources:
		blacklistedResources = peAnalyzer.blacklistedResources()
		print("Blacklisted resources found: " + str(blacklistedResources) if len(blacklistedResources) > 0 else "No blacklisted resources found")
		# TODO: Check resource types and corresponding thresholds in thresholds.xml
		
		peAnalyzer.showAllResources()
	
	if args.signatures:
		matcher = SignatureMatcher(args.file)
		signatures, maxSize = matcher.getSignatures()
		packers = matcher.findPackers(signatures, maxSize)
		if len(packers):
			print(constants.RED + "The signature of the following packer was found: " + str(packers) + constants.RESET)
		else:
			print("No packer signature was found in the PE file")
	

if __name__ == "__main__":
	args = parseCommandLineArguments()
	if args.file is None:
		interactiveMode()
	else:
		checkFile(args)