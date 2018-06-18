#!/usr/bin/python3

import argparse
from SignatureMatcher import SignatureMatcher
from PeAnalyzer import PeAnalyzer
from VirusTotalClient import VirusTotalClient
import prettytable
import re
import constants
import xml.etree.ElementTree as ET
import json
import readline, glob # to path auto complete
import pydoc
import datetime
import os

class Indicator:
	def __init__(self, enable, severity, id, text):
		self.enable = enable
		self.severity = severity
		self.id = id
		self.text = text

def parseCommandLineArguments():
	parser = argparse.ArgumentParser(description='PE file analyzer. The default output is human-readable and structured in tables. If no file is specifies, the interactive mode is entered.')
	parser.add_argument("-f", "--file", help="The file to analyze", required=False, dest="file")
	parser.add_argument("-v", "--virusTotal", help="Submit the file to virus total and get their score.", action="store_true", dest="virusTotal")
	parser.add_argument("--header", help="Show information from header.", action="store_true", dest="header")
	parser.add_argument("-t", "--tlsCallbacks", help="Show addresses of TLS callbacks.", action="store_true", dest="tls")
	parser.add_argument("-i", "--imports", help="Check the imports against known malicious functions.", action="store_true", dest="imports")
	parser.add_argument("--indicators", help="Check the indicators of the file.", action="store_true", dest="indicators")
	parser.add_argument("-e", "--exports", help="Show the exports of the binary", action="store_true", dest="exports")
	parser.add_argument("-r", "--resources", help="Check the resources for blacklisted values.", action="store_true", dest="resources")
	parser.add_argument("--relocations", help="Show the relocations.", action="store_true", dest="relocations")
	parser.add_argument("-s", "--signatures", help="Check for known signatures (e.g. packers).", action="store_true", dest="signatures")
	parser.add_argument("--strings", help="Check the strings in the PE file.", action="store_true", dest="strings")
	parser.add_argument("-x", "--xml", help="Format output as xml.", action="store_true", dest="xml")
	parser.add_argument("-j", "--json", help="Format output as JSON.", action="store_true", dest="json")
	parser.add_argument("--interactive", help="Use the tool in interactive mode.", action="store_true", dest="interactive")
	return parser.parse_args()

def parseIndicators():
	indicators = {}
	root = ET.parse("xml/indicators.xml").getroot().find('indicators')
	for indicator in root.findall('indicator'):
		indicators[indicator.attrib['id']] = Indicator(indicator.attrib['enable'], indicator.attrib['severity'], indicator.attrib['id'], indicator.text)
	
	return indicators

def collectIndicators(vt, peAnalyzer, matcher, all = False, root = None, jsonDict = None):
	if root is None and jsonDict is None:
		print("Indicators:")
	
	indicators = parseIndicators()
	
	score = 0
	maxScore = 0
	
	table = prettytable.PrettyTable()
	
	if peAnalyzer.peFile is None:
		print(constants.RED + "The file is not a PE file" + constants.RESET)
		return
	
	# VirusTotal result
	try:
		rootThresholds = ET.parse("xml/thresholds.xml").getroot()
		mins = rootThresholds.find('thresholds').find('minimums')
		maxs = rootThresholds.find('thresholds').find('maximums')
		vt.getReport()
		min = int(mins.find('VirustotalEnginesPositiv').text)
		max = int(maxs.find('VirustotalEnginesPositiv').text)
		maxScore += int(indicators['1120'].severity)
		if min <= vt.report['positives'] <= max and jsonDict is None and root is None:
			vtRes = constants.GREEN + "\t"
		elif jsonDict is None and root is None:
			vtRes = constants.RED
			score += int(indicators['1120'].severity)
		vtRes += "VirusTotal result: " + str(vt.report['positives']) + " of " + str(vt.report['total']) + " tests are positive" + constants.RESET
		if min <= vt.report['positives'] <= max:
			print(vtRes)
		else:
			if jsonDict is None and root is None:
				table.add_row([vtRes, indicators['1120'].severity])
	except:
		if jsonDict is None and root is None:
			print(constants.BLUE + "\tNo connection to VirusTotal possible" + constants.RESET)

	if not jsonDict is None:
		score, maxScore, jsonDict, root = peAnalyzer.printIndicators(indicators, score, maxScore, table, all=all, jsonDict=jsonDict)
	elif not root is None:
		score, maxScore, jsonDict, root = peAnalyzer.printIndicators(indicators, score, maxScore, table, all=all, root=root)
	else:
		score, maxScore, jsonDict, root = peAnalyzer.printIndicators(indicators, score, maxScore, table, all=all)
	
	if not jsonDict is None:
		score, maxScore, jsonDict, root = peAnalyzer.checkFeatures(indicators, score, maxScore, table, jsonDict=jsonDict)
	elif not root is None:
		score, maxScore, jsonDict, root = peAnalyzer.checkFeatures(indicators, score, maxScore, table, root=root)
	else:
		score, maxScore, jsonDict, root = peAnalyzer.checkFeatures(indicators, score, maxScore, table)
	
	
	if jsonDict is None and root is None: # print summary only for user interface mode
		# Suspicious header information
		timeDateStamp = datetime.datetime.fromtimestamp(peAnalyzer.peFile.header.time_date_stamps)
		if timeDateStamp > datetime.datetime.now():
			print("%s\tFile Header: Suspicious value for TimeDateStamp (%s)%s" % (constants.RED, str(timeDateStamp), constants.RESET))
		elif all:
			print(constants.GREEN + "\tFile Header seems to be valid" + constants.RESET)
		
		# Blacklisted imports and suspicious number of imports
		if not peAnalyzer.checkImportNumber():
			print(constants.GREEN + "\tNumber of imports is in a reasonable range (%d)" % len(peAnalyzer.imports), constants.RESET)
		elif all:
			print(constants.RED + "\tSuspicious number of imports (%d)" % len(peAnalyzer.imports) + constants.RESET)
		
		suspicious, totalImp = peAnalyzer.blacklistedImports()
		if len(suspicious):
			print(constants.RED + "\t%d out of %d imports are blacklisted" % (len(suspicious), len(peAnalyzer.imports)) + constants.RESET)
		elif all:
			print(constants.GREEN + "\tNo blacklisted imports found" + constants.RESET)
		
		# Blacklisted resources
		resources = peAnalyzer.blacklistedResources()
		if len(resources):
			print(constants.RED + "\t%d blacklisted resources found" % (len(resources)) + constants.RESET)
		elif all:
			print(constants.GREEN + "\tNo blacklisted resources found" + constants.RESET)
		
		# tls callbacks
		if peAnalyzer.peFile.has_tls:
			print(constants.RED + "\tThe PE file uses TLS callbacks." + constants.RESET)
		elif all:
			print(constants.GREEN + "\tNo TLS callbacks used PE file" + constants.RESET)
		
		# relocations
		if peAnalyzer.peFile.has_relocations:
			print(constants.RED + "\tThe binary uses relocations" + constants.RESET)
		elif all:
			print(constants.GREEN + "\tThe binary uses no relocations" + constants.RESET)
		
		# Blacklisted strings
		blacklisted, insults, keys = peAnalyzer.getBlacklistedStrings(False)
		if insults > 0:
			print(constants.RED + "\t%d insults found in the file" % (insults) + constants.RESET)
		elif all:
				print(constants.GREEN + "\tNo insults found in the file" + constants.RESET)
		
		if keys > 0:
			print(constants.RED + "\t%d keyboard keys are used by the file" % (keys) + constants.RESET)
		elif all:
			print(constants.GREEN + "\tNo keyboard keys are used in the file" + constants.RESET)
		
		if blacklisted > 0:
			print(constants.RED + "\t%d strings are blacklisted" % (blacklisted) + constants.RESET)
		elif all:
			print(constants.GREEN + "\tNo blacklisted strings found" + constants.RESET)
		
		# Packer signatures
		packers = matcher.findPackers()
		if len(packers):
			print(constants.RED + "\tThe signature of the following packer was found: " + str(packers) + constants.RESET)
		elif all:
			print(constants.GREEN + "\tNo packer signature was found in the PE file" + constants.RESET)
	
	## end if: summary only for user interface mode
	
	if not jsonDict is None:
		jsonDict["indicators"]["summary"] = {"Severity": str(score), "MaxSeverity": str(maxScore)}
	elif not root is None:
		indicatorsXml = root.find("indicators")
		indicatorsScore = ET.SubElement(indicatorsXml, "Summary")
		ET.SubElement(indicatorsScore, "MaxSeverity").text = str(maxScore)
		ET.SubElement(indicatorsScore, "Severity").text = str(score)
	else:
		table.field_names = ["Description", "Severity(" + str(score) + "/" + str(maxScore) + ")"]
		print(table)
	return jsonDict, root

def interactiveMode(file = None):
	peAnalyzer = None
	matcher = None
	vt = None
	print("Entering interactive mode...")
	if file is None:
		print("Please specify file to analyze or type help")
	
	
	def complete(text, state):
		text = text.replace("~", os.path.expanduser("~"))
		return (glob.glob(text+'*')+[None])[state]
    	
	readline.set_completer_delims(' \t\n;')
	readline.parse_and_bind("tab: complete")
	readline.set_completer(complete)
	
	no_user_in = True
	while no_user_in:
		try:
			user_in = input(">> ")
			no_user_in = False
		except EOFError:
			print("Please confirm with enter, don't use ctrl-D")
			no_user_in = True
	
	while user_in != "q" and user_in != "quit":
		if user_in.startswith("file ") or user_in.startswith("f "):
			# File is specified
			args = user_in.split(" ")
			if len(args) > 2:
				print("Please use the command only with one argument: file|f <filename>")
			else:
				file = args[1]
				file = file.replace("~", os.path.expanduser("~"))
				if not os.path.isfile(file):
					print(constants.BLUE + "Could not find the specified file %s" % file + constants.RESET)
				else:
					peAnalyzer = PeAnalyzer(file)
					matcher = SignatureMatcher(file)
					vt = VirusTotalClient(file)
		elif user_in != "help" and peAnalyzer is None:
			print("Select a file first")
		elif user_in == "header" or user_in == "h":
			print("Printing header")
			peAnalyzer.printHeaderInformation()
		elif user_in == "sections":
			print("Printing sections")
			peAnalyzer.printSections()
		elif user_in == "imports" or user_in == "i":
			peAnalyzer.printImportInformation()
		elif user_in == "exports" or user_in == "e":
			peAnalyzer.printExports()
		elif user_in == "resources" or user_in == "r":
			blacklistedResources = peAnalyzer.blacklistedResources()
			print("Blacklisted resources found: " + str(blacklistedResources) if len(blacklistedResources) > 0 else "No blacklisted resources found")
			peAnalyzer.showAllResources()
		elif user_in == "virusTotal" or user_in == "v":
			print(vt.printReport())
		elif user_in == "tlsCallbacks" or user_in == "t":
			peAnalyzer.printTLS()
		elif user_in == "relocations":
			peAnalyzer.printRelocations()
		elif user_in == "strings -a":
			pydoc.pager(peAnalyzer.printAllStrings())
		elif user_in == "strings -b":
			peAnalyzer.getBlacklistedStrings()
		elif user_in == "signatures" or user_in == "s":
			packers = matcher.findPackers()
			if len(packers):
				print(constants.RED + "The signature of the following packer was found: " + str(packers) + constants.RESET)
			else:
				print(constants.GREEN + "No packer signature was found in the PE file" + constants.RESET)
		elif user_in == "indicators":
			collectIndicators(vt, peAnalyzer, matcher)
		elif user_in == "indicators -a":
			collectIndicators(vt, peAnalyzer, matcher, all)
		else:
			if user_in != "help":
				print("Command '" + user_in + "' is unknown.")
			print("Known commands:")
			print("\v/virusTotal - submit the file to VirusTotal and display a summary of the result")
			print("\tf/file <filename> - specify which file should be analyzed")
			print("\tq/quit - quit the program")
			print("\tindicators - show indicators of malware in the PE file")
			print("\tindicators -a - show indicators of malware in the PE file (show all checks)")
			print("\th/header - show information extracted from the header")
			print("\ti/imports - show imports of the PE file")
			print("\te/exports - show exports of the PE file")
			print("\tr/resources - show resources of the PE file")
			print("\tt/tlsCallbacks - show TLS callback addresses of the PE file")
			print("\trelocations - show relocation table of the PE file")
			print("\ts/signatures - find signatures of malicious patterns or packers in the PE file")
			print("\tsections - show all sections in the file")
			print("\tstrings -a - show all strings we can find in the PE file")
			print("\tstrings -b - show blacklisted strings we can find in the PE file")
			print("\thelp - print this help text")
		
		no_user_in = True
		while no_user_in:
			try:
				user_in = input(">> ")
				no_user_in = False
			except EOFError:
				print("Please confirm with enter, don't use ctrl-D")
				no_user_in = True

def checkFile(args):
	if args.xml:
		root = ET.Element("Report")
	elif args.json:
		jsonDict = {}

	if not os.path.isfile(args.file):
		if args.xml:
			root.text = "Could not find the specified file " + args.file
			print(ET.tostring(root).decode('utf-8'))
		elif args.json:
			jsonDict["Error"] = "Could not find the specified file " + args.file
			print(json.dumps(jsonDict))
		else:
			print(constants.BLUE + "Could not find the specified file %s" % args.file + constants.RESET)
		return

	vt = VirusTotalClient(args.file)
	peAnalyzer = PeAnalyzer(args.file)
	matcher = SignatureMatcher(args.file)
	if args.virusTotal:
		if args.xml:
			root = vt.getXmlReport(root)
		elif args.json:
			jsonDict = vt.getJsonReport(jsonDict)
		else:
			print(vt.printReport())
	
	if args.indicators:
		if args.xml:
			jsonDict, root = collectIndicators(vt, peAnalyzer, matcher, root=root)
		elif args.json:
			jsonDict, root = collectIndicators(vt, peAnalyzer, matcher, jsonDict=jsonDict)
		else:
			collectIndicators(vt, peAnalyzer, matcher)
	
	if args.header:
		if args.xml:
			peAnalyzer.addHeaderInformationXml(root)
		elif args.json:
			jsonDict = peAnalyzer.addHeaderInformationJson(jsonDict)
		else:
			peAnalyzer.printHeaderInformation()
	
	if args.tls:
		if args.xml:
			root = peAnalyzer.addTLSXml(root)
		elif args.json:
			jsonDict = peAnalyzer.addTLSJson(jsonDict)
		else:
			peAnalyzer.printTLS()
	
	if args.imports:
		if args.xml:
			root = peAnalyzer.getImportXml(root)
		elif args.json:
			jsonDict = peAnalyzer.getImportJson(jsonDict)
		else:
			peAnalyzer.printImportInformation()
	
	if args.exports:
		if args.xml:
			root = peAnalyzer.addExportsXml(root)
		elif args.json:
			jsonDict = peAnalyzer.addExportsJson(jsonDict)
		else:
			peAnalyzer.printExports()
	
	if args.relocations:
		if args.xml:
			root = peAnalyzer.addRelocationsXml(root)
		elif args.json:
			jsonDict = peAnalyzer.addRelocationsJson(jsonDict)
		else:
			peAnalyzer.printRelocations()
	
	if args.resources:
		blacklistedResources = peAnalyzer.blacklistedResources()
		
		if args.xml:
			root = peAnalyzer.addResourcesXml(root)
		elif args.json:
			jsonDict = peAnalyzer.addResourcesJson(jsonDict)
		else:
			print("Blacklisted resources found: " + str(blacklistedResources) if len(blacklistedResources) > 0 else "No blacklisted resources found")
			# TODO: Check resource types and corresponding thresholds in thresholds.xml
			
			peAnalyzer.showAllResources()
	
	if args.strings:
		if args.xml:
			root = peAnalyzer.addAllStringsXml(root)
		if args.json:
			jsonDict = peAnalyzer.addAllStringsJson(jsonDict)
		else:
			print("Strings in the PE file:")
			print(peAnalyzer.printAllStrings())
			peAnalyzer.getBlacklistedStrings()
	
	if args.signatures:
		packers = matcher.findPackers()
		
		if args.xml:
			root = matcher.addPackersXml(root)
		elif args.json:
			jsonDict = matcher.addPackersJson(jsonDict)
		else:
			if len(packers):
				print(constants.RED + "The signature of the following packer was found: " + str(packers) + constants.RESET)
			else:
				print(constants.GREEN + "No packer signature was found in the PE file" + constants.RESET)
	
	if args.xml:
		print(ET.tostring(root).decode('utf-8'))
	elif args.json:
		print(json.dumps(jsonDict))

if __name__ == "__main__":
	args = parseCommandLineArguments()
	if args.file is None or args.interactive:
		interactiveMode(args.file)
	else:
		checkFile(args)
