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
import sys
import pydoc
import datetime

def parseCommandLineArguments():
	parser = argparse.ArgumentParser(description='PE file analyzer. The default output is human-readable and structured in tables. If no file is specifies, the interactive mode is entered.')
	parser.add_argument("-f", "--file", help="The file to analyze", required=False, dest="file")
	parser.add_argument("-v", "--virusTotal", help="Submit the file to virus total and get their score.", action="store_true", dest="virusTotal")
	parser.add_argument("--header", help="Show information from header.", action="store_true", dest="header")
	parser.add_argument("-t", "--tlsCallbacks", help="Show addresses of TLS callbacks.", action="store_true", dest="tls")
	parser.add_argument("-i", "--imports", help="Check the imports against known malicious functions.", action="store_true", dest="imports")
	parser.add_argument("-e", "--exports", help="Show the exports of the binary", action="store_true", dest="exports")
	parser.add_argument("-r", "--resources", help="Check the resources for blacklisted values.", action="store_true", dest="resources")
	parser.add_argument("--relocations", help="Show the relocations.", action="store_true", dest="relocations")
	parser.add_argument("-s", "--signatures", help="Check for known signatures (e.g. packers).", action="store_true", dest="signatures")
	parser.add_argument("--strings", help="Check the strings in the PE file.", action="store_true", dest="strings")
	parser.add_argument("-x", "--xml", help="Format output as xml.", action="store_true", dest="xml")
	parser.add_argument("-j", "--json", help="Format output as JSON.", action="store_true", dest="json")
	parser.add_argument("--interactive", help="Use the tool in interactive mode.", action="store_true", dest="interactive")
	return parser.parse_args()

def collectIndicators(vt, peAnalyzer, matcher):
	print("Indicators:")
	
	if peAnalyzer.peFile is None:
		print(constants.RED + "The file is not a PE file" + constants.RESET)
		return
	
	# VirusTotal result
	try:
		#vt.getReport()
		#if vt.report['positives']:
		#	vtRes = constants.RED
		#else:
		#	vtRes = constants.GREEN
		#vtRes += "\tVirusTotal result: " + str(vt.report['positives']) + " of " + str(vt.report['total']) + " tests are positive" + constants.RESET
		#print(vtRes)
		pass
	except:
		print(constants.BLUE + "\tNo connection to VirusTotal possible" + constants.RESET)
	
	peAnalyzer.printIndicators()
	
	# Suspicious header information
	timeDateStamp = datetime.datetime.fromtimestamp(peAnalyzer.peFile.header.time_date_stamps)
	if timeDateStamp > datetime.datetime.now():
		print("%s\tFile Header: Suspicious value for TimeDateStamp (%s)%s" % (constants.RED, str(timeDateStamp), constants.RESET))
	else:
		print(constants.GREEN + "\tFile Header seems to be valid" + constants.RESET)
	
	# Blacklisted imports and suspicious number of imports
	if peAnalyzer.checkImportNumber():
		print(constants.GREEN + "\tNumber of imports is in a reasonable range (%d)" % len(peAnalyzer.imports), constants.RESET)
	else:
		print(constants.RED + "\tSuspicious number of imports (%d)" % len(peAnalyzer.imports) + constants.RESET)
	
	suspicious, totalImp = peAnalyzer.blacklistedImports()
	if len(suspicious):
		print(constants.RED + "\t%d out of %d imports are blacklisted" % (len(suspicious), len(peAnalyzer.imports)) + constants.RESET)
	else:
		print(constants.GREEN + "\tNo blacklisted imports found" + constants.RESET)
	
	# Blacklisted resources
	resources = peAnalyzer.blacklistedResources()
	if len(resources):
		print(constants.RED + "\t%d blacklisted resources found" % (len(resources)) + constants.RESET)
	else:
		print(constants.GREEN + "\tNo blacklisted resources found" + constants.RESET)
	
	# tls callbacks
	if peAnalyzer.peFile.has_tls:
		print(constants.RED + "\tThe PE file uses TLS callbacks." + constants.RESET)
	else:
		print(constants.GREEN + "\tNo TLS callbacks used PE file" + constants.RESET)
	
	# relocations
	if not peAnalyzer.peFile.has_relocations:
		print(constants.GREEN + "\tThe binary uses no relocations" + constants.RESET)
	else:
		print(constants.RED + "\tThe binary uses relocations" + constants.RESET)
	
	# Blacklisted strings
	blacklisted, insults, keys = peAnalyzer.getBlacklistedStrings(False)
	if insults > 0:
		print(constants.RED + "\t%d insults found in the file" % (insults) + constants.RESET)
	else:
		print(constants.GREEN + "\tNo insults found in the file" + constants.RESET)
	
	if keys > 0:
		print(constants.RED + "\t%d keyboard keys are used by the file" % (keys) + constants.RESET)
	else:
		print(constants.GREEN + "\tNo keyboard keys are used in the file" + constants.RESET)
	
	if blacklisted > 0:
		print(constants.RED + "\t%d strings are blacklisted" % (blacklisted) + constants.RESET)
	else:
		print(constants.GREEN + "\tNo blacklisted strings found" + constants.RESET)
	
	# Packer signatures
	packers = matcher.findPackers()
	if len(packers):
		print(constants.RED + "\tThe signature of the following packer was found: " + str(packers) + constants.RESET)
	else:
		print(constants.GREEN + "\tNo packer signature was found in the PE file" + constants.RESET)
		

def interactiveMode(file = None):
	peAnalyzer = None
	matcher = None
	vt = None
	print("Entering interactive mode...")
	if file is None:
		print("Please specify file to analyze")
	user_in = input(">> ")
	while user_in != "q" and user_in != "quit":
		if user_in.startswith("file ") or user_in.startswith("f "):
			# File is specified
			args = user_in.split(" ")
			if len(args) > 2:
				print("Please use the command only with one argument: file|f <filename>")
			else:
				# TODO: Check if file exists.
				file = args[1]
				peAnalyzer = PeAnalyzer(file)
				matcher = SignatureMatcher(file)
				vt = VirusTotalClient(file)
		elif user_in == "header" or user_in == "h":
			print("Printing header")
			peAnalyzer.printHeaderInformation()
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
		else:
			if user_in != "help":
				print("Command '" + user_in + "' is unknown.")
			print("Known commands:")
			print("\thelp - print help text")
			print("\tf/file <filename> - specify which file should be analyzed")
			print("\tq/quit - quit the program")
			print("\tindicators - show indicators of malware in the PE file")
			print("\th/header - show information extracted from the header")
			print("\ti/imports - show imports of the PE file")
			print("\te/exports - show exports of the PE file")
			print("\tr/resources - show resources of the PE file")
			print("\tt/tlsCallbacks - show TLS callback addresses of the PE file")
			print("\trelocations - show relocation table of the PE file")
			print("\tstrings -a - show all strings we can find in the PE file")
			print("\tstrings -b - show blacklisted strings we can find in the PE file")
			print("\ts/signatures - find signatures of malicious patterns or packers in the PE file")
			print("\thelp - print this help text")
		user_in = input(">> ")

def checkFile(args):
	if args.xml:
		root = ET.Element("Report")
	elif args.json:
		jsonDict = {}

	if args.virusTotal:
		vt = VirusTotalClient(args.file)
		if args.xml:
			root = vt.getXmlReport(root)
		elif args.json:
			jsonDict = vt.getJsonReport(jsonDict)
		else:
			print(vt.printReport())
	
	peAnalyzer = PeAnalyzer(args.file)
	
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
		matcher = SignatureMatcher(args.file)
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