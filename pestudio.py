#!/usr/bin/python3

import argparse
from SignatureMatcher import SignatureMatcher
from PeAnalyzer import PeAnalyzer
from VirusTotalClient import VirusTotalClient
import prettytable
import re
import constants
import xml.etree.ElementTree as ET
import sys

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
	parser.add_argument("--interactive", help="Use the tool in interactive mode.", action="store_true", dest="interactive")
	return parser.parse_args()

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
			print("Strings in the PE file:")
			peAnalyzer.printAllStrings()
		elif user_in == "strings -b":
			peAnalyzer.getBlacklistedStrings()
		elif user_in == "signatures" or user_in == "s":
			packers = matcher.findPackers()
			if len(packers):
				print(constants.RED + "The signature of the following packer was found: " + str(packers) + constants.RESET)
			else:
				print(constants.GREEN + "No packer signature was found in the PE file" + constants.RESET)
		else:
			if user_in != "help":
				print("Command '" + user_in + "' is unknown.")
			print("Known commands:")
			print("\tq/quit - quit the program")
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

	if args.virusTotal:
		vt = VirusTotalClient(args.file)
		if args.xml:
			root = vt.getXmlReport(root)
		else:
			print(vt.printReport())
	
	peAnalyzer = PeAnalyzer(args.file)
	
	if args.header:
		if args.xml:
			peAnalyzer.addHeaderInformationXml(root)
		else:
			peAnalyzer.printHeaderInformation()
	
	if args.tls:
		if args.xml:
			peAnalyzer.addTLSXml(root)
		else:
			peAnalyzer.printTLS()
	
	if args.imports:
		if args.xml:
			root = peAnalyzer.getImportXml(root)
		else:
			peAnalyzer.printImportInformation()
	
	if args.exports:
		if args.xml:
			root = peAnalyzer.addExportsXml(root)
		else:
			peAnalyzer.printExports()
	
	if args.relocations:
		if args.xml:
			root = peAnalyzer.addRelocationsXml(root)
		else:
			peAnalyzer.printRelocations()
	
	if args.resources:
		blacklistedResources = peAnalyzer.blacklistedResources()
		
		if args.xml:
			root = peAnalyzer.addResourcesXml(root)
		else:
			print("Blacklisted resources found: " + str(blacklistedResources) if len(blacklistedResources) > 0 else "No blacklisted resources found")
			# TODO: Check resource types and corresponding thresholds in thresholds.xml
			
			peAnalyzer.showAllResources()
	
	if args.strings:		
		if args.xml:
			root = peAnalyzer.addAllStringsXml(root)
		else:
			print("Strings in the PE file:")
			peAnalyzer.printAllStrings()
			peAnalyzer.getBlacklistedStrings()
	
	if args.signatures:
		matcher = SignatureMatcher(args.file)
		packers = matcher.findPackers()
		
		if args.xml:
			root = matcher.addPackersXml(root)
		else:
			if len(packers):
				print(constants.RED + "The signature of the following packer was found: " + str(packers) + constants.RESET)
			else:
				print(constants.GREEN + "No packer signature was found in the PE file" + constants.RESET)
	
	if args.xml:
		print(ET.tostring(root).decode('utf-8'))
	

if __name__ == "__main__":
	args = parseCommandLineArguments()
	if args.file is None or args.interactive:
		interactiveMode(args.file)
	else:
		checkFile(args)