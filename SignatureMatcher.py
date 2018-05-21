import pepy
import binascii
import argparse
import xml.etree.ElementTree as ET
import re

class Signature:
	def __init__(self, name, sig, ep):
		self.name = name
		self.sig = sig
		self.ep = ep

	def __str__(self):
		return "\"" + self.name + "\" having signature " + self.sig + ", ep: " + str(self.ep)

class SignatureMatcher:
	def __init__(self, file):
		self.peFile = pepy.parse(file)

	def getSignatures(self):
		'''
		Parses signature.xml file to extract the signature names and patterns
		'''
		sigs = ET.parse("xml/signatures.xml").getroot().find('sigs')
		signatures = []
		maxSize = 0
		for sig in sigs.findall('sig'):
			name = sig.find('text').text
			signature = sig.find('pattern').text
			signature = re.sub(r"\s+", "", signature)
			signature = signature.replace("x", ".").lower()
			if len(signature) > maxSize:
				maxSize = len(signature)
			ep = sig.find('ep').text == 'true'
			signatures.append(Signature(name, signature, ep))
		return signatures, maxSize

	def findPackers(self, signatures, maxSize):
		'''
		Scans the PE file for signatures we use to find packers
		'''
		matches = []
		for sect in self.peFile.get_sections():
			if sect.length:
				sectStart = str(binascii.hexlify(sect.data[:maxSize]))[2:-1]
				for signature in signatures:
					if re.match(signature.sig, sectStart):
						matches.append(signature.name)
		return matches

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='PE file analyzer')
	parser.add_argument("-f", "--file", help="The file to analyze", required=True, dest="file")
	args = parser.parse_args()
	
	matcher = SignatureMatcher(args.file)
	signatures, maxSize = matcher.getSignatures()
	packers = matcher.findPackers(signatures, maxSize)
	if len(packers):
		print("The signature of the following packer was found: ", packers)
	else:
		print("No packer signature was found in the PE file")