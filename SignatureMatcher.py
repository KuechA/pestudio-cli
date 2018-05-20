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
		sigs = ET.parse("xml/signatures.xml").getroot().find('sigs')
		signatures = []
		for sig in sigs.findall('sig'):
			name = sig.find('text').text
			signature = sig.find('pattern').text
			signature = re.sub(r"\s+", " ", signature)
			ep = sig.find('ep').text == 'true'
			signatures.append(Signature(name, signature, ep))
		return signatures

	def findMatches(self):
		for sect in self.peFile.get_sections():
			if sect.length:
				print("\tSection: %s, First 10 bytes: 0x%s" % (sect.name, binascii.hexlify(sect.data[:10])))
			else:
				print("\Section %s has no data" % sect.name)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='PE file analyzer')
	parser.add_argument("-f", "--file", help="The file to analyze", required=True, dest="file")
	args = parser.parse_args()
	
	matcher = SignatureMatcher(args.file)
	print([str(s) for s in matcher.getSignatures()])
	matcher.findMatches()
