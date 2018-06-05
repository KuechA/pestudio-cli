import lief
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
		self.peFile = lief.parse(file)

	def getSignatures(self):
		'''
		Parses signature.xml file to extract the signature names and patterns
		'''
		sigs = ET.parse("xml/signatures.xml").getroot().find('sigs')
		self.signatures = []
		self.maxSize = 0
		for sig in sigs.findall('sig'):
			name = sig.find('text').text
			signature = sig.find('pattern').text
			signature = re.sub(r"\s+", "", signature)
			signature = signature.replace("x", ".").lower()
			if len(signature) > self.maxSize:
				self.maxSize = len(signature)
			ep = sig.find('ep').text == 'true'
			self.signatures.append(Signature(name, signature, ep))
		return self.signatures, self.maxSize

	def findPackers(self):
		'''
		Scans the PE file for signatures we use to find packers
		'''
		self.getSignatures()
		
		self.matches = []
		for sect in self.peFile.sections:
			if sect.size:
				sectStart = "".join(["{0:02x}".format(x) for x in sect.content[:self.maxSize]])
				for signature in self.signatures:
					if re.match(signature.sig, sectStart):
						self.matches.append(signature.name)
		return self.matches
	
	def addPackersXml(self, root):
		packers = ET.SubElement(root, "Packers")
		for match in self.matches:
			packer = ET.SubElement(packers, "packer")
			packer.text = match
		
		return root
	
	def addPackersJson(self, jsonDict):
		jsonDict["Packers"] = self.matches
		return jsonDict


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='PE file analyzer')
	parser.add_argument("-f", "--file", help="The file to analyze", required=True, dest="file")
	args = parser.parse_args()
	
	matcher = SignatureMatcher(args.file)
	packers = matcher.findPackers()
	if len(packers):
		print("The signature of the following packer was found: ", packers)
	else:
		print("No packer signature was found in the PE file")
