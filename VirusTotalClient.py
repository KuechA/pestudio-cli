import requests
import json
import logging
import argparse
import os
import prettytable
import re

FORMAT = '%(asctime)-15s %(message)s' 
logging.basicConfig(format=FORMAT)
logger = logging.getLogger("VirusTotalClient")
logger.setLevel(50)

class VirusTotalClient:

	def __init__(self, file):
		self.file = file
		with open('VirusTotalApiKey', 'r') as keyFile:
			self.key = keyFile.read().strip()

	def sendRequest(self):
		params = {'apikey': self.key}
		files = {'file': (self.file, open(self.file, 'rb'))}
		response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
		
		if response.status_code == 200: # Response: OK
			json_response = response.json()
			logger.info("Sent: %s, Response: %s", os.path.basename(self.file), str(json_response))
			return json_response['resource']
		else:
			logger.warning("Sent: %s, HTTP: %d", os.path.basename(self.file), res.status_code)
			return None

	def getReport(self, resourceId):
		params = {'apikey': self.key, 'resource': resourceId}
		headers = {"Accept-Encoding": "gzip, deflate", "User-Agent" : "VirusTotalClient"}
		response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
		if response.status_code == 200: # Response: OK
			json_response = response.json()
			logger.info("Report: %s", str(json_response))
			return json_response
		else:
			logger.warning("Sent: %s, HTTP: %d", os.path.basename(self.file), res.status_code)
			return None

	def parseReport(self, report, showPositiveResults = True):
		resultString = "VirusTotal result: " + str(report['positives']) + " of " + str(report['total']) + " tests are positive\n"
		if showPositiveResults and not report['positives'] == 0:
			table = prettytable.PrettyTable()
			table.field_names = ["Engine", "Version", "Result"]
			for test, result in report["scans"].items():
				if result['detected']:
					table.add_row([test, version, result['result']])
		
			resultString += str(re.sub(r'(^|\n)', r'\1\t', str(table)))
		return resultString

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Virustotal File Scan')
	parser.add_argument("-f", "--file", help="The file to scan", required=True, dest="file")
	args = parser.parse_args()
	
	vt = VirusTotalClient(args.file)
	resource = vt.sendRequest()
	if resource is not None:
		report = vt.getReport(resource)
		print(vt.parseReport(report))
		