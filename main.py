#!/usr/bin/python
__desc__= "Extract meta data from McAfee Quarantine XOR'd files"
__author__ = "Scott Dermott"
__version__ = "1.0.0"
__maintainer__ = "Scott Dermott"
__email__ = "scottdermott@outlook.com"

import subprocess
import sys
import os
import hashlib
import csv
import time
import datetime
import shutil
from os import walk

quarantine_dir = 'Quarantine/'
extracted_dir = quarantine_dir+'extracted/'

def seven_zip(zip_file):
	# print zip_file
	file_name = zip_file.split('.')[0]
	out_dir = extracted_dir+file_name
	process = subprocess.Popen(['7z.exe', 'x', quarantine_dir+zip_file, '-o'+out_dir], stderr=subprocess.PIPE)
	exitcode = process.wait()
	# print exitcode
	if exitcode != 0:
		print "ERROR : ", subprocess.stderr

def xor_extract(file_name, out_exten):
	if os.path.isfile(file_name):
		process = subprocess.Popen(['xor.exe', file_name, file_name+out_exten, '0X6A'], stderr=subprocess.PIPE)
		exitcode = process.wait()
		# print exitcode
		if exitcode != 0:
			print "ERROR : xor_extract"
			if process.stderr:
				print process.stderr.readlines()


def getFilesNames(dir):
	for (dirpath, dirnames, filenames) in walk(dir):
		return filenames

def getDirectoryNames(dir):
	for (dirpath, dirnames, filenames) in walk(dir):
		return dirnames

def parseDetailsFile(filePath):
	detail_obj = {}
	return_obj = {}
	file = open(filePath)
	for line in file :
	    if "=" in line:
	    	l = line.split('=')
	    	detail_obj[l[0].strip()] = l[1].strip()

	date_str = '%s-%s-%s' % (detail_obj['CreationDay'], detail_obj['CreationMonth'], detail_obj['CreationYear'])
	time_str = '%s:%s:%s' % (detail_obj['CreationHour'], detail_obj['CreationMinute'], detail_obj['CreationSecond'])
	ts = datetime.datetime(int(detail_obj['CreationYear']), int(detail_obj['CreationMonth']), int(detail_obj['CreationDay']), int(detail_obj['CreationHour']), int(detail_obj['CreationMinute']),  int(detail_obj['CreationSecond']))
	
	if 'OriginalName' in detail_obj:
		OriginalName =  detail_obj['OriginalName']
	else:
		OriginalName = "unknown"
	if 'DetectionName' in detail_obj:
		DetectionName =  detail_obj['DetectionName']
	else:
		DetectionName = "unknown"

	return_obj = {
		'isoDate' : ts.isoformat(),
		'time' : ts.time(),
		'date' : date_str,
		'originalName' : OriginalName,
		'detectionName' : DetectionName
	}
	file.close()
	return return_obj

def getMD5(file_name):
	if os.path.isfile(file_name):
		return hashlib.md5(open(file_name, 'rb').read()).hexdigest()
	else:
		return "unknown"

# Start
shutil.rmtree(extracted_dir)
bup_files = getFilesNames(quarantine_dir)
for zip_name in bup_files:
	print zip_name
	seven_zip(zip_name)

extracted_dirs = getDirectoryNames(extracted_dir)
with open('bup_output.csv', 'wb') as myfile:
    wr = csv.writer(myfile, quoting=csv.QUOTE_ALL)
    wr.writerow(['Date', 'Name', 'Original Name', 'Detection Name', 'MD5 Checksum'])
    for dir_name in extracted_dirs:
		print dir_name
		xor_extract(extracted_dir+dir_name+'/Details', '.txt')
		details = parseDetailsFile(extracted_dir+dir_name+'/Details.txt')

		xor_extract(extracted_dir+dir_name+'/File_0', '.xor')
		checksum = getMD5(extracted_dir+dir_name+'/File_0.xor')
		print 'Name :', dir_name
		print 'Date :', details['isoDate']
		print 'OriginalName :', details['originalName']
		print 'DetectionName :', details['detectionName']
		print 'MD5 Checksum :', checksum
		print '====================================='
		wr.writerow([details['isoDate'], dir_name, details['originalName'], details['detectionName'], checksum])
