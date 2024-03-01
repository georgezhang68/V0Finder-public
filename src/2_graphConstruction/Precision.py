
"""
Author:		Seunghoon Woo (seunghoonwoo@korea.ac.kr)
Modified: 	August 1, 2021.
"""

import os
import sys
import subprocess
import re
import tlsh # Please intall python-tlsh
import pandas as pd

"""GLOBALS"""

currentPath	= os.getcwd()
vulFuncPath = "../1_poolConstruction/CVEPool/vulFuncs/"
nvdVulPath  = "../1_poolConstruction/CVEPool/NVD_vulhashes"			# Default path
repoPath	= "../1_poolConstruction/SoftwarePool/repo_functions/"	# Default path
funcPath 	= "../1_poolConstruction/SoftwarePool/raw_functions/"	# Default path

resultCommitPath  = "../1_poolConstruction/SoftwarePool/resultCommit"
cloneResPath = currentPath + "/clone_detection_res"
sheetPath   = "../1_poolConstruction/SoftwarePool/GT_sha1.xlsx"

softwareCol = "Software_D"
localCommitCol = "LocatedPatch(es)"
cveCol = "CVE"
##############

def readExcel():
	dict = {}
	df = pd.read_excel(sheetPath, sheet_name="input")
	df = df[df["index"] == "yes"]
	for index, row in df.iterrows():
		software = row[softwareCol]
		commit = row[localCommitCol]
		cve = row[cveCol]
		if software == "cloud_kernel":
			software = "cloud-kernel"
		elif software == "khadas":
			software = "linux"

		if not commit in dict:
			dict[commit] = {software: [cve]}
		else:
			if not software in dict[commit]:
				dict[commit][software] = [cve]
			else:
				dict[commit][software].append(cve)
	return dict

def readResultCommit():
	list = []
	with open(resultCommitPath, 'r') as file:
		for item in file:
			list.append(item[:-1])
	return list

def handleCloneRes():
	fres 	= open(cloneResPath, 'r')
	cveIndex = 0
	softwareIndex = 5
	commitIndex = 6
	dict = {}

	for line in fres:
		lineList = list(line.split())
		if lineList[commitIndex] == lineList[commitIndex - 1]:
			continue
		software = lineList[softwareIndex].split('@@')[1]
		cve = lineList[cveIndex]
		commit = lineList[commitIndex]

		if not commit in dict:
			dict[commit] = {software: [cve]}
		else:
			if not software in dict[commit]:
				dict[commit][software] = [cve]
			else:
				dict[commit][software].append(cve)
	fres.close()
	return dict


def main():
	cloneResDict = handleCloneRes() # {commit: {software: [cve]}}
	GTDict = readExcel()	# {commit: {software: [cve]}}
	resultCommit = readResultCommit() # [commit, software]

	unpatched = 0 # <=> Found in clone_res, NOT patched in the commit~. What we don't want to see
	patched = 0 # <=> NOT Found in clone_res, patched in the commit~. What we want to see
	for item in resultCommit:
		commit = item.split(",")[0]
		software = item.split(",")[1]
		GTCVE = GTDict[commit][software]

		if commit not in cloneResDict:
			patched = patched + len(GTCVE)
			continue
		resCVE = cloneResDict.get(commit).get(software)

		for cve in GTCVE:
			if cve in resCVE:
				print(commit, cve, software)
				unpatched = unpatched + 1
			else:
				patched = patched + 1

	print("Unpatched =", unpatched)
	print("Patched =", patched)




""" EXECUTE """
if __name__ == "__main__":
	main()