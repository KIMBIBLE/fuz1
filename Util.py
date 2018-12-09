import os
import subprocess

from setting   import *

# This is a read access violation in a block data move, and is therefore classified as probably exploitable 

def classifyCrash(crash_file):
	result = ""

	cdb_cmd = ""
	cdb_cmd += ";.echo 'cmd : ub eip'"
	cdb_cmd += ";ub eip"
	cdb_cmd += ";.echo 'cmd : !load msec'"
	cdb_cmd += ";!load msec"
	cdb_cmd += ";.echo 'cmd : !exploitable'"
	cdb_cmd += ";!exploitable"
	cdb_cmd += ";.echo 'cmd : q'"
	cdb_cmd += ";q"

	cmdset = [dbg_path, "-G", "-g", "-o", "-c", cdb_cmd, "-logo", "classfication.log", hwp_path, crash_file]
  	proc = subprocess.Popen(cmdset, bufsize=0, shell=True)
  	#os.system(dbg_path + " -G -g -o -c " + cdb_cmd + " -logo classfication.log " + hwp_path + " "+ fuzzing_file)
  	proc.wait()

  	if os.path.isfile("classfication.log") is True:
		with open("classfication.log", "rb") as f:
			classfication_log = f.readlines()
			for each in classfication_log:
				if 'Exploitability Classification:' in each:
					result = each.split()[2]
					print "[*] CRASH : " + result + "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
					break

		os.remove("classfication.log")

	return result








