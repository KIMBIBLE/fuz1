# -*- coding: utf-8 -*- 

import os
import subprocess
import shutil
import time
import random

from file_IO            import *
from mutation           import *
from mutation_radamsa   import *
from setting            import *
from Util               import *

loop_cnt = 0   # total loop count
find_cnt = 0   # found crash count

seedfile_list = os.listdir(seed_path)
total_file_cnt = len(seedfile_list)

while True:
   crash_flag = False
   current_seedfile = ""
   filename = ""
   fuzzing_file = ""
   seed_file = ""

   current_seedfile = seed_path + seedfile_list[loop_cnt % total_file_cnt]
   
   seed_format = "." + current_seedfile.split('.')[-1]
   # set fuzzing file name with current time.
   filename = str(int(time.time())) + seed_format
   fuzzing_file = result_path + filename

   if mute_type == 0:
      seed_file = getSeedfile(current_seedfile)
      # make mutated fuzzing file.
      putFile(fuzzing_file, mutation4(seed_file))

   elif mute_type == 1:

      cmd_set = [radamsa_path, "-o", fuzzing_file, "-n" , "1", current_seedfile]
#      print cmd_set
      proc = subprocess.Popen(cmd_set, bufsize=0, shell=True)
      radamsa_excute="radamsa.exe"+ fuzzing_file + " -n 1 " + current_seedfile
      proc.wait()
      print "[*] "+ radamsa_excute

      #os.system(radamsa_excute)
   else:
      print "[*] unknown mutation type"
      exit()
   
   print "Fuzzing File Created: " + hwp_path + " " + fuzzing_file

   '''
   [Detailed Option Description]
   [reference] : https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/cdb-command-line-options

   [options]
   -G
   Ignores the final breakpoint at process termination. 
   By default, CDB stops during the image run-down process. 
   This option will cause CDB to exit immediately 
   when the child terminates. 
   This has the same effect as entering the command sxd epr. 
   For more information, see Controlling Exceptions and Events.

   -g
   Ignores the initial breakpoint in target application. 
   This option will cause the target application to continue 
   running after it is started or CDB attaches to it, 
   unless another breakpoint has been set. 
   See Initial Breakpoint for details.

   -o
   Debugs all processes launched by the target application 
   (child processes). 
   By default, processes created by the one you are debugging 
   will run as they normally do. 
   For other methods of controlling this, 
   see Debugging a User-Mode Process Using CDB.

   -c " command "
   Specifies the initial debugger command to run at start-up. 
   This command must be surrounded with quotation marks. 
   Multiple commands can be separated with semicolons. 
   (If you have a long command list, it may be easier 
   to put them in a script and then use the -c option 
   with the $<, $><, $><, $$>< (Run Script File) command.)

   -log{a|au|o|ou} LogFile
   Begins logging information to a log file. 
   If the specified file already exists, 
   it will be overwritten if -logo is used, 
   or output will be appended to the file if -loga is used. 
   The -logau and -logou options operate similar to 
   -loga and -logo respectively, except that the log file 
   is a Unicode file. 
   For more details, see Keeping a Log File in CDB.
   
   '''
   cdb_cmd = ""
   cdb_cmd += ";.echo '___crashed___'"
   cdb_cmd += ";.echo 'cmd : ub eip'"
   cdb_cmd += ";ub eip"
   cdb_cmd += ";.echo 'cmd : r'"
   cdb_cmd += ";r"
   cdb_cmd += ";.echo 'cmd :u eip'"
   cdb_cmd += ";u eip"
   cdb_cmd += ";.echo 'cmd : kb'"
   cdb_cmd += ";kb"
   cdb_cmd += ";.echo 'cmd : !load msec'"
   cdb_cmd += ";!load msec"
   cdb_cmd += ";.echo 'cmd : !exploitable'"
   cdb_cmd += ";!exploitable"
   cdb_cmd += ";.echo 'cmd : q'"
   cdb_cmd += ";q"

   cmdset = [dbg_path, "-G", "-g", "-o", "-c", cdb_cmd, "-logo", "crash.log", hwp_path, fuzzing_file]
   proc = subprocess.Popen(cmdset, bufsize=0, shell=True)

   timeout = time.time() + timeout_limit
   # sleep Parent process(fuzzer) until a user-specified timeout 
   # is encountered or the child process(cdb) is terminated.
   while(time.time() < timeout and proc.poll() == None):
      time.sleep(1)

   # kill cdb, if child process still running
   if proc.poll() == None:
      proc.terminate()
      os.system('taskkill.exe /f /IM cdb.exe')
      print "debugger(cdb) killed\n"

   if os.path.isfile("crash.log") is True:
      f = open("crash.log", "rb")
      crash_log = f.readlines()

      crash_flag = False
      f.close()

      # CRASH Check!!!
      for i in crash_log:
         if "___crashed___" in i:
            crash_flag = True
            break

      if crash_flag == True:
         crash_type = classifyCrash(fuzzing_file) 
         
         crash_identifier = result_path + crash_type + '\\' + filename
         print "[!] CRASH !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
         print "path : " + result_path
         print "type = " + crash_type
         print "name //" + filename
         os.makedirs(crash_identifier)

         shutil.copy('crash.log', crash_identifier)
         os.remove('crash.log')
         print "[*] COPY ORIGIN : " +  current_seedfile+"####################################################################################################################"
         shutil.copy(current_seedfile, crash_identifier)
         print "[*] FUZZING FILE : " + fuzzing_file +"####################################################################################################################"
         shutil.copy(fuzzing_file, crash_identifier)

         find_cnt += 1

      elif crash_flag == False:
         os.system('taskkill.exe /f /IM cdb.exe')

   
   os.remove(fuzzing_file)

   loop_cnt += 1

   with open('zet.log', 'w') as f:
      msg = "TRY  COUNT    : " + str(loop_cnt) + '\n'
      f.write(msg)
      print msg

      msg =  "FIND COUNT    : " + str(find_cnt) + '\n'
      f.write(msg)
      print msg
