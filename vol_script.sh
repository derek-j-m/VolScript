clear
usage ()
{
  echo " "
  echo "Usage : No variables are needed. Just place a copy of the script in the same directory as your RAM capture."
  echo "        A subdirectory called vol will be created and will contain the results of this script."
  echo " "
  exit 1
}

if [ ! -z "$1" ]
then
  usage
fi

echo " "
echo "____   ____    .__          __  .__.__  .__  __           ________         _____ " 
echo "\   \ /   /___ |  | _____ _/  |_|__|  | |__|/  |_ ___.__. \_____  \       /  |  |" 
echo " \   Y   /  _ \|  | \__  \\   __\   |  | |  \   __<   |  |  /  ___/       /   |  |_"
echo "  \     (  <_> )  |__/ __ \|  | |  |  |_|  ||  |  \___  | /       \     /    ^   /"
echo "   \___/ \____/|____(____  /__| |__|____/__||__|  / ____| \_______ \ /\ \____   | "
echo "                         \/                       \/              \/ \/      |__| "
echo " "
echo "The plugins and script is designed for Volatility 2.4. on an Ubuntu 14.0.1 system."
echo "Requires that nuhup, mactime, yara, and hashdeep are installed."
echo "*Optional are several plugins released by the outstanding memory forensics community."
echo "**Check the script for details on any non-vanilla plugins."
echo " "
#Setting a static path - currently using version 2.4 public release. Modify to fit your installation.
vol_path="/apps/memory/volatility"
#Reading contents of current directory. This script is designed to be modified for each case
#and run from the same directory as the RAM image.
#Assigning a case number or unique identifier.
echo " "
echo "Greetings $USER"
echo "Please enter a case number or unique identifier: "
read case_number
echo " "
pwd
ls -lah
echo 
#Comment out the next two lines if you don't wish to paste in the directory with the RAM capture
#echo "Please enter the full path to your memory capture: "
#read ram_path
#Uncomment the next line to use the working directory (pwd) as the default directory
ram_path=$(pwd)
echo "Please enter or paste the full image name: "
read ram_image
#Creating directory structure to hold output.
mkdir -p "$ram_path"/vol
mkdir -p "$ram_path"/vol/be_output
mkdir -p "$ram_path"/vol/dll_dump
mkdir -p "$ram_path"/vol/shots
mkdir -p "$ram_path"/vol/file_dump
mkdir -p "$ram_path"/vol/file_dump/pf
mkdir -p "$ram_path"/vol/file_dump/jpg
mkdir -p "$ram_path"/vol/evtlogs
#mkdir -p "$ram_path"/vol/pcap
mkdir -p "$ram_path"/vol/proc_dump
mkdir -p "$ram_path"/vol/procmem_dump
echo "+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+" > "$ram_path"/vol/time.log
echo "Analysis of $case_number started on: $(date)" >> "$ram_path"/vol/time.log
echo "Analysis of $case_number. Started on: $(date)" > "$ram_path"/vol/banner.log
echo "Script run by:  $USER" >> "$ram_path"/vol/time.log
echo "On the computer named: $HOSTNAME running: " $(uname -mrs) >> "$ram_path"/vol/time.log
echo "+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+" >> "$ram_path"/vol/time.log
echo " " >> "$ram_path"/vol/time.log
#Computing SHA256 hash of the image file.
echo "Computing the SHA256 hash of the ram image file."
nohup hashdeep -s -c sha256 "$ram_path"/"$ram_image" >> "$ram_path"/vol/time.log 2>&1 &
echo "Searching for the correct profile information by processing kdbgscan. Please wait." >> "$ram_path"/vol/time.log
echo "Searching for the correct profile information by processing kdbgscan. Please wait."
echo " "
python $vol_path/vol.py -f "$ram_path"/"$ram_image" kdbgscan > "$ram_path"/vol/kdbgscan.txt 
ram_profile=$(cat "$ram_path"/vol/kdbgscan.txt | grep "KDBGHeader" | cut -f 4 -d ' ' | sed -n '1p')
sleep 1
#Checking to see if kdbgscan found a profile.
if [ -n "$ram_profile" ]; then
	echo "Success!"
    echo "Profile is set to: $ram_profile."
else
	echo "kdbgscan has failed. I am so sorry."
	echo "Trying imageinfo instead. Please wait."
	python $vol_path/vol.py -f "$ram_path"/"$ram_image" imageinfo > "$ram_path"/vol/imageinfo.txt
	cat "$ram_path"/vol/imageinfo.txt
	echo "Please enter the identified profile: "
	read ram_profile
fi
echo " "
echo "Using profile: $ram_profile." >> "$ram_path"/vol/time.log
sleep 2
clear
echo "+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+" >> "$ram_path"/vol/time.log
echo " " >> "$ram_path"/vol/time.log
echo "Processing "$ram_image" in the "$ram_path" folder. Using profile: $ram_profile."
echo "Processing "$ram_image" in the "$ram_path" folder. Using profile: $ram_profile." >> "$ram_path"/vol/time.log
echo "Example: "
echo "python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile <command>"
echo "Example: " >> "$ram_path"/vol/time.log
echo "python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile <command>" >> "$ram_path"/vol/time.log
echo " "
echo "+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+" >> "$ram_path"/vol/time.log
echo "Attempting to run strings, pdgmail.py, and other grep terms."
echo "Attempting to run strings, pdgmail.py, and other grep terms." >> "$ram_path"/vol/time.log
echo "Running strings -el : 16-bit little endian"
strings -el "$ram_path"/"$ram_image" > "$ram_path"/vol/gmailstrings.str
echo "Running strings -a : all"
strings -a "$ram_path"/"$ram_image" >> "$ram_path"/vol/gmailstrings.str
echo "Finished running strings."
echo "Finished running strings." >> "$ram_path"/vol/time.log
echo "Running pdgmail.py. Download from: http://www.jeffbryner.com/code/pdgmail"
python /apps/memory/pdgmail.py -f "$ram_path"/vol/gmailstrings.str > "$ram_path"/vol/pdgmail_output.txt
echo "Searching for keywords. Modify to fit."
echo "Searching for keywords. Modify to fit." >> "$ram_path"/vol/time.log
echo "Searching for invalid UltraVNC connection attempts"
echo "Searching for invalid UltraVNC connection attempts" > "$ram_path"/vol/interesting_greps.txt
grep "Invalid attempt from client" "$ram_path"/vol/gmailstrings.str >> "$ram_path"/vol/interesting_greps.txt
echo "Searching for succesful UltraVNC connection attempts"
grep  --after-context=1 "Connection received from" "$ram_path"/vol/gmailstrings.str >> "$ram_path"/vol/interesting_greps.txt
echo "Searching for mstscax.dll usage - indicates remote desktop connections."
echo "Searching for mstscax.dll usage - indicates remote desktop connections." >> "$ram_path"/vol/time.log
grep -i --before-context=1 --after-context=1 '\\Windows\\system32\\mstscax.dll' "$ram_path"/vol/gmailstrings.str >> "$ram_path"/vol/interesting_greps.txt
#echo "Searching for <insert term here> remnants" >> "$ram_path"/vol/interesting_greps.txt
#grep "term" "$ram_path"/vol/gmailstrings.str >> "$ram_path"/vol/interesting_greps.txt
echo "Searching for Website history remnant" >> "$ram_path"/vol/interesting_greps.txt
echo "Searching for Website history remnant"
grep -i "Visited:" "$ram_path"/vol/gmailstrings.str >> "$ram_path"/vol/interesting_greps.txt
#echo "Searching for gmail posting" >> "$ram_path"/vol/interesting_greps.txt
#grep -i --after-context=1 "/mail?gxlu" "$ram_path"/vol/gmailstrings.str >> "$ram_path"/vol/interesting_greps.txt
#echo "Searching for Hotmail posting" >> "$ram_path"/vol/interesting_greps.txt
#grep -i --after-context=1 "@hotmail.com&pass" "$ram_path"/vol/gmailstrings.str >> "$ram_path"/vol/interesting_greps.txt
echo "Searching for term &passwd" >> "$ram_path"/vol/interesting_greps.txt
echo "Searching for term &passwd"
grep --after-context=1 "&passwd" "$ram_path"/vol/gmailstrings.str >> "$ram_path"/vol/interesting_greps.txt
rm "$ram_path"/vol/gmailstrings.str
echo "Finished running strings and pdgmail.py" >> "$ram_path"/vol/time.log
echo "Finished with pdgmail and other grep terms"
echo "+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+" >> "$ram_path"/vol/time.log
echo "Continuing Volatility processing."
echo "Continuing Volatility processing." >> "$ram_path"/vol/time.log
echo >> "$ram_path"/vol/time.log
#echo "Processing pstree first"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile pstree > "$ram_path"/vol/pstree.txt
echo "Processing a verbose pstree"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile pstree -v >> "$ram_path"/vol/pstree.txt
echo "Processing cmdline"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile cmdline > "$ram_path"/vol/cmdline.txt
echo "The following files are run from suspicious locations. Further research is needed for unrecognised files." > "$ram_path"/vol/suspicious_cmdline.txt
cat "$ram_path"/vol/cmdline.txt | grep -i -w 'temp\|appdata' | grep -i -v -w 'remcomsvc.exe\|dumpit.exe\|inetpub\|system32\|chrome\|firefox\|chrome\|mozilla\|spotify\|google\|akamai' | grep -i -v "ftk" | grep -i -v "program files" | awk '{print $3,$4,$5}' >> "$ram_path"/vol/suspicious_cmdline.txt
cat "$ram_path"/vol/suspicious_cmdline.txt
echo "Processing netscan"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile netscan > "$ram_path"/vol/netscan.txt

#---------------------------------------------TESTING---------------------------------------------
echo "Testing new plugins."
#echo "Processing editbox."
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile editbox -m > "$ram_path"/vol/editbox.txt
echo "Processing malprocfind."
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile malprocfind > "$ram_path"/vol/malprocfind.txt
echo "Processing chromehistory."
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile chromehistory > "$ram_path"/vol/chromehistory.txt
echo "Processing chromedownloads."
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile chromedownloads > "$ram_path"/vol/chromedownloads.txt
echo "Processing chromecookies."
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile chromecookies > "$ram_path"/vol/chromecookies.txt
echo "Processing firefoxhistory."
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile firefoxhistory > "$ram_path"/vol/firefoxhistory.txt
echo "Processing firefoxcookies."
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile firefoxcookies > "$ram_path"/vol/firefoxcookies.txt
echo "Processing idxparser."
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile idxparser > "$ram_path"/vol/idxparser.txt
echo "Processing prefetchparser."
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile prefetchparser > "$ram_path"/vol/prefetchparser.txt
echo "Processing uninstallinfo."
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile uninstallinfo > "$ram_path"/vol/uninstallinfo.txt
echo "Processing autoruns."
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile autoruns > "$ram_path"/vol/autoruns.txt
echo "Finished testing new plugins."
#---------------------------------------------TESTING---------------------------------------------


#echo "Processing auditpol"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile auditpol > "$ram_path"/vol/auditpol.txt
#echo "Processing bioskbd"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile bioskbd > "$ram_path"/vol/bioskbd.txt
echo "Processing cachedump"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile cachedump > "$ram_path"/vol/cachedump.txt
#echo "Processing callbacks"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile callbacks > "$ram_path"/vol/callbacks.txt
echo "Processing clipboard"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile clipboard > "$ram_path"/vol/clipboard.txt
echo "Processing cmdscan"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile cmdscan > "$ram_path"/vol/cmdscan.txt
echo "Processing connections"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile connections > "$ram_path"/vol/connections.txt
echo "Processing connscan"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile connscan > "$ram_path"/vol/connscan.txt
echo "Processing consoles"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile consoles > "$ram_path"/vol/consoles.txt
#echo "Processing deskscan"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile deskscan > "$ram_path"/vol/deskscan.txt
echo "Processing devicetree"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile devicetree > "$ram_path"/vol/devicetree.txt

#BE processing:
echo "Running bulk_extractor on all available cores - grab from https://github.com/simsong/bulk_extractor"
echo " "
echo " __________      .__   __    ___________         __                        __                  ____      .________   _______    "
echo " \______   \__ __|  | |  | __\_   _____/__  ____/  |_____________    _____/  |_  ___________  /_   |     |   ____/   \   _  \   "
echo "  |    |  _/  |  \  | |  |/ / |    __)_\  \/  /\   __\_  __ \__  \ _/ ___\   __\/  _ \_  __ \  |   |     |____  \    /  /_\  \  "
echo "  |    |   \  |  /  |_|    <  |        \>    <  |  |  |  | \// __ \\  \___|   | (  <_> )  | \/  |   |     /       \   \  \_/   \ "
echo "  |______  /____/|____/__|_ \/_______  /__/\_ \ |__|  |__|  (____  /\___  >__|  \____/|__|     |___| /\ /______  / /\ \_____  / "
echo "         \/                \/        \/      \/                  \/     \/                           \/        \/  \/       \/  "
echo " "
echo "+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+" >> "$ram_path"/vol/time.log
echo "Running bulk_extractor on all available cores" >> "$ram_path"/vol/time.log
echo " " >> "$ram_path"/vol/time.log
echo Bulk_Extractor analysis started on: $(date) >> "$ram_path"/vol/time.log
#Using nohup will allow Volatility to continue running while BE processes the image
#You can use regular expressions specifying -f for a single search term or -F for a file containing regex terms. 
nohup bulk_extractor "$ram_path"/"$ram_image" -o "$ram_path"/vol/be_output -e wordlist -x sqlite -b "$ram_path"/vol/banner.log >> "$ram_path"/vol/time.log 2>&1 &
echo " " >> "$ram_path"/vol/time.log

#echo "Processing dll_dump and dumping all dll files to: "$ram_path"/vol/dll_dump/"
#echo "Processing dll_dump and dumping all dll files to: "$ram_path"/vol/dll_dump/" >> "$ram_path"/vol/time.log
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile dlldump -D "$ram_path"/vol/dll_dump/ > "$ram_path"/vol/dlldump.txt
echo "Processing dlllist"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile dlllist > "$ram_path"/vol/dlllist.txt
#echo "Processing dnscachedump - testing from https://code.google.com/p/volatility/issues/detail?id=124"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile dnscachedump > "$ram_path"/vol/dnscachedump.txt
#echo "Processing dumpcerts and dumping them to: "$ram_path"/vol/certs/"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile dumpcerts --dump-dir "$ram_path"/vol/certs/ > "$ram_path"/vol/dumpcerts.txt
#echo "Processing dumpfiles to dump all files. Testing only, as it takes a long time."
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile dumpfiles --dump-dir "$ram_path"/vol/file_dump/ -n > "$ram_path"/vol/dumpfiles.txt
echo "Processing envars"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile envars > "$ram_path"/vol/envars.txt
#echo "Processing ethscan, a plugin recently released. Dumping pcap is a looooong process. Use with caution. http://jamaaldev.blogspot.com/2013/07/ethscan-volatility-memory-forensics.html"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile ethscan -D "$ram_path"/vol/pcap/ -C ram_netcap.pcap > "$ram_path"/vol/ethscan.txt
echo "Processing evtlogs and dumping them to: "$ram_path"/vol/evtlogs/"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile evtlogs -S -D "$ram_path"/vol/evtlogs/ > "$ram_path"/vol/evtlogs.txt
#echo "Processing facebook - must grab the facebook.py plugin from https://github.com/jeffbryner/volatilityPlugins and put it in the plugin folder"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile facebook > "$ram_path"/vol/facebook.txt
echo "Processing filescan"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile filescan > "$ram_path"/vol/filescan.txt

echo "Attempting to carve interesting files. Add more search terms if needed. Running twice as the formatting has been screwed up..."
echo "Attempting to carve interesting files." >> "$ram_path"/vol/time.log
grep "key3.db " "$ram_path"/vol/filescan.txt | sort -u > "$ram_path"/vol/interesting_files.txt
grep "cert8.db " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "signons.sqlite " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "Login Data " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "UsrClass.dat " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "NTUSER.DAT " "$ram_path"/vol/filescan.txt | grep -v "Service" | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "SECURITY " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "SAM " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "mslogon.log " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "SYSTEM " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "SOFTWARE " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".xlsx " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".xls " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".docx " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".doc " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".cs " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "recentservers.xml " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".pf " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files_pf.txt
grep ".dit " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".evtx " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".psafe3 " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "mslogon.log " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "Wlansvc" "$ram_path"/vol/filescan.txt | grep ".xml \|.xml$" | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "hosts " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".jpg " "$ram_path"/vol/filescan.txt | sort -u > "$ram_path"/vol/interesting_files_jpg.txt
grep -i "password" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
#Second run with end of line regex
grep "key3.db$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "cert8.db$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "signons.sqlite$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "Login Data$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "UsrClass.dat$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "NTUSER.DAT$" "$ram_path"/vol/filescan.txt | grep -v "Service" | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "SECURITY$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "SAM$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "mslogon.log$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "SYSTEM$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "SOFTWARE$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".xlsx$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".xls$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".docx$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".doc$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".cs$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "recentservers.xml$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".pf$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files_pf.txt
grep ".dit$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".evtx$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".psafe3$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "mslogon.log$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "hosts$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".jpg$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files_jpg.txt
grep -i "password" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt

cat "$ram_path"/vol/interesting_files.txt | awk '{print $1}' | sort -u > "$ram_path"/vol/carve_files.txt
for word in $(cat "$ram_path"/vol/carve_files.txt); do python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile dumpfiles --dump-dir "$ram_path"/vol/file_dump/ -n -Q $word; done >> "$ram_path"/vol/file_dump/dumped.txt
echo "Done testing the specified file carving."
cat "$ram_path"/vol/interesting_files_jpg.txt | awk '{print $1}' | sort -u > "$ram_path"/vol/carve_files_jpg.txt
for word in $(cat "$ram_path"/vol/carve_files_jpg.txt); do python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile dumpfiles --dump-dir "$ram_path"/vol/file_dump/jpg/ -n -Q $word; done >> "$ram_path"/vol/file_dump/jpg/dumped.txt

cat "$ram_path"/vol/interesting_files_pf.txt | awk '{print $1}' | sort -u > "$ram_path"/vol/carve_files_pf.txt
for word in $(cat "$ram_path"/vol/carve_files_pf.txt); do python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile dumpfiles --dump-dir "$ram_path"/vol/file_dump/pf/ -n -Q $word; done >> "$ram_path"/vol/file_dump/pf/dumped.txt
echo "Done testing the specified jpg file carving."


echo "Processing prefetch files"
echo "Processing prefetch files" >> "$ram_path"/vol/time.log
echo "Removing extra .dat file extension"
find "$ram_path"/vol/file_dump -type f -name '*.dat' | while read f; do mv "$f" "${f%.dat}"; done
find "$ram_path"/vol/file_dump -type f -name '*.vacb' | while read f; do mv "$f" "${f%.vacb}"; done
#Grab the excellent prefetch-parser from http://bitbucket.cassidiancybersecurity.com/prefetch-parser
python /path-to-plugins/plugins/prefetch.py -r "$ram_path"/vol/file_dump/pf >> "$ram_path"/vol/prefetch_files.txt
echo "Finished processing prefetch files."

echo "Processing gahti"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile gahti > "$ram_path"/vol/gahti.txt
echo "Processing getsids"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile getsids > "$ram_path"/vol/getsids.txt
cat "$ram_path"/vol/getsids.txt |  grep 'Domain\|Enterprise' > "$ram_path"/vol/getsids_domain_admins.txt
echo "Processing handles"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile handles > "$ram_path"/vol/handles.txt
cat "$ram_path"/vol/handles.txt | grep "\LanmanRedirector" > "$ram_path"/vol/handles_mapped_shares.txt
echo "Processing hivelist"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile hivelist > "$ram_path"/vol/hivelist.txt
#Searching for the registry files and their virtual address
virt_mem_sys=$(grep -i 'system \|system\>$' "$ram_path"/vol/hivelist.txt | awk '{print $1}')
virt_mem_SAM=$(grep 'SAM \|SAM\>' "$ram_path"/vol/hivelist.txt | awk '{print $1}')
virt_mem_sec=$(grep 'SECURITY \|SECURITY\>' "$ram_path"/vol/hivelist.txt | awk '{print $1}')
echo "Preparing to automatically parse the registry to extract the hashes - x86 only. Running: vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile hashdump -y $virt_mem_sys -s $virt_mem_SAM"
echo "Preparing to automatically parse the registry to extract the hashes. Running: vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile hashdump -y $virt_mem_sys -s $virt_mem_SAM" >> "$ram_path"/vol/time.log
echo "Processing hashdump"
echo "Processing hashdump" >> "$ram_path"/vol/time.log
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile hashdump -y $virt_mem_sys -s $virt_mem_SAM >> "$ram_path"/vol/hashdump.txt
echo "Processing hivescan"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile hivescan > "$ram_path"/vol/hivescan.txt
echo "Processing idt"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile idt > "$ram_path"/vol/idt.txt
echo "Processing iehistory"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile iehistory > "$ram_path"/vol/iehistory.txt
echo "Processing iehistory -L (LEAK - Deleted)"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile iehistory -L >> "$ram_path"/vol/iehistory.txt
echo "Processing imageinfo"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile imageinfo > "$ram_path"/vol/imageinfo.txt
echo "Processing impscan"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile impscan > "$ram_path"/vol/impscan.txt
#echo "Processing ldrmodules"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile ldrmodules -v > "$ram_path"/vol/ldrmodules_verbose.txt
#echo "Processing lsadump - WinXP only"
#echo "Preparing to automatically parse the registry to extract the hashes. Running: vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile lsadump -y $virt_mem_sys -s $virt_mem_sec" > "$ram_path"/vol/lsadump.txt
#echo "Preparing to automatically parse the registry to extract the hashes. Running: vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile lsadump -y $virt_mem_sys -s $virt_mem_sec" >> "$ram_path"/vol/time.log
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile lsadump -y $virt_mem_sys -s $virt_mem_sec >> "$ram_path"/vol/lsadump.txt
echo "Processing malfind"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile malfind > "$ram_path"/vol/malfind.txt
echo "Processing malsysproc - must grab plugin from https://github.com/Invoke-IR/Volatility"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile malsysproc > "$ram_path"/vol/malsysproc.txt
#echo "Processing mbrparser"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile mbrparser > "$ram_path"/vol/mbrparser.txt
#echo "Processing messagehooks"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile messagehooks > "$ram_path"/vol/messagehooks.txt

echo "Processing lsass output using the mimikatz plugin - must grab it from https://github.com/dfirfpi/hotoloti and put it in the plugin folder"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile mimikatz > "$ram_path"/vol/mimikatz.txt

echo "Processing pslist"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile pslist > "$ram_path"/vol/pslist.txt
echo "Processing psscan"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile psscan > "$ram_path"/vol/psscan.txt
echo "Processing psscan dot graph version"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile psscan --output=dot --output-file="$ram_path"/vol/psscan.dot
#The next line searches against a known good whitelist of services - not a home-run but a simple check.
cat "$ram_path"/vol/psscan.txt | awk '{print $2}' | grep -vwf /path-to-files/yarasigs/whitelist.txt | sort -u > "$ram_path"/vol/psscan_outliers.txt
echo "The following service(s) are not in the whitelist."
cat "$ram_path"/vol/psscan.txt | awk '{print $2}' | grep -vwf /path-to-files/yarasigs/whitelist.txt | sort -u
echo " "
echo "Creating a list for VirusTotal based on the outliers..."
echo "Creating a list for VirusTotal based on the outliers..." >> "$ram_path"/vol/time.log
#The next line is for grabbing the PID.
#cat "$ram_path"/vol/psscan.txt | grep -vwf /path-to-files/yarasigs/whitelist.txt | tr -s ' ' | cut -d ' ' -f3 | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' > "$ram_path"/vol/virustotal_hash.txt
#The next line is for grabbing the filename.
cat "$ram_path"/vol/psscan.txt | awk '{print $2}' | grep -vwf /path-to-files/yarasigs/whitelist.txt | sort -u | uniq > "$ram_path"/vol/virustotal_hash.txt

echo "Processing psxview"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile psxview > "$ram_path"/vol/psxview.txt
#echo "Processing openvpn"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile openvpn > "$ram_path"/vol/openvpn.txt
#echo "Processing modscan"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile modscan > "$ram_path"/vol/modscan.txt
echo "Processing mutantscan"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile mutantscan --silent > "$ram_path"/vol/mutantscan.txt
echo "Processing notepad"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile notepad > "$ram_path"/vol/notepad.txt
echo "Processing pooltracker"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile pooltracker > "$ram_path"/vol/pooltracker.txt
echo "Processing multiple printkey registry queries"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile printkey -K "SAM\Domains\Account\Users" > "$ram_path"/vol/printkey.txt
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile printkey -K "SAM\Domains\Account\Users\Names" >> "$ram_path"/vol/printkey_secrets.txt
#For plaintext Secret phrase export the following for each Names entry: printkey -K "SAM\Domains\Account\Users\<00000XXX>"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile printkey -K "SAM\Domains\Account\Users\000001F4" >> "$ram_path"/vol/printkey_secrets.txt
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile printkey -K "SAM\Domains\Account\Users\000001F5" >> "$ram_path"/vol/printkey_secrets.txt
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile printkey -K "SAM\Domains\Account\Users\000003EC" >> "$ram_path"/vol/printkey_secrets.txt
echo "Processing printkey - runonce"
echo "Microsoft\Windows\CurrentVersion\Run" > "$ram_path"/vol/printkey_runs.txt
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile printkey -K "Software\Microsoft\Windows\CurrentVersion\Run" >> "$ram_path"/vol/printkey_runs.txt
echo "Microsoft\Windows\CurrentVersion\Runonce" >> "$ram_path"/vol/printkey_runs.txt
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile printkey -K "Microsoft\Windows\CurrentVersion\Runonce" >> "$ram_path"/vol/printkey_runs.txt
echo "Microsoft\Windows NT\CurrentVersion\Winlogon" >> "$ram_path"/vol/printkey_runs.txt
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile printkey -K "Microsoft\Windows NT\CurrentVersion\Winlogon" >> "$ram_path"/vol/printkey_runs.txt
echo "Classes\.exe\shell\open\command" >> "$ram_path"/vol/printkey_runs.txt
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile printkey -K "Classes\.exe\shell\open\command" >> "$ram_path"/vol/printkey_runs.txt
echo "Classes\exefile\shell\open\command" >> "$ram_path"/vol/printkey_runs.txt
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile printkey -K "Classes\exefile\shell\open\command" >> "$ram_path"/vol/printkey_runs.txt
echo "Software\Microsoft\Command Processor\AutoRun" >> "$ram_path"/vol/printkey_runs.txt
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile printkey -K "Software\Microsoft\Command Processor\AutoRun" >> "$ram_path"/vol/printkey_runs.txt
echo "Processing privs"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile privs > "$ram_path"/vol/privs.txt
echo "Finding odd privileges"
cat "$ram_path"/vol/privs.txt | awk '{print $4}' | sort | uniq -c | grep -i -e "sebackupprivilege" -e "sedebugprivilege" -e "seloaddriverprivilege" -e "sechangenotifyprivilege" -e "seshutdownprivilege" > "$ram_path"/vol/privs_interesting.txt
echo "Processing procdump and dumping to: "$ram_path"/vol/proc_dump/"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile procdump -D "$ram_path"/vol/proc_dump/ > "$ram_path"/vol/procdump.txt
echo "Processing security - must grab the plugin from https://twitter.com/CGurkok and put it in the plugin folder"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile security > "$ram_path"/vol/security.txt
echo "Processing screenshot and dumping the files to: "$ram_path"/vol/shots/"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile screenshot -D "$ram_path"/vol/shots/ > "$ram_path"/vol/screenshot.txt
echo "Processing sessions"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile sessions > "$ram_path"/vol/sessions.txt
echo "Processing shimcache (new)"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile shimcache > "$ram_path"/vol/shimcache.txt
echo "Processing sockets"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile sockets > "$ram_path"/vol/sockets.txt
echo "Processing sockscan"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile sockscan > "$ram_path"/vol/sockscan.txt
#echo "Processing svcscan"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile svcscan --verbose > "$ram_path"/vol/svcscan.txt
echo "Processing symlinkscan"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile symlinkscan > "$ram_path"/vol/symlinkscan.txt
echo "Processing threads"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile threads -F AttachedProcess > "$ram_path"/vol/threads_attachedprocess.txt
echo "Processing thrdscan"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile thrdscan > "$ram_path"/vol/thrdscan.txt
#echo "Processing orphan threads"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile threads -F OrphanThread > "$ram_path"/vol/threads_orphan.txt
#echo "Processing timers"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile timers > "$ram_path"/vol/timers.txt
#echo "Processing truecryptsummary"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile truecryptsummary > "$ram_path"/vol/truecryptsummary.txt
#echo "Processing truecryptpassphrase"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile truecryptpassphrase > "$ram_path"/vol/truecryptpassphrase.txt
#echo "Processing twitter - must grab the plugin from https://github.com/jeffbryner/volatilityPlugins and put it in the plugin folder"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile twitter > "$ram_path"/vol/twitter.txt
echo "Processing userassist"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile userassist > "$ram_path"/vol/userassist.txt
#echo "Processing vadinfo"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile vadinfo > "$ram_path"/vol/vadinfo.txt
echo "Processing vadtree"
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile vadtree --output=dot --output-file="$ram_path"/vol/vadtree.dot > "$ram_path"/vol/vadtree.txt
#echo "Processing vadwalk"
#python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile vadwalk > "$ram_path"/vol/vadwalk.txt
echo "Processing verinfo"
python $vol_path/vol.py --plugins=$vol_path/contrib/plugins -f "$ram_path"/"$ram_image" --profile=$ram_profile verinfo > "$ram_path"/vol/verinfo.txt

echo "Finding shellbags - testing"
ls -l "$ram_path"/vol/file_dump | grep "UsrClass.dat" | awk '{print $9}' > "$ram_path"/vol/shellbag_manual_scan.txt
ls -l "$ram_path"/vol/file_dump | grep "NTUSER.DAT" | awk '{print $9}' >> "$ram_path"/vol/shellbag_manual_scan.txt
echo "Finding shellbags - testing" > "$ram_path"/vol/shellbag_manual_results.txt
for word2 in $(cat "$ram_path"/vol/shellbag_manual_scan.txt); do python /path-to-files/yarasigs/shellbags-master/shellbags.py "$ram_path"/vol/file_dump/$word2; done >> "$ram_path"/vol/shellbag_manual_results.txt
echo "Finished manually looking for shellbags"

echo "Testing VirusTotal API from https://github.com/Sebastienbr/Volatility. Running against these processes:"
cat "$ram_path"/vol/virustotal_hash.txt
echo "This will take a few minutes."
for word2 in $(cat "$ram_path"/vol/virustotal_hash.txt); do python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile virustotal -r $word2 -i --submit; done >> "$ram_path"/vol/virustotal_output.txt
echo "Finished processing VirusTotal info."
grep -e "File:" -e "MD5:" -e "ratio:" "$ram_path"/vol/virustotal_output.txt
echo " "
echo "Processing yarascan - must have prereqs installed for Yara and Yara-Python"
echo "This is in testing mode. Takes a long time and there will be FP."
python $vol_path/vol.py -f "$ram_path"/"$ram_image" --profile=$ram_profile yarascan -y /path-to-files/ye_all_include.yar > "$ram_path"/vol/yarascan_git.txt
echo "Grabbing md5 hash." >> "$ram_path"/vol/time.log
echo "Filename:" >> "$ram_path"/vol/time.log
cat "$ram_path"/vol/be_output/report.xml | grep "image_filename" | cut -d '>' -f2 | cut -d '<' -f1 >> "$ram_path"/vol/time.log
echo "File size:" >> "$ram_path"/vol/time.log
cat "$ram_path"/vol/be_output/report.xml | grep "image_size" | cut -d '>' -f2 | cut -d '<' -f1 >> "$ram_path"/vol/time.log
echo "File hash MD5:" >> "$ram_path"/vol/time.log
cat "$ram_path"/vol/be_output/report.xml | grep "hashdigest" | cut -d '>' -f2 | cut -d '<' -f1 >> "$ram_path"/vol/time.log
tail "$ram_path"/vol/time.log -n 7 -q
echo " "
#Creating a RAM timeline - see http://volatility-labs.blogspot.com/2013/05/movp-ii-23-creating-timelines-with.html
echo "Creating timeline at: $(date)"
echo Creating timeline at: $(date) >> "$ram_path"/vol/time.log
echo "Creating timeline. Takes a while."
echo "Processing shellbags"
python $vol_path/vol.py --plugins=$vol_path/contrib/plugins -f "$ram_path"/"$ram_image" --profile=$ram_profile shellbags --output=body > "$ram_path"/vol/shellbags.txt
echo "Processing mftparser"
python $vol_path/vol.py --plugins=$vol_path/contrib/plugins -f "$ram_path"/"$ram_image" --profile=$ram_profile mftparser --output=body > "$ram_path"/vol/mft.txt
cat "$ram_path"/vol/mft.txt | grep "DATA ADS" > "$ram_path"/vol/mft_odd.txt
cat "$ram_path"/vol/mft.txt | grep "DOS batch" >> "$ram_path"/vol/mft_odd.txt
echo "Processing timeliner"
python $vol_path/vol.py --plugins=$vol_path/contrib/plugins -f "$ram_path"/"$ram_image" --profile=$ram_profile timeliner --output=body > "$ram_path"/vol/timeliner.txt
#echo "Processing usnparser - testing. Needs to be placed in the plugins folder from https://github.com/tomspencer/volatility"
#python $vol_path/vol.py --plugins=$vol_path/contrib/plugins -f "$ram_path"/"$ram_image" --profile=$ram_profile usnparser --output=body > "$ram_path"/vol/usnparser.txt
echo "+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+" >> "$ram_path"/vol/time.log
echo Volatility analysis finished on: $(date) >> "$ram_path"/vol/time.log
echo "Completed processing of timeline. Creating CSV: "$ram_path"/vol/timeline.csv"
echo "Completed processing of timeline. Creating CSV: "$ram_path"/vol/timeline.csv" >> "$ram_path"/vol/time.log
cat "$ram_path"/vol/mft.txt "$ram_path"/vol/shellbags.txt "$ram_path"/vol/timeliner.txt "$ram_path"/vol/shellbag_manual.txt >> "$ram_path"/vol/bodyfile.txt
mactime -b "$ram_path"/vol/bodyfile.txt -d > "$ram_path"/vol/timeline.csv
echo "Finished."
echo "Tidying up a bit. Removing bodyfile and all zero length txt files."
rm "$ram_path"/vol/bodyfile.txt
find . -type f -empty -delete
echo "+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+" >> "$ram_path"/vol/time.log
echo Timeline creation finished on: $(date) >> "$ram_path"/vol/time.log
sleep 5
