clear
usage ()
{
  echo " "
  echo "Usage : No variables are needed. Just place a copy of the script in the same directory as your RAM capture."
  echo "        A subdirectory called vol will be created and will contain the results of this script."
  echo "        This script assumes you are using a ramdisk or a fast scratch location and will copy to that location."
  echo " "
  exit 1
}

#Starting time.
START=`date +%s%N`

if [ ! -z "$1" ]
then
  usage
fi
echo " "
echo "Volatility 2.6 script version 2.1."
echo " "
echo "The plugins and script is designed for Volatility 2.6. on an Ubuntu 18.x system."
echo "Requires that git, nuhup, parallel, mactime, yara, Automater, and hashdeep are installed."
echo "*Optional are several plugins released by the outstanding memory forensics community."
echo "**Check the script for details on any non-vanilla plugins."
echo " "
#Setting a static path - currently using version 2.6 public release. Modify to fit your installation.
vol_path="/home/user/apps/volatility"
PLUGINSPATH="/home/user/apps/community"
#Using --plugins=$PLUGINSPATH for community plugins.
#Reading contents of current directory. This script is designed to be modified for each case
#and run from the same directory as the RAM image.
#Adding an option to use a ramdisk if it exists.
#Assigning a case number or unique identifier.
echo " "
echo "Greetings $USER"
echo "Please enter a case number or unique identifier: "
read case_number

#The main MFT and other timeline artifacts will be searched and filtered for the date you enter below.
echo " " 
echo "Please enter a timestamp of interest (Matching this syntax: Fri Aug 28 2015 11:15 ): "
read time_stamp
echo " "
echo "Please enter an IP address, URL, or MD5 hash of a file for external lookup using Automater by TekDefense: "
read ioc_automater
echo " "
pwd
ls -lah
echo 
ram_path=$(pwd)
echo "Please enter or paste the full image name: "
read ram_image
#Creating directory structure to hold output.
mkdir -p "$ram_path"/vol
mkdir -p "$ram_path"/vol/be_output
mkdir -p "$ram_path"/vol/certs
mkdir -p "$ram_path"/vol/shots
mkdir -p "$ram_path"/vol/file_dump
mkdir -p "$ram_path"/vol/file_dump/pf
mkdir -p "$ram_path"/vol/file_dump/jpg
mkdir -p "$ram_path"/vol/file_dump/chrome_extensions
#mkdir -p "$ram_path"/vol/file_dump/chrome_hindsight
mkdir -p "$ram_path"/vol/file_dump/registry
mkdir -p "$ram_path"/vol/evtlogs
mkdir -p "$ram_path"/vol/pcap
mkdir -p "$ram_path"/vol/proc_dump
#mkdir -p "$ram_path"/vol/procmem_dump

echo "Creating time.log to store information for the final report."
echo "+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+" > "$ram_path"/vol/time.log
echo "Analysis of $case_number started on: $(date)" >> "$ram_path"/vol/time.log
echo "Analysis of $case_number. Started on: $(date)" > "$ram_path"/vol/banner.log
echo "Script run by:  $USER" >> "$ram_path"/vol/time.log
echo "On the computer named: $HOSTNAME running: " $(uname -mrs) >> "$ram_path"/vol/time.log
echo "Looking for evidence on $time_stamp. " >> "$ram_path"/vol/time.log
echo "IoC entered: $ioc_automater " >> "$ram_path"/vol/time.log
echo " "
echo "Looking for evidence on $time_stamp. "
echo "IoC entered: $ioc_automater "
echo " "
echo "+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+" >> "$ram_path"/vol/time.log
echo " " >> "$ram_path"/vol/time.log

echo Copying to the ramdisk.
cp "$ram_path"/"$ram_image" /mnt/ramdisk/"$ram_image"
ramdisk=/mnt/ramdisk/"$ram_image"
echo "Copied to ramdisk. File to be processed is now:"
echo $ramdisk

echo "Computing the SHA256 hash of the ram image file."
nohup hashdeep -s -c sha256 $ramdisk >> "$ram_path"/vol/time.log 2>&1 &
echo "Searching for the correct profile information by processing kdbgscan. Please wait." >> "$ram_path"/vol/time.log
echo "Searching for the correct profile information by processing kdbgscan. Please wait."
echo " "
python $vol_path/vol.py -f $ramdisk kdbgscan > "$ram_path"/vol/kdbgscan.txt 
ram_profile=$(cat "$ram_path"/vol/kdbgscan.txt | grep "KDBGHeader" | cut -f 4 -d ' ' | sed -n '1p')
echo $ram_profile
sleep 5
#Checking to see if kdbgscan found a profile.
if [ -n "$ram_profile" ]; then
	echo "Success!"
    echo "Profile is set to: $ram_profile. Continuing to check if it is a minor version of Win10x64 and will automatically select the correct version."
	sleep 5
	if [[ "$ram_profile" == "Win10x64"* ]]; then
		temp_profile=$(cat "$ram_path"/vol/kdbgscan.txt | grep "Minor:" | awk '{print $7}' | sed 's/.$//' | uniq)
		ram_profile=$(cat "$ram_path"/vol/kdbgscan.txt | grep "$temp_profile" | grep "Instantiating" | awk '{print $6}' | uniq)
	else
		echo "Profile is not Win10x64!"
	fi
else
	echo "kdbgscan has failed. I am so sorry."
	echo "Trying imageinfo instead. Please wait."
	python $vol_path/vol.py -f $ramdisk imageinfo > "$ram_path"/vol/imageinfo.txt
	cat "$ram_path"/vol/imageinfo.txt
	echo "Please enter the identified profile: "
	read ram_profile
fi
echo " "
echo "Using profile: $ram_profile." >> "$ram_path"/vol/time.log
sleep 5
echo "+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+" >> "$ram_path"/vol/time.log

# dmp files were causing some errors during processing - the next part will convert to a raw image
echo "Checking if this is a dmp file or a raw image."
if [[ "$ram_image" == *".dmp" ]]; then
	python $vol_path/vol.py -f $ramdisk --profile=$ram_profile imagecopy -O "$ram_path"/image.raw
	rm $ramdisk
	echo Copying new file to the ramdisk.
	cp "$ram_path"/image.raw /mnt/ramdisk/image.raw
	ramdisk=/mnt/ramdisk/image.raw
	echo New file to be processed is:
	echo $ramdisk
	ram_image=image.raw
else
	echo "Capture does not have the .dmp extension."
fi

echo " " >> "$ram_path"/vol/time.log
echo "Processing "$ram_image" in the "$ram_path" folder. Using profile: $ram_profile."
echo "Processing "$ram_image" in the "$ram_path" folder. Using profile: $ram_profile." >> "$ram_path"/vol/time.log
echo "Example: "
echo "python $vol_path/vol.py -f $ramdisk --profile=$ram_profile <command>"
echo "Example: " >> "$ram_path"/vol/time.log
echo "python $vol_path/vol.py -f $ramdisk --profile=$ram_profile <command>" >> "$ram_path"/vol/time.log
echo "Original file location to be processed was: "$ram_path"/"$ram_image" before copying to the scratch location" >> "$ram_path"/vol/time.log ""
echo " "
echo "+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+" >> "$ram_path"/vol/time.log
echo "Attempting to run strings and other grep terms."
echo "Attempting to run strings and other grep terms." >> "$ram_path"/vol/time.log
echo "Running strings -el : 16-bit little endian"
strings -el $ramdisk > "$ram_path"/vol/gmailstrings.str
echo "Running strings -a : all"
strings -a $ramdisk >> "$ram_path"/vol/gmailstrings.str
echo "Now I am attempting to run strings with the decimal pointer to translate later."
echo "Running strings -a -td : all"
strings -a -td $ramdisk > "$ram_path"/vol/strings.str
echo "Running strings -a -td -el : 16-bit little endian"
strings -a -td -el $ramdisk >> "$ram_path"/vol/strings.str
echo "Running Volatility strings to map to memory location."
nohup python $vol_path/vol.py -f $ramdisk --profile=$ram_profile strings -s "$ram_path"/vol/strings.str --output-file="$ram_path"/vol/memory_mapped.str > /dev/null 2>&1&
echo "Finished running strings."
echo "Finished running strings." >> "$ram_path"/vol/time.log
echo "Searching for keywords. Modify to fit."
echo "Searching for keywords. Modify to fit." >> "$ram_path"/vol/time.log
echo "Searching for invalid UltraVNC connection attempts"
echo "Searching for invalid UltraVNC connection attempts" > "$ram_path"/vol/interesting_greps.txt
cat "$ram_path"/vol/gmailstrings.str | parallel --pipe grep -F 'Invalid\ attempt\ from\ client' >> "$ram_path"/vol/interesting_greps.txt
echo "Searching for succesful UltraVNC connection attempts"
cat "$ram_path"/vol/gmailstrings.str | parallel --pipe grep --after-context=1 "Connection\ received\ from" >> "$ram_path"/vol/interesting_greps.txt
echo "Searching for mstscax.dll usage - indicates remote desktop connections." >> "$ram_path"/vol/interesting_greps.txt
echo "Searching for mstscax.dll usage - indicates remote desktop connections."
cat "$ram_path"/vol/gmailstrings.str | parallel --pipe grep -i --before-context=1 '\\Windows\\system32\\mstscax.dll' >> "$ram_path"/vol/interesting_greps.txt
echo "Searching for WMI usage - indicates remote persistence." >> "$ram_path"/vol/interesting_greps.txt
echo "Searching for WMI usage - indicates remote persistence."
cat "$ram_path"/vol/gmailstrings.str | parallel --pipe grep --after-context=1 'Event\ Consumer' >> "$ram_path"/vol/interesting_greps.txt
cat "$ram_path"/vol/gmailstrings.str | parallel --pipe grep --after-context=1 'Event\ Filter' >> "$ram_path"/vol/interesting_greps.txt
cat "$ram_path"/vol/gmailstrings.str | parallel --pipe grep --after-context=1 'Wscript.shell' >> "$ram_path"/vol/interesting_greps.txt
cat "$ram_path"/vol/gmailstrings.str | parallel --pipe grep --after-context=1 'Wscript.sleep' >> "$ram_path"/vol/interesting_greps.txt
cat "$ram_path"/vol/gmailstrings.str | parallel --pipe grep --after-context=1 '\\CIMV2\\Win32\ Clock\ provider' >> "$ram_path"/vol/interesting_greps.txt
echo "Searching for PowerSploit." >> "$ram_path"/vol/interesting_greps.txt
echo "Searching for PowerSploit."
cat "$ram_path"/vol/gmailstrings.str | parallel --pipe grep --after-context=10 'mimikatz' >> "$ram_path"/vol/interesting_greps.txt
cat "$ram_path"/vol/gmailstrings.str | parallel --pipe grep --after-context=1 'add-member' >> "$ram_path"/vol/interesting_greps.txt
cat "$ram_path"/vol/gmailstrings.str | parallel --pipe grep --after-context=1 'out-null' >> "$ram_path"/vol/interesting_greps.txt
cat "$ram_path"/vol/gmailstrings.str | parallel --pipe grep --after-context=1 '-encodedcommand' >> "$ram_path"/vol/interesting_greps.txt

#Add additional case-specific search terms below this point.
#echo "Searching for <term> remnants" >> "$ram_path"/vol/interesting_greps.txt
#grep "<term>" "$ram_path"/vol/*.str >> "$ram_path"/vol/interesting_greps.txt
echo "Searching for Website history remnant" >> "$ram_path"/vol/interesting_greps.txt
echo "Searching for Website history remnant"
cat "$ram_path"/vol/gmailstrings.str | parallel --pipe grep -i "Visited:" >> "$ram_path"/vol/interesting_greps.txt
echo "Searching for term j_password=" >> "$ram_path"/vol/interesting_greps.txt
echo "Searching for term j_password="
grep --after-context=1 "j_password=" "$ram_path"/vol/*.str >> "$ram_path"/vol/interesting_greps.txt
grep --after-context=1 "$ioc_automater" "$ram_path"/vol/*.str >> "$ram_path"/vol/interesting_greps.txt
echo "Finished running strings" >> "$ram_path"/vol/time.log
echo "Finished running grep searches"
echo "+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+" >> "$ram_path"/vol/time.log

echo "Checking IoC through TekDefense Automater"
echo "Checking IoC through TekDefense Automater" >> "$ram_path"/vol/time.log

cd /home/user/apps/TekDefense-Automater
echo " "
python /home/user/apps/TekDefense-Automater/Automater.py $ioc_automater -rv --csv CSV --output "$ram_path"/vol/Automater_report.csv > "$ram_path"/vol/Automater.log
echo "Finished checking IoC"
echo " "
cd "$ram_path"

echo "+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+" >> "$ram_path"/vol/time.log

echo "Continuing Volatility processing."
echo "Continuing Volatility processing." >> "$ram_path"/vol/time.log
echo >> "$ram_path"/vol/time.log
echo "Processing a verbose pstree."
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile pstree -v --output=text > "$ram_path"/vol/pstree.txt

echo "The following files are run from suspicious locations. Further research is needed for unrecognised files." > "$ram_path"/vol/suspicious_pstree.txt
cat "$ram_path"/vol/pstree.txt | grep -i -w 'temp\|appdata\|Users\|Windows' | grep -i -v -w 'remcomsvc.exe\|dumpit.exe\|inetpub\|system32\|chrome\|firefox\|chrome\|mozilla\|spotify\|google\|akamai\|Dropbox\|explorer.exe\|RTHDCPL.EXE' | grep -i -v "ftk" | grep -i -v "program files" | grep -i -v "ccm\|framework" >> "$ram_path"/vol/suspicious_pstree.txt
cat "$ram_path"/vol/suspicious_pstree.txt
echo "Processing cmdline"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile cmdline > "$ram_path"/vol/cmdline.txt
echo "The following files are run from suspicious locations. Compare to the output from pstree." > "$ram_path"/vol/suspicious_cmdline.txt
cat "$ram_path"/vol/cmdline.txt | grep -i -w 'temp\|appdata' | grep -i -v -w 'remcomsvc.exe\|dumpit.exe\|inetpub\|system32\|chrome\|firefox\|chrome\|mozilla\|spotify\|google\|akamai\|Dropbox' | grep -i -v "ftk" | grep -i -v "program files" | awk '{print $3,$4,$5}' >> "$ram_path"/vol/suspicious_cmdline.txt
cat "$ram_path"/vol/suspicious_cmdline.txt
echo "Processing netscan"
nohup python $vol_path/vol.py -f $ramdisk --profile=$ram_profile netscan > "$ram_path"/vol/netscan.txt 2>&1 &

echo "Testing new plugins."
echo "Processing amcache - Win8 only."
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile amcache > "$ram_path"/vol/amcache.txt
echo "Processing chromedownloads."
python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile chromedownloads > "$ram_path"/vol/chromedownloads.txt
echo "Processing chromecookies."
python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile chromecookies > "$ram_path"/vol/chromecookies.txt
echo "Processing firefoxhistory."
python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile firefoxhistory > "$ram_path"/vol/firefoxhistory.txt
echo "Processing firefoxcookies."
python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile firefoxcookies > "$ram_path"/vol/firefoxcookies.txt
echo "Processing prefetchparser."
python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile prefetchparser > "$ram_path"/vol/prefetchparser.txt
echo "Processing uninstallinfo."
python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile uninstallinfo > "$ram_path"/vol/uninstallinfo.txt
echo "Processing systeminfo."
python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile systeminfo > "$ram_path"/vol/systeminfo.txt
echo "Processing usbstor."
python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile usbstor > "$ram_path"/vol/usbstor.txt
echo "Processing directoryenumerator."
python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile directoryenumerator > "$ram_path"/vol/directoryenumerator.txt
echo "Processing directoryenumerator."
python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile directoryenumerator > "$ram_path"/vol/directoryenumerator.txt
echo "Testing new autoruns WINESAP plugin. Need to use a custom path."
python $vol_path/vol.py --plugins=/home/user/apps/winesap -f $ramdisk --profile=$ram_profile winesap --match > "$ram_path"/vol/winesap.txt
echo "Finished testing new plugins."
echo "Processing cachedump"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile cachedump > "$ram_path"/vol/cachedump.txt
echo "Processing clipboard"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile clipboard > "$ram_path"/vol/clipboard.txt
echo "Processing cmdscan"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile cmdscan > "$ram_path"/vol/cmdscan.txt
echo "Processing connections"
nohup python $vol_path/vol.py -f $ramdisk --profile=$ram_profile connections > "$ram_path"/vol/connections.txt 2>&1 &
echo "Processing connscan"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile connscan > "$ram_path"/vol/connscan.txt
echo "Processing consoles"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile consoles > "$ram_path"/vol/consoles.txt
echo "Processing devicetree"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile devicetree > "$ram_path"/vol/devicetree.txt

#The next few lines were to dump all DLL files for scanning by clamscan. Removed as it takes a long time.
#echo "Processing dll_dump and dumping all dll files to: "$ram_path"/vol/dll_dump/"
#echo "Processing dll_dump and dumping all dll files to: "$ram_path"/vol/dll_dump/" >> "$ram_path"/vol/time.log
#python $vol_path/vol.py -f $ramdisk --profile=$ram_profile dlldump -D "$ram_path"/vol/dll_dump/ > "$ram_path"/vol/dlldump.txt

echo "Processing dlllist"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile dlllist > "$ram_path"/vol/dlllist.txt

#echo "Processing dnscachescan - very slow."
#python $vol_path/vol.py -f $ramdisk --profile=$ram_profile dnscachescan > "$ram_path"/vol/dnscachescan.txt
#echo "Processing dumpcerts and dumping them to: "$ram_path"/vol/certs/"
#python $vol_path/vol.py -f $ramdisk --profile=$ram_profile dumpcerts --dump-dir "$ram_path"/vol/certs/ > "$ram_path"/vol/dumpcerts.txt
#echo "Processing dumpfiles to dump all files. Testing only, as it takes a long time."
#python $vol_path/vol.py -f $ramdisk --profile=$ram_profile dumpfiles --dump-dir "$ram_path"/vol/file_dump/ -n > "$ram_path"/vol/dumpfiles.txt

echo "Processing envars"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile envars > "$ram_path"/vol/envars.txt

#Community plugin processing
echo "Processing community supplied plugins."
echo "schtasks"
nohup python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile schtasks > "$ram_path"/vol/schtasks.txt 2>&1 &
echo "usnjrnl"
python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile usnjrnl --output=body > "$ram_path"/vol/usnjrnl.txt
echo "Processing chromehistory."
python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile chromehistory > "$ram_path"/vol/chromehistory.txt
echo "Processing malfinddeep"
python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile malfinddeep > "$ram_path"/vol/malfinddeep.txt
echo "Processing lsass output using the mimikatz plugin - must grab it from https://github.com/dfirfpi/hotoloti and put it in the plugin folder"
nohup python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile mimikatz > "$ram_path"/vol/mimikatz.txt 2>&1 &
echo "Processing Chrome useage with lastpass - must grab it from https://github.com/kevthehermit/volatility_plugins/tree/master/lastpass and put it in the plugin folder"
nohup python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile lastpass > "$ram_path"/vol/lastpass.txt 2>&1 &
echo "bitlocker"
python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile bitlocker > "$ram_path"/vol/bitlocker.txt
echo "Processing shimcachemem (new)"
python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile shimcachemem -c > "$ram_path"/vol/shimcachemem.txt
echo "Processing autoruns."
python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile autoruns > "$ram_path"/vol/autoruns.txt
echo "usnparser"
python $vol_path/vol.py --plugins=$PLUGINSPATH/TomSpencer -f $ramdisk --profile=$ram_profile usnparser -C -S --output=body > "$ram_path"/vol/usnparser.txt
echo "Finished processing community supplied plugins."
echo "Processing filescan"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile filescan > "$ram_path"/vol/filescan.txt

echo "Attempting to carve interesting files. Add more search terms if needed. Running twice as the formatting has been screwed up inbetween versions. Will fix later."
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
grep ".mof " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".cs " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "schedlgu.txt " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "Amcache.hve " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "ultravnc.ini " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "recentservers.xml " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep -i "schedlgu.txt " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".pf " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files_pf.txt
grep ".dit " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".bat " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".psafe3 " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "mslogon.log " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "Windows.edb " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "Wlansvc" "$ram_path"/vol/filescan.txt | grep ".xml \|.xml$" | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "hosts " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".jpg " "$ram_path"/vol/filescan.txt | sort -u > "$ram_path"/vol/interesting_files_jpg.txt
grep -i "password" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "manifest.json " "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files_chrome_extensions.txt
#grep "Default\\\History" "$ram_path"/vol/filescan.txt | grep -v "journal" | grep -v "Cache" | sort -u >> "$ram_path"/vol/interesting_files_chrome_hindsight.txt
#grep "Default\\\Archived History" "$ram_path"/vol/filescan.txt | grep -v "journal" | grep -v "Cache" | sort -u >> "$ram_path"/vol/interesting_files_chrome_hindsight.txt
#grep -i "Default\\\Bookmarks" "$ram_path"/vol/filescan.txt | grep -v "journal" | grep -v "Cache" | sort -u >> "$ram_path"/vol/interesting_files_chrome_hindsight.txt
#grep "Default\\\Web Data" "$ram_path"/vol/filescan.txt | grep -v "journal" | grep -v "Cache" | sort -u >> "$ram_path"/vol/interesting_files_chrome_hindsight.txt
#grep "Default\\\Cookies" "$ram_path"/vol/filescan.txt | grep -v "journal" | grep -v "Cache" | sort -u >> "$ram_path"/vol/interesting_files_chrome_hindsight.txt

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
grep ".mof$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".cs$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "schedlgu.txt$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "Amcache.hve$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "ultravnc.ini$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "recentservers.xml$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep -i "schedlgu.txt$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".pf$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files_pf.txt
grep ".dit$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".bat$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".psafe3$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "mslogon.log$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "Windows.edb$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "hosts$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep ".jpg$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files_jpg.txt
grep -i "password" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files.txt
grep "manifest.json$" "$ram_path"/vol/filescan.txt | sort -u >> "$ram_path"/vol/interesting_files_chrome_extensions.txt
#grep "Default\\\History$" "$ram_path"/vol/filescan.txt | grep -v "journal" | grep -v "Cache" | sort -u >> "$ram_path"/vol/interesting_files_chrome_hindsight.txt
#grep "Default\\\Archived History$" "$ram_path"/vol/filescan.txt | grep -v "journal" | grep -v "Cache" | sort -u >> "$ram_path"/vol/interesting_files_chrome_hindsight.txt
#grep -i "Default\\\Bookmarks$" "$ram_path"/vol/filescan.txt | grep -v "journal" | grep -v "Cache" | sort -u >> "$ram_path"/vol/interesting_files_chrome_hindsight.txt
#grep "Default\\\Web Data$" "$ram_path"/vol/filescan.txt | grep -v "journal" | grep -v "Cache" | sort -u >> "$ram_path"/vol/interesting_files_chrome_hindsight.txt
#grep "Default\\\Cookies$" "$ram_path"/vol/filescan.txt | grep -v "journal" | grep -v "Cache" | sort -u >> "$ram_path"/vol/interesting_files_chrome_hindsight.txt

#The next section will automatically carve out anything found to be interesting. Less reliable with the newer versions of Windows 10.
cat "$ram_path"/vol/interesting_files.txt | awk '{print $1}' | sort -u > "$ram_path"/vol/carve_files.txt
for word in $(cat "$ram_path"/vol/carve_files.txt); do python $vol_path/vol.py -f $ramdisk --profile=$ram_profile dumpfiles --dump-dir "$ram_path"/vol/file_dump/ -n -Q $word; done >> "$ram_path"/vol/file_dump/dumped.txt
echo "Done testing the specified file carving."
cat "$ram_path"/vol/interesting_files_jpg.txt | awk '{print $1}' | sort -u > "$ram_path"/vol/carve_files_jpg.txt
for word in $(cat "$ram_path"/vol/carve_files_jpg.txt); do python $vol_path/vol.py -f $ramdisk --profile=$ram_profile dumpfiles --dump-dir "$ram_path"/vol/file_dump/jpg/ -n -Q $word; done >> "$ram_path"/vol/file_dump/jpg/dumped.txt

cat "$ram_path"/vol/interesting_files_pf.txt | awk '{print $1}' | sort -u > "$ram_path"/vol/carve_files_pf.txt
for word in $(cat "$ram_path"/vol/carve_files_pf.txt); do python $vol_path/vol.py -f $ramdisk --profile=$ram_profile dumpfiles --dump-dir "$ram_path"/vol/file_dump/pf/ -n -Q $word; done >> "$ram_path"/vol/file_dump/pf/dumped.txt
echo "Done testing the specified jpg file carving."

cat "$ram_path"/vol/interesting_files_chrome_extensions.txt | awk '{print $1}' | sort -u > "$ram_path"/vol/carve_files_chrome.txt
for word in $(cat "$ram_path"/vol/carve_files_chrome.txt); do python $vol_path/vol.py -f $ramdisk --profile=$ram_profile dumpfiles --dump-dir "$ram_path"/vol/file_dump/chrome_extensions/ -n -Q $word; done >> "$ram_path"/vol/file_dump/chrome_extensions/dumped.txt

#cat "$ram_path"/vol/interesting_files_chrome_hindsight.txt | awk '{print $1}' | sort -u > "$ram_path"/vol/carve_files_hindsight.txt
#for word in $(cat "$ram_path"/vol/carve_files_hindsight.txt); do python $vol_path/vol.py -f $ramdisk --profile=$ram_profile dumpfiles --dump-dir "$ram_path"/vol/file_dump/chrome_hindsight/ -n -Q $word; done >> "$ram_path"/vol/file_dump/chrome_hindsight/dumped.txt

#Bulk Extractor processing:
echo "Running bulk_extractor on all available cores - grab from https://github.com/simsong/bulk_extractor"
echo " "
echo "Bulk Extractor 1.6.x."
echo " "
echo "+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+" >> "$ram_path"/vol/time.log
echo "Running bulk_extractor on all available cores" >> "$ram_path"/vol/time.log
echo " " >> "$ram_path"/vol/time.log
echo Bulk_Extractor analysis started on: $(date) >> "$ram_path"/vol/time.log
#Using nohup will allow Volatility to continue running while BE processes the image
#You can use regular expressions specifying -f for a single search term or -F for a file containing regex terms. 
nohup bulk_extractor $ramdisk -o "$ram_path"/vol/be_output -e wordlist -e net -x sqlite -j 4 -b "$ram_path"/vol/banner.log >> "$ram_path"/vol/be.log 2>&1 &
echo " " >> "$ram_path"/vol/time.log

echo "Processing prefetch files"
echo "Processing prefetch files" >> "$ram_path"/vol/time.log
echo "Removing extra .dat and .vacb file extensions creating while carving."
find "$ram_path"/vol/file_dump -type f -name '*.dat' | while read f; do mv "$f" "${f%.dat}"; done
find "$ram_path"/vol/file_dump -type f -name '*.vacb' | while read f; do mv "$f" "${f%.vacb}"; done
#Grab the prefetch-parser from http://bitbucket.cassidiancybersecurity.com/prefetch-parser
python /home/user/apps/yarasigs/plugins/prefetch.py -r "$ram_path"/vol/file_dump/pf >> "$ram_path"/vol/prefetch_files.txt
echo "Finished processing prefetch files"
echo "Processing Google Chrome extensions to find the name"
echo "Processing Google Chrome extensions" >> "$ram_path"/vol/time.log
egrep --binary-files=text "name.:" "$ram_path"/vol/file_dump/chrome_extensions/*.json >> "$ram_path"/vol/chrome_plugins.txt
echo "Finished processing chrome extensions"
echo "Processing handles"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile handles > "$ram_path"/vol/handles.txt
cat "$ram_path"/vol/handles.txt | grep "\LanmanRedirector" > "$ram_path"/vol/handles_mapped_shares.txt
echo "Attempting to dump all registry hives - dumpregistry plugin is new."
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile dumpregistry -D "$ram_path"/vol/file_dump/registry > "$ram_path"/vol/dumpregistry.txt
echo "Processing hivelist"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile hivelist > "$ram_path"/vol/hivelist.txt
#Searching for the registry files and their virtual address to store for hashdump
virt_mem_sys=$(grep 'SYSTEM \|SYSTEM\>$' "$ram_path"/vol/hivelist.txt | awk '{print $1}')
virt_mem_SAM=$(grep 'SAM \|SAM\>' "$ram_path"/vol/hivelist.txt | awk '{print $1}')
virt_mem_sec=$(grep 'SECURITY \|SECURITY\>' "$ram_path"/vol/hivelist.txt | awk '{print $1}')
echo "Preparing to automatically parse the registry to extract the hashes - x86 only. Running: vol.py -f $ramdisk --profile=$ram_profile hashdump -y $virt_mem_sys -s $virt_mem_SAM"
echo "Preparing to automatically parse the registry to extract the hashes. Running: vol.py -f $ramdisk --profile=$ram_profile hashdump -y $virt_mem_sys -s $virt_mem_SAM" >> "$ram_path"/vol/time.log
echo "Processing hashdump"
echo "Processing hashdump" >> "$ram_path"/vol/time.log
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile hashdump -y $virt_mem_sys -s $virt_mem_SAM >> "$ram_path"/vol/hashdump.txt
echo "Processing hivescan"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile hivescan > "$ram_path"/vol/hivescan.txt
echo "Processing iehistory"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile iehistory > "$ram_path"/vol/iehistory.txt
echo "Processing iehistory -L (LEAK - Deleted)"
nohup python $vol_path/vol.py -f $ramdisk --profile=$ram_profile iehistory -L >> "$ram_path"/vol/iehistory.txt 2>&1 &
echo "Processing imageinfo"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile imageinfo > "$ram_path"/vol/imageinfo.txt
echo "Processing malfind"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile malfind > "$ram_path"/vol/malfind.txt
echo "Processing mbrparser"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile mbrparser > "$ram_path"/vol/mbrparser.txt
echo "Processing pslist"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile pslist > "$ram_path"/vol/pslist.txt
echo "Processing psscan"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile psscan > "$ram_path"/vol/psscan.txt
#The next line searches against a known good whitelist of services - not a home-run but a simple check.
cat "$ram_path"/vol/psscan.txt | awk '{print $2}' | grep -vwf /home/user/apps/yarasigs/whitelist.txt | sort -u > "$ram_path"/vol/psscan_outliers.txt
cat "$ram_path"/vol/pslist.txt | awk '{print $2}' | grep -vwf /home/user/apps/yarasigs/whitelist.txt | sort -u >> "$ram_path"/vol/psscan_outliers.txt
echo "The following service(s) are not in the whitelist."
cat "$ram_path"/vol/psscan_outliers.txt | sort -u | uniq
echo " "
echo "Creating a list for VirusTotal based on the outliers..."
echo "Creating a list for VirusTotal based on the outliers..." >> "$ram_path"/vol/time.log
#The next line is for grabbing the PID.
#cat "$ram_path"/vol/psscan.txt | grep -vwf /home/user/apps/yarasigs/whitelist.txt | tr -s ' ' | cut -d ' ' -f3 | sed -n -e 'H;${x;s/\n/,/g;s/^,//;p;}' > "$ram_path"/vol/virustotal_hash.txt
#The next line is for grabbing the filename.
cat "$ram_path"/vol/psscan_outliers.txt | sort -u | uniq > "$ram_path"/vol/virustotal_hash.txt

echo "Processing psxview"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile psxview > "$ram_path"/vol/psxview.txt
echo "Processing mutantscan"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile mutantscan --silent > "$ram_path"/vol/mutantscan.txt
echo "Processing multiple printkey registry queries"
echo "Manually pulling the IP information from the registry - needs cleaning but works"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile printkey -o $virt_mem_sys -K "ControlSet001\services\Tcpip\Parameters\Interfaces" | grep "{" | awk '{print $2}' > "$ram_path"/vol/printkey_interfaces.txt
for word in $(cat "$ram_path"/vol/printkey_interfaces.txt); do python $vol_path/vol.py -f $ramdisk --profile=$ram_profile printkey -o $virt_mem_sys -K "ControlSet001\services\Tcpip\Parameters\Interfaces""\\""$word"; done >> "$ram_path"/vol/printkey_interfaces_output.txt
#Removing null characters from file for parsing
sed -i 's/\x0//g' "$ram_path"/vol/printkey_interfaces_output.txt
echo "Potential IP addresses from registry: " > "$ram_path"/vol/printkey_ipaddress.txt
cat "$ram_path"/vol/printkey_interfaces_output.txt | egrep --binary-files=text "IPAddress" | awk '{print $5}' | egrep -v --binary-files=text "0.0.0.0"  >> "$ram_path"/vol/printkey_ipaddress.txt
echo "Potential DNS Name server addresses from registry: " >> "$ram_path"/vol/printkey_ipaddress.txt
cat "$ram_path"/vol/printkey_interfaces_output.txt | egrep --binary-files=text "NameServer" | cut -d \) -f 2 >> "$ram_path"/vol/printkey_ipaddress.txt
echo "Done grabbing IP information"

echo "Grabbing plaintext Secret phrase in Win7 by exporting the following for each Names entry: SAM\Domains\Account\Users\<00000XXX>"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile printkey -K "SAM\Domains\Account\Users" |  grep "00000" | cut -d \) -f 2 | awk '{print $1}' > "$ram_path"/vol/printkey.txt
for word in $(cat "$ram_path"/vol/printkey.txt); do python $vol_path/vol.py -f $ramdisk --profile=$ram_profile printkey -K "SAM\Domains\Account\Users""\\""$word"; done >> "$ram_path"/vol/printkey_secrets.txt

echo "Working on new registry artifacts - can also use regripper on the dumped registry hives from earlier"
echo "Microsoft\Windows\CurrentVersion\Explorer\MountPoints2 - mapped network drives"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile printkey -K "Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" >> "$ram_path"/vol/MountPoints.txt

echo "Microsoft\Windows NT\CurrentVersion - Owner Information"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile printkey -K "Microsoft\Windows NT\CurrentVersion" >> "$ram_path"/vol/MountPoints.txt

echo "Processing printkey - runonce"
echo "Microsoft\Windows\CurrentVersion\Run" > "$ram_path"/vol/printkey_runs.txt
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile printkey -K "Software\Microsoft\Windows\CurrentVersion\Run" >> "$ram_path"/vol/printkey_runs.txt
echo "Microsoft\Windows\CurrentVersion\Runonce" >> "$ram_path"/vol/printkey_runs.txt
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile printkey -K "Microsoft\Windows\CurrentVersion\Runonce" >> "$ram_path"/vol/printkey_runs.txt
echo "Microsoft\Windows NT\CurrentVersion\Winlogon" >> "$ram_path"/vol/printkey_runs.txt
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile printkey -K "Microsoft\Windows NT\CurrentVersion\Winlogon" >> "$ram_path"/vol/printkey_runs.txt
echo "Classes\.exe\shell\open\command" >> "$ram_path"/vol/printkey_runs.txt
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile printkey -K "Classes\.exe\shell\open\command" >> "$ram_path"/vol/printkey_runs.txt
echo "Classes\exefile\shell\open\command" >> "$ram_path"/vol/printkey_runs.txt
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile printkey -K "Classes\exefile\shell\open\command" >> "$ram_path"/vol/printkey_runs.txt
echo "Software\Microsoft\Command Processor\AutoRun" >> "$ram_path"/vol/printkey_runs.txt
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile printkey -K "Software\Microsoft\Command Processor\AutoRun" >> "$ram_path"/vol/printkey_runs.txt
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile printkey -K "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" >> "$ram_path"/vol/printkey_runs.txt
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile printkey -K "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Runonce" >> "$ram_path"/vol/printkey_runs.txt
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile printkey -K "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" >> "$ram_path"/vol/printkey_runs.txt
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile printkey -K "Software\Microsoft\Windows\CurrentVersion\RunOnceEx" >> "$ram_path"/vol/printkey_runs.txt
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile printkey -K "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx" >> "$ram_path"/vol/printkey_runs.txt
echo "Time Zone" > "$ram_path"/vol/printkey_forensic_artifacts.txt
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile printkey -K "ControlSet001\Control\TimeZoneInformation" >> "$ram_path"/vol/printkey_forensic_artifacts.txt
echo "WindowsUpdate" >> "$ram_path"/vol/printkey_forensic_artifacts.txt
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile printkey -K "Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" >> "$ram_path"/vol/printkey_forensic_artifacts.txt
sed -i 's/\x0//g' "$ram_path"/vol/printkey_forensic_artifacts.txt

echo "Processing shutdowntime"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile shutdowntime > "$ram_path"/vol/shutdowntime.txt
#echo "Processing privs - disabled for now"
#python $vol_path/vol.py -f $ramdisk --profile=$ram_profile privs > "$ram_path"/vol/privs.txt
#echo "Finding odd privileges"
#cat "$ram_path"/vol/privs.txt | awk '{print $4}' | sort | uniq -c | grep -i -e "sebackupprivilege" -e "sedebugprivilege" -e "seloaddriverprivilege" -e "sechangenotifyprivilege" -e "seshutdownprivilege" > "$ram_path"/vol/privs_interesting.txt
echo "Processing procdump and dumping to: "$ram_path"/vol/proc_dump/"
nohup python $vol_path/vol.py -f $ramdisk --profile=$ram_profile procdump -D "$ram_path"/vol/proc_dump/ > "$ram_path"/vol/procdump.txt 2>&1 &
echo "Processing security - must grab the plugin from https://twitter.com/CGurkok and put it in the plugin folder"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile security > "$ram_path"/vol/security.txt
echo "Processing screenshot and dumping the files to: "$ram_path"/vol/shots/"
nohup python $vol_path/vol.py -f $ramdisk --profile=$ram_profile screenshot -D "$ram_path"/vol/shots/ > "$ram_path"/vol/screenshot.txt 2>&1 &
echo "Processing sessions"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile sessions > "$ram_path"/vol/sessions.txt
echo "Processing shimcache (new)"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile shimcache > "$ram_path"/vol/shimcache.txt
echo "Processing sockets"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile sockets > "$ram_path"/vol/sockets.txt
echo "Processing sockscan"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile sockscan > "$ram_path"/vol/sockscan.txt
echo "Processing svcscan"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile svcscan > "$ram_path"/vol/svcscan.txt
echo "Processing symlinkscan"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile symlinkscan > "$ram_path"/vol/symlinkscan.txt
#echo "Processing threads - disabled for now"
#python $vol_path/vol.py -f $ramdisk --profile=$ram_profile threads -L > "$ram_path"/vol/threads_verbose.txt
#echo "Processing thrdscan"
#python $vol_path/vol.py -f $ramdisk --profile=$ram_profile thrdscan > "$ram_path"/vol/thrdscan.txt
#echo "Processing orphan threads"
#python $vol_path/vol.py -f $ramdisk --profile=$ram_profile threads -F OrphanThread > "$ram_path"/vol/threads_orphan.txt
echo "Processing timers"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile timers > "$ram_path"/vol/timers.txt
#echo "Processing truecryptsummary"
#python $vol_path/vol.py -f $ramdisk --profile=$ram_profile truecryptsummary > "$ram_path"/vol/truecryptsummary.txt
#echo "Processing truecryptpassphrase"
#python $vol_path/vol.py -f $ramdisk --profile=$ram_profile truecryptpassphrase > "$ram_path"/vol/truecryptpassphrase.txt
echo "Processing userassist"
python $vol_path/vol.py -f $ramdisk --profile=$ram_profile userassist > "$ram_path"/vol/userassist.txt
#echo "Processing vadinfo"
#python $vol_path/vol.py -f $ramdisk --profile=$ram_profile vadinfo > "$ram_path"/vol/vadinfo.txt
#echo "Processing vadtree"
#python $vol_path/vol.py -f $ramdisk --profile=$ram_profile vadtree --output=dot --output-file="$ram_path"/vol/vadtree.dot > "$ram_path"/vol/vadtree.txt
#echo "Processing vadwalk"
#python $vol_path/vol.py -f $ramdisk --profile=$ram_profile vadwalk > "$ram_path"/vol/vadwalk.txt
echo "Processing verinfo"
python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile verinfo > "$ram_path"/vol/verinfo.txt

echo "Interpreting shellbags with custom python"
for word2 in $(cat "$ram_path"/vol/shellbag_manual_scan.txt); do python /home/user/apps/yarasigs/shellbags/shellbags.py "$ram_path"/vol/file_dump/$word2; done >> "$ram_path"/vol/shellbag_manual_results.txt
echo "Finished manually looking for shellbags"

echo "Testing malwoverview - flags will submit all of the carved processes and use the public API to submit. Needs formatting."
nohup python3 /home/user/apps/malwoverview/malwoverview/malwoverview.py -d "$ram_path"/vol/proc_dump/ -v 1 -t 3 > "$ram_path"/vol/malwoverview.txt 2>&1 &

echo "Testing VirusTotal API from https://github.com/Sebastienbr/Volatility. Running against these processes:"
echo "Disabled for now while testing malwoverview"
cat "$ram_path"/vol/virustotal_hash.txt
#echo "This will take a few minutes."
#for word2 in $(cat "$ram_path"/vol/virustotal_hash.txt); do python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile virustotal -r $word2 -i --submit; done >> "$ram_path"/vol/virustotal_output.txt
#echo "Finished processing VirusTotal info."
#grep -e "File:" -e "MD5:" -e "ratio:" "$ram_path"/vol/virustotal_output.txt
echo " "
echo "Processing yarascan - must have prereqs installed for Yara and Yara-Python"
echo "This is in testing mode. Takes a long time and there will be FP."
nohup python $vol_path/vol.py -f $ramdisk --profile=$ram_profile yarascan -y /home/user/apps/yarasigs/yarasigs-master/ye_all_include.yar > "$ram_path"/vol/yarascan_git.txt 2>&1 &
echo "Additional Yara scanning"
#python $vol_path/vol.py -f $ramdisk --profile=$ram_profile yarascan -y /home/user/apps/yarasigs/yarasigs-master/webshells/custom.yar > "$ram_path"/vol/yarascan_git_all.txt
#python $vol_path/vol.py -f $ramdisk --profile=$ram_profile yarascan -Y "Added by HTTrack --" > "$ram_path"/vol/yarascan_artifacts.txt 2>&1 &

echo "Grabbing md5 hash." >> "$ram_path"/vol/time.log
echo "Filename:" >> "$ram_path"/vol/time.log
cat "$ram_path"/vol/be_output/report.xml | grep "image_filename" | cut -d '>' -f2 | cut -d '<' -f1 >> "$ram_path"/vol/time.log
echo "File size:" >> "$ram_path"/vol/time.log
cat "$ram_path"/vol/be_output/report.xml | grep "image_size" | cut -d '>' -f2 | cut -d '<' -f1 >> "$ram_path"/vol/time.log
echo "File hash MD5:" >> "$ram_path"/vol/time.log
cat "$ram_path"/vol/be_output/report.xml | grep "hashdigest" | cut -d '>' -f2 | cut -d '<' -f1 >> "$ram_path"/vol/time.log
tail "$ram_path"/vol/time.log -n 7 -q
echo " "
#Creating a RAM timeline
echo "Creating timeline at: $(date)"
echo Creating timeline at: $(date) >> "$ram_path"/vol/time.log
echo "Creating timeline. Takes a while."
echo "Processing shellbags"
python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile shellbags > "$ram_path"/vol/shellbags.txt
echo "Processing mftparser"
python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile mftparser --output=body > "$ram_path"/vol/mft.txt
cat "$ram_path"/vol/mft.txt | grep "DATA ADS" > "$ram_path"/vol/mft_odd.txt
cat "$ram_path"/vol/mft.txt | grep "DOS batch" >> "$ram_path"/vol/mft_odd.txt
echo "Processing timeliner"
python $vol_path/vol.py --plugins=$PLUGINSPATH -f $ramdisk --profile=$ram_profile timeliner --output=body > "$ram_path"/vol/timeliner.txt

echo "+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+" >> "$ram_path"/vol/time.log
echo "Attempting to make a simple automated report"
touch "$ram_path"/report.txt
head -n 8 "$ram_path"/vol/time.log >> "$ram_path"/report.txt
echo "Analysis of the system named:" >> "$ram_path"/report.txt
grep "COMPUTERNAME" "$ram_path"/vol/envars.txt | awk '{print $5}' | uniq >> "$ram_path"/report.txt
echo "Analyzed system was detected as: $ram_profile" >> "$ram_path"/report.txt
echo " " >> "$ram_path"/report.txt
grep "Image date and time" "$ram_path"/vol/imageinfo.txt | sed -e 's/^\s*//' -e '/^$/d' >> "$ram_path"/report.txt
echo " " >> "$ram_path"/report.txt
echo "Image size is:" >> "$ram_path"/report.txt
ls -lah $ramdisk | awk '{print $5, $6, $7, $8, $9}' >> "$ram_path"/report.txt
echo " " >> "$ram_path"/report.txt
echo "Possible Usernames found:" >> "$ram_path"/report.txt
cat "$ram_path"/vol/filescan.txt | grep "AppData" | grep '\\Users\\' | cut -d '\' -f 5 | sort | uniq | grep -v "Harddisk" | grep -v "Administrator" >> "$ram_path"/report.txt
cat "$ram_path"/vol/filescan.txt | grep "Local Settings" | grep "Documents and Settings" | cut -d '\' -f 5 | sort | uniq | grep -i -v "administrator" | grep -i -v "Service" >> "$ram_path"/report.txt
echo "Possible passwords found: " >> "$ram_path"/report.txt
grep -a "wdigest" "$ram_path"/vol/mimikatz.txt | awk '{print $2, $3, $4}' >> "$ram_path"/report.txt
echo " " >> "$ram_path"/report.txt
echo "Possible registry Run/RunOnce malicious entries: " >> "$ram_path"/report.txt
grep -a "REG_SZ" "$ram_path"/vol/printkey_runs.txt | grep -a -i 'temp\|roaming' >> "$ram_path"/report.txt
echo " " >> "$ram_path"/report.txt
cat "$ram_path"/vol/printkey_ipaddress.txt | sed -e '/^ *$/d' | sed -e 's/^\s*//' -e '/^$/d' >> "$ram_path"/report.txt
echo "Last time Windows Update was run:" >> "$ram_path"/report.txt
cat "$ram_path"/vol/printkey_forensic_artifacts.txt | grep --after-context=1 "Auto Update" | grep "Last updated" | awk '{print $3, $4, $5}' >> "$ram_path"/report.txt
echo "Time zone information:" >> "$ram_path"/report.txt
cat "$ram_path"/vol/printkey_forensic_artifacts.txt |  grep "TimeZoneKeyName" | cut -f '2' -d ')' >> "$ram_path"/report.txt
echo "Last shutdown time from registry and modification date:" >> "$ram_path"/report.txt
cat "$ram_path"/vol/shutdowntime.txt | tail -n 4 >> "$ram_path"/report.txt
echo "Processes not in the whitelist" >> "$ram_path"/report.txt
echo "------------------------------" >> "$ram_path"/report.txt
cat "$ram_path"/vol/psscan_outliers.txt >> "$ram_path"/report.txt
echo " " >> "$ram_path"/report.txt
echo "VT results of the processes" >> "$ram_path"/report.txt
echo "------------------------------" >> "$ram_path"/report.txt
#grep -e "File:" -e "MD5:" -e "ratio:" "$ram_path"/vol/virustotal_output.txt  >> "$ram_path"/report.txt
echo " " >> "$ram_path"/report.txt
echo "Yara results:" >> "$ram_path"/report.txt
echo "------------------------------" >> "$ram_path"/report.txt
grep -v -i "mbam.exe" "$ram_path"/vol/yarascan_git.txt | grep -v -i "msmpeng.exe" | grep -v -i "vpnui.exe" | grep -i 'Owner\|Rule:' | sort | uniq >> "$ram_path"/report.txt
grep -v -i "mbam.exe" "$ram_path"/vol/yarascan_git.txt | grep -v -i "msmpeng.exe" | grep -v -i "vpnui.exe" | grep --after-context=16 "Owner: " | tail -n 16 | awk '{print $18}' >> "$ram_path"/report.txt
echo " " >> "$ram_path"/report.txt
cat "$ram_path"/vol/suspicious_cmdline.txt >> "$ram_path"/report.txt
echo "Finished making the report"
echo "+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+" >> "$ram_path"/vol/time.log
echo Volatility analysis finished on: $(date) >> "$ram_path"/vol/time.log
echo "Completed processing of timeline. Creating CSV: "$ram_path"/vol/timeline.csv"
echo "Completed processing of timeline. Creating CSV: "$ram_path"/vol/timeline.csv" >> "$ram_path"/vol/time.log
cat "$ram_path"/vol/mft.txt "$ram_path"/vol/shellbags.txt "$ram_path"/vol/timeliner.txt "$ram_path"/vol/shellbag_manual.txt "$ram_path"/vol/usnjrnl.txt >> "$ram_path"/vol/bodyfile.txt
mactime -b "$ram_path"/vol/bodyfile.txt -d > "$ram_path"/vol/timeline.csv
echo "Searching for malicious timestamp... $time_stamp"
echo "Searching for malicious timestamp... $time_stamp" >> "$ram_path"/vol/time.log
head "$ram_path"/vol/timeline.csv -n 1 > "$ram_path"/vol/filtered_timeline.csv
cat "$ram_path"/vol/filtered_timeline.csv
cat "$ram_path"/vol/timeline.csv | grep "$time_stamp" >> "$ram_path"/vol/filtered_timeline.csv
cat "$ram_path"/vol/timeline.csv | grep \"$time_stamp\" >> "$ram_path"/vol/filtered_timeline.csv
echo "Filtered timeline linecount: " >> "$ram_path"/report.txt
cat "$ram_path"/vol/filtered_timeline.csv | wc -l >> "$ram_path"/report.txt
echo "Finished."
echo "Tidying up a bit. Removing bodyfile and all zero length txt files."
rm "$ram_path"/vol/bodyfile.txt
find . -type f -empty -delete
echo "+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+" >> "$ram_path"/vol/time.log
echo Timeline creation finished on: $(date) >> "$ram_path"/vol/time.log
END=`date +%s%N`
ELAPSED=`echo "scale=8; ($END - $START) / 1000000000" | bc`
echo "Elapsed time is: $ELAPSED "
echo "Elapsed time is: $ELAPSED seconds." >> "$ram_path"/vol/time.log
echo "Elapsed time is: $ELAPSED seconds." >> "$ram_path"/report.txt
sleep 5
