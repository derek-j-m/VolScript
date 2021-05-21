# VolScript
This is my version of a "simple" shell script for automated processing of Windows RAM captures using Volatility 2.6. I've been using a similar script for years, and have slowly been improving it as I see interesting new ideas come up in the awesome InfoSec community. It got pretty long, but I've tried to make it modular and easy to read. It runs what I would call is the kitchen sink of Volatility commands and saves their output into a new folder for full analysis.
Hopefully somebody else can make use of this version, and if anyone has ideas on how to improve it please don't hesitate to reach out.

Enjoy - warts and all!

Features:
 - Automatic detection of the Windows version based on the output of kdbgscan.
 - Copying of the RAM image to a scratch or ramdisk location for faster processing.
 - "Multi-threaded" processing and string searching using nohup or other built in bash trickery.
 - An automated simplistic report will be generated at the end.
 - Automated virustotal checking using MalwOverview.
 - Bulk_extractor and strings are part of the process. 


Requirements:
This is a shell script that runs via Linux - I have always used Ubuntu LTS, and 20.04 is what I currently use. 
Other dependencies are: Python 2.x AND 3.x, git, nuhup, parallel, mactime, yara, Automater, malwoverview, and hashdeep. 
As you install your own version of Volatility you will find it has its own dependencies, some of which can be challenging to find due to their version. At the time of this commit, version 2.6 of Volatility is the latest. I look forward to the final release of Volatility 3.0 - it may force me finally to rewrite this automation in Python.

