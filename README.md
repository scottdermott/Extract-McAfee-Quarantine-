# Extract-McAfee-Quarantine-
Extract meta data from McAfee Quarantine XOR'd files
7z Used for .bup extract
- xor.exe used to decrypt the contents of the extracted bup (details and File_0)
For more info see : https://kc.mcafee.com/corporate/index?page=content&id=KB72755&pmv=print

## Instructions
1. Drop .bup files in the Quarantine directory
2. Add the Quarantine directory to Windows defender exceptions
3. **Important** - This script extracts potential malicious binaries – Take precautions (Disconnect from WiFi, etc)
4. Run - # python main.py
5. Open generated "bup_output.csv"

##### The script parses the McAfee bup file(s) and collects the following (Example)

- Name : 7e191a153b31b90
- Date : 2017-09-26T21:59:49
- OriginalName : C:\WINDOWS\MSSECSVC.EXE
- DetectionName : Ransom-WannaCry!153EF357F607
- MD5 Checksum : 153ef357f607745c50ac7ccb3dd2b470


##### Generated CSV 
'Date', 'Name', 'Original Name', 'Detection Name', 'MD5 Checksum'
