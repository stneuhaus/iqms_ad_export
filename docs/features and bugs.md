## bug: Missing group members

Bugdescription: In case a group has more than 100 members only the first 100 group members will be retrieved.

Expected Result: All group members will be retrieved

Status: Solved

## feature: Enhance documentation and usage

Expected Result:

* Purpose of Programm will be explained in readme.md.
* Prerequisites input file, mapping file and output file(s) will be explained in readme.md
* The folder structure will be explained in readme.md file
  * Explanation of expected files in the folder
* How to get the Bearer Token will be explained in the readme.md

Code Changes

* All code comments must be English
* When starting the program an explanation should show which option exist to start the programm

Status: Solved

## feature: change report type to csv format

Exprected Result: The current md file format observations_from_get_users_and_groups_20260220_181359.md does it make difficult to search and filter for observations. Therefore the fileformat must be changed to csv. The existing md file should not be produced anymore and will be replaced. The file name should be observations_{TIME_STAMP}.csv

The new csv file format should contain following columns. These columns should be filled in case an observation was made.

* TIME_STAMP	-> date and time of occurence,  YYYY-MM-DD HH:MM e.g. 2026-12-31 14:35
* SCRIPT_NAME	-> the script name that produced this entry
* OBSERVATION_TYPE	-> Made observation. Please add here `Group with 0 members`  or  `Group Not Found`
* OBSERVATION	-> for both observation types add the group name
* ADD_INFO1	-> for observation type `Group with 0 members`  add group ID for `Group Not Found` leave it empty
* ADD_INFO2	-> For future use, keep it empty.
