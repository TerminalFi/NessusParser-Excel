# NessusParser

Python based nessus parser that converts NessusV2 files into formatted XLSX documents.

# Key Features!

  - Multiple file support
  - Formatted XLSX output with worksheets (Full Detail, Device Type, Critical, High, Medium, Low, Informational)

## Table of Contents

  - [Inspiration](#inspiration)
  - [Planned Updates](#planned-updates)
  - [Screen](#screen)
  - [Pro's vs Con's](#pro's-vs-con's)
  - [Usage](#usage)
  - [Example](#example)




### Inspiration

Inspiration of this came from [Nessus Parser - Cody](http://www.melcara.com/archives/253). While this ruby one is still kicking, I prefer python. I hope to eventually emulate all of the features provide by this tool + more


#### Planned Updates

 - Charts: Total Vulnerabilities by Severity, Oldest by patch publication date, Top Offenders
 - Ignored Plugin ID's : Ignore ID's that are noisy, pointless, or other reasons
 - And more!


#### Updates

##### Version 0.3.3

 - Memory Optimization
 - Max memory usage expectency calculation
 - Overview sheet includes Pie chart of Vuln Count by Severities

##### Version 0.3.2

 - Code refractoring
 - Added BugTraq ID's column to Full Report, Critical, High, Medium, Low, Informational


##### Version 0.3.1

 - Code refractoring
 - Added CVE Information to correlating findings. (Last column of worksheets)


##### Version 0.3

 - Optimized Memory Usage (Bug ID: Memory Usage can be calculated pretty accurately. `(Max File Size * 2 + 40)`)


##### Version 0.2

 - Added MS Process Infor Tab
 - Optimized Memory Usage (Bug ID: 1)
 - Nessus v.2 Support
 - File to finding mapping

##### Version 0.2

 - Added MS Process Infor Tab
 - Optimized Memory (Bug ID: 1)
 - Nessus v.2 Support
 - File to finding mapping

##### Version 0.1

 - Creation of Full Report, Device Type, Critical, High, Medium, Low, Informational
 - Multi File Support
 - Nessus v.2 Support
 - File to finding mapping

###### Bugs

 - <del>ID 1: High Memory Usage</del>





#### Screen

| Full Report |
| ---------------|
| <img src="./screenshots/Example1.png" width="100%"> |
| ---------------|
| <img src="./screenshots/Example2.png" width="100%"> |


### Pro's vs Con's
#### Pro's
  - Fast
  - Multi file support
  - Nicely formatted
  - Commented Code (In Progress)

#### Con's
  - Error Checking? What's that! (I have yet to finish this code and wrote it quickly. Didn't implement much of any of this)
 

### Usage

```
pip install pipenv

pipenv install
pipenv shell

python nessusparser.py -l FOLDER_WITH_FILES -o OUTPUT_DIRECTORY/FILENAME
```

#### Example

```
Notice: No file extension specified

python nessusparser.py -l nessus_files -o reports/combined_report
```


