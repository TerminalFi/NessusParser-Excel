# NessusParser

Python based nessus parser that converts a NessusV2 files into formatted XLSX documents.

# Key Features!

  - Multiple file support
  - Formatted XLSX output with worksheets (Full Detail, Device Type, Critical, High, Medium, Low, Informational)

| Screen |
| ---------------|
| <img src="./screenshots/example.png" width="600"> |


## Pro's vs Con's
#### Pro's
  - Fast
  - Multi file support
  - Nicely formatted
  - Commented Code (In Progress)

#### Con's
  - Error Checking? What's that! (I have yet to finish this code and wrote it quickly. Didn't implement much of any of this)
  - Memory usage (Varies from system to system, my MBP (16GB) handles 2GB worth of Nessus files without hiccup 
 

## Usage

```
pip install pipenv

pipenv install
pipenv shell

python nessusparser.py -l FOLDER_WITH_FILES -o OUTPUT_DIRECTORY/FILENAME
```

### Example

```
Notice: No file extension specified

python nessusparser.py -l nessus_files -o reports/combined_report
```


