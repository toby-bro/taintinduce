---
applyTo: "**/*.json"
---

- the `read_taint_output.py` parses all the files in output/\*.json files, try and use this script as most as possible
  - if this script does not provide the data you need, look at its code to see how it reads the JSON structure
- use `jq` to read JSON files if you don't use the python script
- do not assume anything on the structure of the file : start by exploring the keys of each level, before reaching the data you want to access
- do not use taint_visualiser as it generates a web based UI that is not relevant to you !
- the JSON format used here is described in taintinduce/serialization.py
- all the big integers are in fact states, it's their binary representation that matters
