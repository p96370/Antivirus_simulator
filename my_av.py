#!/usr/bin/python3

def check_database(my_line):
    file = open("data/urls/domains_database", "rt")
    data = file.readlines()
    for domain in data:
        domain = domain.strip()
        if domain in my_line:
            return 1
    file.close()
    return 0

def check_malware(line):
    n = len(line)
    if line[n - 2] == 'e' and line[n - 3] == 'x' and line[n - 4] == 'e' and line[n - 5] == '.':
        return 1
    return 0

def check_digits(line, test):
    digits = 0
    len_dom = 0
    i = -1
    poz = 0
    i = line.find("http://")
    if i != -1:
        poz = 7
    else:
        i = line.find("https://")
        if i != -1:
            poz = 8 
    while line[poz] != '/' and poz < len(line) - 1:
        if line[poz] >= '0' and line[poz] <= '9':
            digits += 1
        poz += 1
        len_dom += 1

    if digits * 10 >= len_dom:
        return 1
    return 0

def check_www(line):
    poz = -1
    poz = line.find("http://")
    if poz == -1:
        poz = line.find("https://")
    if poz == -1:
        poz = 0
    if line[poz] == 'w' and line [poz + 1] == 'w' and line[poz + 2] == 'w':
        if line[poz + 3] != '.':
            return 1
    return 0

f = open("data/urls/urls.in", "rt")
g = open("urls-predictions.out", "wt")

lines = f.readlines()
test = 0
for line in lines:
    test += 1
    ok1 = check_database(line)
    ok2 = check_malware(line)
    ok3 = check_digits(line, test)
    ok4 = check_www(line)
    if ok1 == 1 or ok2 == 1 or ok3 == 1:
        g.write("1\n")
    elif ok4 == 1:
        g.write("1\n")
    else:
        g.write("0\n")


f.close()
g.close()

def valid_flow_time(line):
    poz = -1
    poz = line.find("0 days")
    if poz != -1:
        for i in range(poz, poz + 8):
            if line[i] != ':' and line[i] != '0':
                return 0
    return 1

def valid_flow_pkts(line):
    n = len(line)
    if line[n - 1] == '0' and line[n - 2] == '.' and line[n - 3] == '0' and line[n - 4] == ',':
        return 1
    return 0

fin = open("data/traffic/traffic.in", "rt")
fout = open("traffic-predictions.out", "wt")

test = 0
lines = fin.readline()
lines = fin.readlines()
for line in lines:
    line = line.strip()
    ok1 = valid_flow_time(line)
    ok2 = valid_flow_pkts(line)
    if ok1 == 1:
        fout.write("0\n")
    elif ok2:
        fout.write("0\n")
    else: # ok1 = 0 si ok2 = 0
        fout.write("1\n")

fin.close()
fout.close()