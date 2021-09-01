#!/usr/bin/env python
import os, sys
import time
import re
import socket
import fcntl
import struct
import pexpect
import yaml, hashlib

########SSH logon stuff############
default_passwd = "rootroot"
prompt_firstlogin = "Are you sure you want to continue connecting \(yes/no.."  # update to regex when "(yes/no/[fingerprint])?"
prompt_passwd_lnx = "root@.*'s password:"
prompt_passwd_ftd = "[pP]assword:"
prompt_logined_lnx = "\\x1b]0;root@.*?\]#"
prompt_logined_lnx_bk = "\[root@.*\]#"
prompt_logined_ftd = "> "
prompt_logined_ftd_root_6_7 = "root@firepower:.*?\$"
prompt_logined_ftd_root_6_8 = "root@firepower:.*?#"
prompt_percentage = ".*100%.*"
prompt_percentage_dir = prompt_logined_ftd_root_6_7

console_passwd_prompt = "[pP]assword:"
console_user_prompt = "[uU]sername:"
console_usr = console_pwd = "lab"
console_prompt = "cluster-.*?#"

# fxos_passwd = "Admin135!"
fxos_passwd = "Cisco123!@#"
fxos_user = "admin"
fxos_firstlogin = "Are you sure you want to continue connecting \(yes/no.."
fxos_passwd_prompt = "[pP]assword:"
fxos_shell_prompt = "firepowerfxos#"
fxos_lina_prompt = ">"
fxos_user_prompt = "firepowerfxos login:"
fxos_more_prompt = "--More--"
ftd_raw_prompt = "firepower>"
ftd_en_prompt = "firepower#"
ftd_conf_prompt = "firepower(.*?)#"
ftd_more_prompt = "<--- More --->"

tnt_console_prompt = "Escape character is '^]'."

OceanPrompt = []
OceanPrompt.append(fxos_shell_prompt)
OceanPrompt.append(fxos_lina_prompt)
OceanPrompt.append(ftd_raw_prompt)
OceanPrompt.append(ftd_en_prompt)
OceanPrompt.append(ftd_conf_prompt)
OceanPrompt.append(fxos_user_prompt)
OceanPrompt.append(fxos_passwd_prompt)

asa_firstlogin = "Are you sure you want to continue connecting \(yes/no.."
asa_raw = "ciscoasa>"
asa_passwd = "Password:"
asa_enable = "ciscoasa#"
asa_config = "ciscoasa(.*?)#"
asa_more = "<--- More --->"
asa_question = "help improve the product? \[Y\]es, \[N\]o, \[A\]sk later:"
asa_reload = "System config has been modified. Save\? \[Y\]es\/\[N\]o:"
# asa_reload_confirm = "Proceed with reload? \[confirm\]"
# asa_overwritten_confirm = "Do you want to over write? \[confirm\]"
asa_confirm = "\[confirm\]"
asa_copy_confirm = "\[.*?\]\?"
asa_shutdown = "- SHUTDOWN NOW -"

asav_geneve_prompt = []
asav_geneve_prompt.append(asa_raw)
asav_geneve_prompt.append(asa_passwd)
asav_geneve_prompt.append(asa_enable)
asav_geneve_prompt.append(asa_config)
asav_geneve_prompt.append(asa_more)
asav_geneve_prompt.append(asa_question)
asav_geneve_prompt.append(asa_firstlogin)
asav_geneve_prompt.append(asa_reload)
asav_geneve_prompt.append(asa_confirm)
asav_geneve_prompt.append(asa_copy_confirm)
asav_geneve_prompt.append(asa_shutdown)
# asav_geneve_prompt.append(asa_overwritten_confirm)


fxos_firstlogin = "Are you sure you want to continue connecting \(yes/no.."
fxos_passwd_creation = "Enter new password:"
fxos_passwd_confirm = "Confirm new password:"
fxos_lina_prompt = "[^\w-]>"
ftd_raw_prompt = "firepower>"
ftd_passwd_prompt = "Password:"
ftd_en_prompt = "firepower#"
ftd_conf_prompt = "firepower\(.*?\)#"
ftd_more_prompt = "<--- More --->"
ftd_exp_admin = "admin@firepower:~\$"
ftd_exp_root = "root@firepower:~#"

ftdv_geneve_prompt = []
ftdv_geneve_prompt.append(fxos_lina_prompt)
ftdv_geneve_prompt.append(ftd_raw_prompt)
ftdv_geneve_prompt.append(ftd_passwd_prompt)
ftdv_geneve_prompt.append(ftd_en_prompt)
ftdv_geneve_prompt.append(ftd_conf_prompt)
ftdv_geneve_prompt.append(ftd_more_prompt)
ftdv_geneve_prompt.append(fxos_firstlogin)
ftdv_geneve_prompt.append(fxos_passwd_creation)
ftdv_geneve_prompt.append(fxos_passwd_confirm)
ftdv_geneve_prompt.append(ftd_exp_admin)
ftdv_geneve_prompt.append(ftd_exp_root)


def force2fxos(ip, port):
    pass


def force2asa(ip, port):
    pass


def force2lina(ip, port):
    pass


def go2fxos_telnet(tnt, res=None):
    while not res or "fxos_user_prompt" not in res:
        tnt.sendline("exit")
        tnt, res = Ocean_reply(tnt)

    tnt.sendline(fxos_user)
    tnt, res = Ocean_reply(tnt)
    tnt.sendline(fxos_passwd)
    tnt, res = Ocean_reply(tnt)

    if "fxos_shell_prompt" not in res:
        print("Error: Failed to Enter FXOS")
    return tnt, res

def go2fxos(tnt, res=None, debug=False):
    if debug: print("enter fxos")
    tnt.sendline("")
    tnt, res, _ = Ocean_reply(tnt, debug=debug)

    num = 0
    while "fxos_lina_prompt" not in res and "timeout" not in res:
        tnt.sendline("exit")
        tnt, res, _ = Ocean_reply(tnt, debug=debug)
        if num > 10:
            print_color("[ERROR][go2fxos]: 'EXIT' exceed the limit","red")
            sys.exit(1)
        num += 1
        #weird behavor to avoid unnecessary exit for go2expert
        tnt.sendline("")
        tnt, res, _ = Ocean_reply(tnt, debug=debug)

    if debug: print("enter fxos done")
    return tnt, res

def go2ftd(tnt, res=None, debug=False):
    if debug: print("enter ftd")
    tnt, res = go2fxos(tnt, debug=debug)

    tnt.sendline("system support diagnostic-cli")
    tnt, result, _ = Ocean_reply(tnt, debug=debug)
    tnt.sendline("")
    Ocean_reply(tnt, debug=debug)

    if debug: print("enter ftd done")
    return tnt, res

def go2expert(tnt, res=None, debug=False):
    if debug: print("enter expert")
    tnt, res = go2fxos(tnt, debug=debug)

    tnt.sendline("expert")
    tnt, result, _ = Ocean_reply(tnt, debug=debug)
    tnt.sendline("")
    Ocean_reply(tnt, debug=debug)

    tnt.sendline("sudo su -")
    tnt, result, _ = Ocean_reply(tnt, debug=debug)
    tnt.sendline("")
    Ocean_reply(tnt, debug=debug)

    if debug: print("enter expert done")
    return tnt, res

def go2lina(tnt, res=None):
    # exit to fxos
    # enter lina
    tnt, res = go2fxos(tnt, res)
    tnt.sendline("connect ftd")
    tnt, res = Ocean_reply(tnt)
    if "fxos_lina_prompt" not in res:
        print("Error: Failed to Enter Lina")

    return tnt, res


def go2asa(tnt, res=None):
    # exit to fxos
    # enter lina
    # enter asa
    go2lina(tnt, res)
    tnt.sendline("system support diagnostic-cli")
    tnt, res = Ocean_reply(tnt)
    if "ftd_raw_prompt" not in res:
        print("Error: Failed to Enter ASA:ftd_raw_prompt")
    tnt.sendline("en")
    tnt, res = Ocean_reply(tnt)
    tnt.sendline("")
    tnt, res = Ocean_reply(tnt)
    if "ftd_en_prompt" not in res:
        print("Error: Failed to Enter ASA:ftd_en_prompt")
    return tnt, res


def console_clear(ip, port):
    tnt = pexpect.spawn('telnet {ip} {port}'.format(ip=ip, port=port))
    tnt, result = Console_reply(tnt)
    # print(result)

    tnt.sendline("clear line 27")
    tnt.expect(["\[confirm\]"], timeout=5)
    tnt.sendline("")
    tnt.expect(["\[OK\]"], timeout=5)
    tnt.close()


def Conn_reply(tnt):
    try:
        result = tnt.expect([pexpect.TIMEOUT, tnt_console_prompt], timeout=5)
        tnt.logfile = None
        if result == 0:
            res = "0:Conn_reply: failure(timeout)!"
            return tnt, res
        elif result == 1:
            tnt.sendline("\n")
            return Ocean_reply(tnt)
    except Exception as e:
        print(e)
        res = "Error:Conn_reply: failure(Exception)"
        return None, res


def Geneve_load(tnt, fileName, timeout=5, debug=False):
    if not os.path.exists(fileName):
        return None
    with open(fileName, "r") as f:
        for line in f:
            line = line.strip()
            # print("debug::", line)
            tnt.sendline(line)
            tnt, result, cont = Geneve_reply(tnt, debug=debug, timeout=timeout)

def Ocean_load(tnt, fileName, timeout=5, debug=False):
    if not os.path.exists(fileName):
        return None
    with open(fileName, "r") as f:
        for line in f:
            line = line.strip()
            # print("debug::", line)
            tnt.sendline(line)
            tnt, result, cont = Ocean_reply(tnt, debug=debug, timeout=timeout)

def Geneve_reply(tnt, timeout=120, debug=False, keyword=None):
    try:
        start_time = time.time()
        if keyword:
            asav_geneve_prompt_upd = []
            for item in asav_geneve_prompt:
                item = item.replace("ciscoasa", keyword)
                asav_geneve_prompt_upd.append(item)
        else:
            asav_geneve_prompt_upd = asav_geneve_prompt

        result = tnt.expect([pexpect.TIMEOUT] + asav_geneve_prompt_upd, timeout=timeout)
        tnt.logfile = None

        if result == 0:
            res = "0:Geneve_reply: failure(timeout)!"
            content = tnt.before.decode()  #content = str(tnt.before)+str(tnt.after)
            if debug: print(res); print(content)
        elif result == 1:
            res = "1:Geneve_reply: success(asa_raw)!"
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
            content = tnt.before.decode()+tnt.after.decode()  #content = str(tnt.before)+str(tnt.after)
        elif result == 2:
            res = "2:Geneve_reply: success(asa_passwd)!"
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
            content = tnt.before.decode()+tnt.after.decode()  #content = str(tnt.before)+str(tnt.after)
            tnt.sendline("cisco")
            _, _, tmp_content = Geneve_reply(tnt, timeout=timeout, debug=debug)
            content += "\n" + tmp_content
        elif result == 3:
            res = "3:Geneve_reply: success(asa_enable)!"
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
            content = tnt.before.decode()+tnt.after.decode()  #content = str(tnt.before)+str(tnt.after)
        elif result == 4:
            res = "4:Geneve_reply: success(asa_config)!"
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
            content = tnt.before.decode()+tnt.after.decode()  #content = str(tnt.before)+str(tnt.after)
        elif result == 5:
            res = "5:Geneve_reply: success(asa_more)!"
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
            content = tnt.before.decode()+tnt.after.decode()  #content = str(tnt.before)+str(tnt.after)
            tnt.sendline(" ")
            _, _, tmp_content = Geneve_reply(tnt, timeout=timeout, debug=debug)
            content += "\n" + tmp_content
        elif result == 6:
            res = "6:Geneve_reply: success(asa_question)!"
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
            content = tnt.before.decode()+tnt.after.decode()  #content = str(tnt.before)+str(tnt.after)
            tnt.sendline("n")
            _, _, tmp_content = Geneve_reply(tnt, timeout=timeout, debug=debug)
            content += "\n" + tmp_content
        elif result == 7:
            res = "7:Geneve_reply: success(asa_firstlogin)!"
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
            content = tnt.before.decode()+tnt.after.decode()  #content = str(tnt.before)+str(tnt.after)
            tnt.sendline("yes")
            _, _, tmp_content = Geneve_reply(tnt, timeout=timeout, debug=debug)
            content += "\n" + tmp_content
        elif result == 8:
            res = "8:Geneve_reply: success(asa_reload)!"
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
            content = tnt.before.decode()+tnt.after.decode()  #content = str(tnt.before)+str(tnt.after)
            tnt.sendline("Y")
            _, _, tmp_content = Geneve_reply(tnt, timeout=timeout, debug=debug)
            content += "\n" + tmp_content
        elif result == 9:
            res = "9:Geneve_reply: success(asa_confirm)!"
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
            content = tnt.before.decode()+tnt.after.decode()  #content = str(tnt.before)+str(tnt.after)
            tnt.sendline("")
            _, _, tmp_content = Geneve_reply(tnt, timeout=timeout, debug=debug)
            content += "\n" + tmp_content
        elif result == 10:
            res = "10:Geneve_reply: success(asa_copy_confirm)!"
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
            content = tnt.before.decode()+tnt.after.decode()  #content = str(tnt.before)+str(tnt.after)
            tnt.sendline("")
            _, _, tmp_content = Geneve_reply(tnt, timeout=timeout, debug=debug)
            content += "\n" + tmp_content
        elif result == 11:
            res = "11:Geneve_reply: success(asa_shutdown)!"
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
            content = tnt.before.decode()+tnt.after.decode()  #content = str(tnt.before)+str(tnt.after)
        else:
            res = "{result}:Geneve_reply: failure(unknown)".format(result=result)
            content = None
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
        return tnt, res, content
    except Exception as e:
        print(e)
        res = "Error:Geneve_reply: failure(Exception)"
        end_time = time.time()
        gap = round(end_time - start_time,2)
        if debug: print(f"{res} # cost {gap}s")
        return None, res, None


def Ocean_reply(tnt, timeout=30, debug=False):
    try:
        start_time = time.time()
        result = tnt.expect([pexpect.TIMEOUT] + ftdv_geneve_prompt, timeout=timeout)
        tnt.logfile = None
        if result == 0:
            res = "0:Ocean_reply: failure(timeout)!"
            content = tnt.before.decode()
            if debug: print(res);print(content)
        elif result == 1:
            res = "1:Ocean_reply: success(fxos_lina_prompt)!"
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
            content = tnt.before.decode()+tnt.after.decode()
        elif result == 2:
            res = "2:Ocean_reply: success(ftd_raw_prompt)!"
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
            content = tnt.before.decode()+tnt.after.decode()
        elif result == 3:
            res = "3:Ocean_reply: success(ftd_passwd_prompt)!"
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
            content = tnt.before.decode()+tnt.after.decode()
            if "Sorry, try again" in content:
                tnt.sendline("Cisco123!@#")   #expert mode
            else:
                tnt.sendline("")               #ftd en mode
            _, _, tmp_content = Ocean_reply(tnt, timeout=timeout, debug=debug)
            content += "\n" + tmp_content
        elif result == 4:
            res = "4:Ocean_reply: success(ftd_en_prompt)!"
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
            content = tnt.before.decode()+tnt.after.decode()
        elif result == 5:
            res = "5:Ocean_reply: success(ftd_conf_prompt)!"
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
            content = tnt.before.decode()+tnt.after.decode()
        elif result == 6:
            res = "6:Ocean_reply: success(ftd_more_prompt)!"
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
            content = tnt.before.decode()+tnt.after.decode()
            tnt.sendline(" ")
            _, _, tmp_content = Ocean_reply(tnt, timeout=timeout, debug=debug)
            content += "\n" + tmp_content
        elif result == 7:
            res = "7:Ocean_reply: success(fxos_firstlogin)!"
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
            content = tnt.before.decode()+tnt.after.decode()
            tnt.sendline("yes")
            _, _, tmp_content = Ocean_reply(tnt, timeout=timeout, debug=debug)
            content += "\n" + tmp_content
        elif result == 8:
            res = "8:Ocean_reply: success(fxos_passwd_creation)!"
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
            content = tnt.before.decode()+tnt.after.decode()
            tnt.sendline("Cisco123!@#")
            _, _, tmp_content = Ocean_reply(tnt, timeout=timeout, debug=debug)
            content += "\n" + tmp_content
        elif result == 9:
            res = "9:Ocean_reply: success(fxos_passwd_confirm)!"
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
            content = tnt.before.decode()+tnt.after.decode()
            tnt.sendline("Cisco123!@#")
            _, _, tmp_content = Ocean_reply(tnt, timeout=timeout, debug=debug)
            content += "\n" + tmp_content
        elif result == 10:
            res = "10:Ocean_reply: success(ftd_exp_admin)!"
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
            content = tnt.before.decode()+tnt.after.decode()

        elif result == 11:
            res = "11:Ocean_reply: success(ftd_exp_root)!"
            end_time = time.time()
            gap = round(end_time - start_time,2)
            if debug: print(f"{res} # cost {gap}s")
            content = tnt.before.decode()+tnt.after.decode()
        else:
            res = "{result}:Ocean_reply: failure(unknown)".format(result=result)
        return tnt, res, content
    except Exception as e:
        print(e)
        res = "Error:Ocean_reply: failure(Exception)"
        end_time = time.time()
        gap = round(end_time - start_time,2)
        if debug: print(f"{res} # cost {gap}s")
        return None, res, None


def Console_reply(tnt):
    try:
        result = tnt.expect([console_user_prompt, console_passwd_prompt, console_prompt, pexpect.TIMEOUT], timeout=5)
        tnt.logfile = None
        if result == 0:
            tnt.sendline(console_usr)
            tnt.expect([console_passwd_prompt], timeout=5)
            tnt.sendline(console_pwd)
            tnt.expect([console_prompt], timeout=5)
            res = "0:telnet: success!"
        elif result == 1:
            tnt.sendline(console_pwd)
            tnt.expect([console_prompt], timeout=5)
            res = "1:telnet: success!"
        elif result == 2:
            res = "2:telnet: success!"
        elif result == 3:
            res = "3:telnet: failure(timeout)!"
        else:
            res = "{result}:telnet: failure(unknown)".format(result=result)
        return tnt, res
    except Exception as e:
        print(e)
        res = "Error:telnet: failure(Exception)"
        return None, res

import shutil, sys
def withprogressbar(func):
    def _func_with_progress(*args, **kwargs):
        max_width, _ = shutil.get_terminal_size()
        gen = func(*args, **kwargs)
        while True:
            try:
                progress, passed_time = next(gen)
            except StopIteration as exc:
                sys.stdout.write('\n')
                return exc.value
            else:
                message = '[%s] {}%%({}s)'.format(progress, round(passed_time, 2))
                bar_width = max_width - len(message) + 3
                filled = int(round(bar_width / 100.0 * progress))
                spaceleft = bar_width - filled
                bar = '=' * filled + ' ' * spaceleft
                sys.stdout.write((message+'\r') % bar)
                sys.stdout.flush()

    return _func_with_progress

@withprogressbar
def wait(seconds):
    start = time.time()
    step = seconds / 100.0
    for i in range(1, 101):
        time.sleep(step)
        passed_time = time.time() - start
        yield i, passed_time  # Send % of progress to withprogressbar
    return time.time() - start

def timer(op):
    global timer_p, timer_start

    def report(beginning):
        while True:
            passed_time = time.time() - beginning
            sys.stdout.write("timer::{}s\r".format(round(passed_time,2)))
            sys.stdout.flush()
            time.sleep(1)

    if op == "start":
        from multiprocessing import Process
        timer_start = time.time()
        timer_p = Process(target=report, args=(timer_start,))
        timer_p.start()
        # p.join()  等结束
    elif op == "stop":
        timer_p.terminate()
        end = time.time() - timer_start
        print("timer::{}s".format(round(end, 2)))
        # del sys.modules["multiprocessing"]  #not sugguested


if __name__ == "__main__":
    # console_clear("172.23.62.184", "23")
    print("start clear console")
    console_clear("172.23.62.184", "23")
    print("start test")
    tnt = pexpect.spawn('telnet 172.23.62.184 2027')
    tnt, result = Conn_reply(tnt)

    go2asa(tnt)
    tnt.sendline("show cluster info")
    tnt, res = Ocean_reply(tnt)
    print(tnt.before[:-1])

    go2fxos(tnt)
    tnt.sendline("show version")
    tnt, res = Ocean_reply(tnt)
    print(tnt.before[:-1])

def print_color(message, color="black", style="{}", newLine=True):
    COLORS = {
        "black": "\x1b[30m",
        "red": "\x1b[31m",
        "green": "\x1b[32m",
        "yellow": "\x1b[33m",
        "blue": "\x1b[34m",
        "magenta": "\x1b[35m",
        "cyan": "\x1b[36m",
        "white": "\x1b[37m"
    }
    ENDCOLOR = "\x1b[0m"
    color = color.lower()
    if not color in COLORS:
        color = "black"
    color = COLORS[color]
    args = list(message)

    if len(args) == 0:
        # print('{0}{1}{2}'.format(COLORS['red'],"[ERROR]:[print_color]:Empty Message!!!",ENDCOLOR))
        message = ""
    else:
        args[0] = '{0}{1}'.format(color, str(args[0]))
        args[-1] = '{1}{0}'.format(ENDCOLOR, str(args[-1]))
        message = "".join(args)

    format_str = style.format(message)
    if newLine:
        print(format_str)
    else:
        print(format_str, end="")