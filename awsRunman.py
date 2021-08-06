import os, sys, traceback
import re, time, datetime, inspect
import shutil, atexit
import subprocess,collections
import yaml

from awsAPIv3 import *
from lib_yijun import print_color

special_list = []
special_list.append("aws ec2 describe-route-tables")

def special_handling(cmd, pattern, resp):
    if cmd  == "aws ec2 describe-route-tables":
        p1 = '(?s)Main: true.*?RouteTableId: (.*?)(?=\n).*?VpcId: (.*?)(?=\n)'
        mainRT_list = re.compile(p1).findall(resp)


def runman(fileName, action=None) -> str:
        print_color("[Info][aws][convert]: Select the default AWS config/credentials","green")
        #must have each resource as its own name in creation part of fileName, otherwise, \
        # termination part will not 100% work
        ans = input("Continue? [Yes/No]")

        if ans.lower() != "yes":
            return

        if action == "termination":
            tmp_obj = aws(record=False)
            tmp_obj.manual_termination(fileName)
            tmp_obj.close()
            return

        def term():
            # strategy: for each term line
            # 1. delete mapped resource
            # 2. delete poped and related resource
            # 3. skip delete

            try:
                with open(new_file, "a") as file:
                    heading = "~~~~~~~~~~~~~~~~~~~ RUNMAN TERM ~~~~~~~~~~~~~~~~~~~~\n"
                    file.write(heading)
            except Exception as e:
                print(e)
                traceback.print_exc(file=sys.stdout)

            org_term_lines = []
            chg_term_lines = []
            with open(fileName, 'r') as f:
                term_cont = f.read()
                pattern = "(?s)~ TERMINATION ~.*"
                org_term_lines = re.compile(pattern).findall(term_cont)[0].split("\n")

            for cmd in org_term_lines:
                if "~~" in cmd:
                    continue
                org_cmd = cmd
                for p in id_list:
                    res = re.compile(p).findall(cmd)
                    if res and res[0] in res_dict:   #strategy 1
                        id = res[0]
                        cmd = cmd.replace(id, res_dict[id])
                    elif res:                       #strategy 2
                        id = res[0]
                        try:
                            v = orphaned[p].pop()
                        except:
                            print("[ERROR]exhausted res_dict:", orphaned[p])
                            tmp_obj.close()
                            return
                        cmd = cmd.replace(id, v)

                if org_cmd != cmd:          #strategy 3
                    chg_term_lines.append(cmd)


            try:
                with open(new_file, "a") as file:
                    for cmd in chg_term_lines:
                        file.write(cmd+"\n")
            except Exception as e:
                print(e)
                traceback.print_exc(file=sys.stdout)



        t_time = datetime.datetime.now()
        new_file = fileName + ".removal"
        # new_file = "aws_runman_" + t_time.strftime("%Y-%m-%d_%H-%M-%S")

        try:
            with open(new_file, "w+") as file:
                heading = "~~~~~~~~~~~~~~~~~~~ RUNMAN CREATION ~~~~~~~~~~~~~~~~~~~~\n"
                file.write(heading)
        except Exception as e:
            print(e)
            traceback.print_exc(file=sys.stdout)

        import signal
        def signal_handler(signal, frame):
            print('RunMan:Someone pressed Ctrl+C!')
            if tmp_obj:
                term()
                tmp_obj.close()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)

        tmp_obj = aws(record=new_file)

        res_dict = collections.defaultdict(lambda: None)
        orphaned = collections.defaultdict(set)
        # orphaned = collections.defaultdict(list)
        id_list = []
        id_list.append(r"igw-\w{5,}")
        id_list.append(r"vpc-\w{5,}")
        id_list.append(r"sg-\w{5,}")
        id_list.append(r"subnet-\w{5,}")
        id_list.append(r"rtb-\w{5,}")
        id_list.append(r"i-\w{5,}")
        id_list.append(r"eni-\w{5,}")
        id_list.append(r"arn:aws:elasticloadbalancing:\S+:loadbalancer\S+")
        id_list.append(r"arn:aws:elasticloadbalancing:\S+:targetgroup\S+")
        id_list.append(r"vpce-\w{5,}")

        # TBD: eni-attach-0cccbaa188cc08d68 [**]
        # TBD: rtbassoc-041c5e6e7959ba458 [**]

        # "Associations": [
        #     {
        #         "Main": true,
        #         "RouteTableAssociationId": "rtbassoc-0df3f54e06EXAMPLE",
        #         "RouteTableId": "rtb-09ba434c1bEXAMPLE"
        #     }
        # ],

        # TBD: eipalloc-3df34d09  [*]

        lineNum = 0
        with open(fileName, "r") as f:
            for line in f:
                lineNum += 1
                if action == "creation" and "~ TERMINATION ~" in line:
                    break
                elif "~~~" in line:
                    continue

                cmd = None
                runman = None
                if "@runman" in line:
                    cmd = re.compile(".*?(?=@runman)").findall(line)[0].strip()
                    runman = re.compile("@runman=(.*?)@").findall(line)[0].strip()
                else:
                    cmd = line.strip()

                # print("Debug:Line=",line)
                #search/replace ID
                for p in id_list:
                    res = re.compile(p).findall(cmd)
                    if runman:
                        res_runman = re.compile(p).findall(runman)
                        if res_runman and res_runman[0] in res_dict:
                            res_id = res_runman[0]
                            runman = runman.replace(res_id, res_dict[res_id])

                    if res and res[0] in res_dict:
                        # print("search/replace ID 1")
                        id = res[0]
                        cmd = cmd.replace(id, res_dict[id])
                    elif res:
                        id = res[0]
                        try:
                            v = orphaned[p].pop()
                        except:
                            print("[ERROR]exhausted res_dict:", orphaned[p])
                            tmp_obj.close()
                            return
                        res_dict[id] = v
                        cmd = cmd.replace(id, v)

                num = 0
                while num < 50:
                    resp = tmp_obj.raw_cli_res(cmd)
                    if "error occurred" in resp and "already exists" not in resp:
                        num += 1
                        time.sleep(5)
                    else:
                        break
                if num >= 50:
                    print(f"[Warning][aws][runman][creation]::[{lineNum}]GiveUp cli={cmd}, after 50 tries", "yellow")
                    tmp_obj.close()
                    return

                #search/add ID
                resp2 = re.sub("AWS-Auto#.*", "", resp)

                if runman:  #limit the search scope for obscure command
                    try:
                        resp2 = re.compile(runman).findall(resp2)[0]
                    except:
                        print_color(f"[Warning][aws][runman][creation] Runman not working: {runman}\n{resp2}", "yellow")

                for p in id_list:
                    # if cmd in special_list:
                    #     special_handling(cmd, runman, resp2)
                    # else:
                    res_list = re.compile(p).findall(resp2)
                    if res_list and res_list[0] not in res_dict.values():
                        orphaned[p].add(res_list[0])

                print("Debug:orphaned=", orphaned)
                print("Debug:res_dict=", res_dict)



        if action == "creation":
            term()


if __name__ == "__main__":
    fileName = sys.argv[1]
    ops = sys.argv[2]
    runman(fileName, ops)
