import os, sys, traceback
import re, time, datetime, inspect
import shutil, atexit
import subprocess,collections
import yaml

from awsRESv4 import *
from lib_yijun import print_color
#version 2: add command cli recording
#version 3: add blind function to fetch address/id of aws resource
#version 3.1: update Manual_termination to suport runman
#version 3.2: config syntax check
#version 3.3: record_cli add runman notes

class aws(object):
    def __init__(self, configuration=None, record=True, debug=False):
        self.config = False
        self.credentials = False
        self.home = os.getenv("HOME")
        self.prompt = "AWS-Auto#"
        self.res_deployment = collections.defaultdict(lambda: None) #Yijun
        self.res_yaml = None
        self.res_mapping = {}
        self.resource = {}
        self.tobeCleanUp = {}
        self.resCleanUp = not debug
        self.cfgCleanUp = True
        self.term_seq = collections.deque()
        self.close_toggle = False
        self.cliLog = None

        t_time = datetime.datetime.now()
        if record:
            if record != True:
                self.cliLog = record
            else:
                self.cliLog = "aws_cli_" + t_time.strftime("%H-%M-%S_%d-%m-%Y")

        atexit.register(self.close)

        self._config_backup()

        if not configuration:
            setting = {}
            if not self.credentials:
                credentials = self._credentials_interactive_setup()
                setting["credentials"] = credentials
            if not self.config:
                config = self._config_interactive_setup()
                setting["config"] = config

            self._config_set(setting)
        else:
            self._config_set(configuration)

    def close(self, exec=True):
        print("\nDebug::close triggered")
        self._res_clean(exec)
        self._config_restore()
        self.close_toggle = True

    def __exit__(self):
        print("\nDebug::__exit__ triggered")
        if not self.close_toggle:
            self.close()

    def __del__(self):
        print("\nDebug::__del__ triggered")
        if not self.close_toggle:
            self.close()

    def _config_backup(self):
        path_config = self.home + "/.aws/config"
        if not os.path.exists(path_config):
            print("[Warn/_config_backup]: No ~/.aws/config found!")
        else:
            self.config = True
            os.popen(f"cp {path_config} {path_config}_auto_bk")

        path_credentials = self.home + "/.aws/credentials"
        if not os.path.exists(path_credentials):
            print("[Warn/_config_backup]: No ~/.aws/credentials found!")
        else:
            self.credentials = True
            os.popen(f"cp {path_credentials} {path_credentials}_auto_bk")

        if self.credentials and self.config:
            while not os.path.exists(f"{path_config}_auto_bk") or \
                    not os.path.exists(f"{path_credentials}_auto_bk"):
                time.sleep(0.1)

        return None

    def _config_restore(self):
        if self.resCleanUp:
            self._res_term()
            self.resCleanUp = False

        if self.cfgCleanUp:
            if self.config:
                path_config_bk = self.home + "/.aws/config" + "_auto_bk"
                path_config_org = self.home + "/.aws/config"
                if not os.path.exists(path_config_bk):
                    print("[ERROR]: No ~/.aws/config_auto_bk found!")
                    print("[Warning]: Maybe 2+ aws object closure with same configure file")
                    # traceback.print_stack()
                else:
                    shutil.move(path_config_bk, path_config_org)
                    # os.popen(f"mv {path_config_bk} {path_config_org}")  python exit-prog kill popen ahead
            else:
                os.remove(self.home + "/.aws/config")

            if self.credentials:
                path_credentials_bk = self.home + "/.aws/credentials" + "_auto_bk"
                path_credentials_org = self.home + "/.aws/credentials"
                if not os.path.exists(path_credentials_bk):
                    print("[ERROR]: No ~/.aws/credentials_auto_bk found!")
                    print("[Warning]: Maybe 2+ aws object closure with same configure file")
                    # traceback.print_stack()
                else:
                    shutil.move(path_credentials_bk, path_credentials_org)
                    # os.popen(f"mv {path_credentials_bk} {path_credentials_org}")python exit-prog kill popen ahead
            else:
                os.remove(self.home + "/.aws/credentials")

            self.cfgCleanUp = False

        return

    def _config_interactive_setup(self):
        config = "[default]" + "\n"
        res3 = input("Default region name [None]: ")
        config += "region = " + res3 + "\n"
        res4 = input("Default output format [None]: ")
        config += "output = " + res4 + "\n"
        return config

    def _credentials_interactive_setup(self):
        credentials = "[default]" + "\n"
        res1 = input("AWS Access Key ID [None]:")
        credentials += "aws_access_key_id = " + res1 + "\n"
        res2 = input("AWS Secret Access Key [None]:")
        credentials += "aws_secret_access_key = " + res2 + "\n"
        return credentials

    def _connection_check(self):
        pass

    def _config_set(self, setting):
        try:
            if isinstance(setting["config"], str):
                with open(self.home + "/.aws/config", "w+") as f1:
                    f1.write(setting["config"])

            elif isinstance(setting["config"], dict):
                # {"default":{"access-id":"1234","secret-id":"3456",...}, "profile2":{...}}
                cont = ""
                for profile, content in setting["config"].items():
                    cont += f"[{profile}]" + "\n"
                    for key, value in content.items():
                        cont += f"{key} = {value}" + "\n"
                with open(self.home + "/.aws/config", "w+") as f1:
                    f1.write(cont)

        except KeyError:
            print("[Info]: Use default config setting")
            # traceback.print_exc(file=sys.stdout)

        try:
            if isinstance(setting["credentials"], str):
                with open(self.home + "/.aws/credentials", "w+") as f2:
                    f2.write(setting["credentials"])
            elif isinstance(setting["credentials"], dict):
                # {"default":{"access-id":"1234","secret-id":"3456",...}, "profile2":{...}}
                cont = ""
                for profile, content in setting["credentials"].items():
                    cont += f"[{profile}]" + "\n"
                    for key, value in content.items():
                        cont += f"{key} = {value}" + "\n"
                with open(self.home + "/.aws/credentials", "w+") as f2:
                    f2.write(cont)

        except KeyError:
            print("[Info]: Use default credentials setting")
            # traceback.print_exc(file=sys.stdout)

    def config_check(self):
        if not os.path.exists(self.home + "/.aws/config"):
            print("[ERROR]: No ~/.aws/config found!")

        if not os.path.exists(self.home + "/.aws/credentials"):
            print("[ERROR]: No ~/.aws/credentials found!")

        if self.config:
            res = os.popen(f"cat {self.home}/.aws/config").read()
            print(res)

        if self.credentials:
            res = os.popen(f"cat {self.home}/.aws/credentials").read()
            print(res)

    def raw_cli_res(self, commandline, runman=None, show=True, exec=True):

        self.record_cli(commandline, runman)
        if not self.resCleanUp:
            if "res_clean" in inspect.stack()[2][3]:
                return ""

        if not exec:
            return ""

        if show:
            print_color(self.prompt, "black", newLine=False)
            print_color(commandline, "blue")

        res1 = "AWS-Auto#" + commandline + "\n"
        # res2 = os.popen(commandline).read()  not working in class destructor
        p = subprocess.Popen(commandline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        res2 = out.decode()
        if type(err).__name__ == "bytes":
            err = err.decode()
        if show:
            if not err:
                print_color(res2, "green")
            else:
                print_color(err, "red")
                print_color(res2, "red")
        return res1 + res2 + err

    def raw_cli(self, commandline, show=True):

        category, sub_class = self._res_filter(commandline)

        if show:
            print_color(self.prompt, "black", newLine=False)
            print_color(commandline, "blue")

        res1 = "AWS-Auto#" + commandline + "\n"
        # res2 = os.popen(commandline).read()  not working in class destructor
        p = subprocess.Popen(commandline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        res2 = out.decode()
        if type(err).__name__ == "bytes":
            err = err.decode()

        if not err and category:
            res_suite = self._res_deepHandle(category, res2)
            self.resource[category][sub_class] += res_suite

        if show:
            if not err:
                print_color(res2, "green")
            else:
                print_color(err, "red")
                print_color(res2, "red")

        return res1 + res2 + err

    def _res_filter(self, commandline):
        category = None
        sub_class = None
        if "aws ec2 run-instances" in commandline:
            category = "EC2"
            sub_class = "INSTANCES"
            if "EC2" not in self.resource:
                self.resource[category] = {}
                self.tobeCleanUp[category] = []
                self.resource[category][sub_class] = []
            elif "INSTANCES" not in self.resource["EC2"]:
                self.resource[category][sub_class] = []

        return category, sub_class

    def _res_deepHandle(self, category, res2):
        if not res2:
            return None
        if category == "EC2":
            yml = yaml.load(res2, Loader=yaml.FullLoader)

            for ins in yml["Instances"]:
                temp = {}
                temp["InstanceId"] = ins["InstanceId"]
                temp["LaunchTime"] = ins["LaunchTime"]
                self.tobeCleanUp[category].append(temp)

            return yml["Instances"]

    def _res_term(self):
        if self.tobeCleanUp != {}:
            print_color("Resource Clean Up", style="\n{0:#^50}")

            if "EC2" in self.tobeCleanUp:
                print_color(".....[CleanUP][EC2].......")
                for ins in self.tobeCleanUp["EC2"]:
                    id = ins["InstanceId"]
                    cmd = f"aws ec2 terminate-instances --instance-ids {id}"
                    self.raw_cli(cmd)

            if "KeyPair" in self.tobeCleanUp:
                print_color(".....[CleanUP][KeyPair].......")
                for key in self.tobeCleanUp["KeyPair"]:
                    cmd = f"aws ec2 delete-key-pair --key-name {key}"
                    self.raw_cli(cmd)
                    os.remove(key+".pem")

            print_color("END", style="{0:#^50}")

    def list_resource(self, verbose=False):
        if verbose:
            print_color(yaml.dump(self.resource), "cyan")
        else:
            print_color(yaml.dump(self.tobeCleanUp), "magenta")

    def record_cli(self, cmd, runman=None):
        if self.cliLog:
            try:
                with open(self.cliLog, "a") as file:
                    if runman:
                        cli = cmd + " @runman=" + runman + "@" + "\n"
                    else:
                        cli = cmd + "\n"
                    file.write(cli)
            except NameError:
                pass
            except Exception as e:
                print(e)
                traceback.print_exc(file=sys.stdout)

    def res_record(self, fileName=None):
        if not fileName:
            t_time = datetime.datetime.now()
            fileName = "aws_res_" + t_time.strftime("%H-%M-%S_%d-%m-%Y ")
        try:
            with open(fileName, "w+") as file:
                yaml.dump(self.resource, file)
                # yaml.dump("{0:#^50}".format("name-instance"), file)
                file.write("\n{0:#^50}\n".format("name-instance"))
                yaml.dump(self.res_mapping, file)
        except Exception as e:
            print(e)
            traceback.print_exc(file=sys.stdout)

    def key_generation(self, keyName=None):
        if not keyName:
            keyName = "key_auto"

        cmd = "aws ec2 create-key-pair --key-name " + keyName
        res = self.raw_cli(cmd, False)
        pattern = r"(?s)KeyMaterial: '(.*?)'"
        key_private = re.compile(pattern).findall(res)
        if key_private != []:
            with open(keyName+".pem", "w+") as f:
                f.write(key_private[0])

            if "KeyPair" not in self.tobeCleanUp:
                self.tobeCleanUp["KeyPair"] = [keyName]
            else:
                self.tobeCleanUp["KeyPair"].append(keyName)
        else:
            print_color("[Error]:[key_generation]","red")
            print(res)

    def load_deployment(self, fileName=None, content=None):
        if fileName:
            try:
                with open(fileName, "r") as f:
                    cont =f.read()
            except FileNotFoundError as e:
                print_color(f"[ERROR][awsAPI.load_deplyment]:{e}", "red")
                traceback.print_exc(file=sys.stdout)
                return
        else:
            cont = content

        self.res_yaml = yaml.load(cont,Loader=yaml.FullLoader)

        if not self.res_yaml:
            print_color(f"[ERROR][awsAPI._res_arrange]: Empty resource content", "red")
            return

        good_result, complain = self._syntax_check()
        if not good_result:
            print_color("[Error][awsAPI.load_deplyment]:configure file syntax not correct", "red")
            print_color(f"can't find dependency of {complain}", "red")
            sys.exit(1)
        else:
            print_color("Syntax Check...Pass", "green")

        for res, content in self.res_yaml.items():
            tagName, resName = re.compile(r'(.*?)\((.*?)\)').findall(res)[0]
            res_class = eval(resName)
            self.res_deployment[tagName] = res_class(tagName, content)

    def start_deployment(self):
        if self.cliLog:
            try:
                with open(self.cliLog, "w+") as file:
                    heading = "~~~~~~~~~~~~~~~~~~~ CREATION ~~~~~~~~~~~~~~~~~~~~\n"
                    file.write(heading)
            except Exception as e:
                print(e)
                traceback.print_exc(file=sys.stdout)

        for res in self._creation_sort(self.res_deployment):
            self.term_seq.append(res)
            self.res_deployment[res].exec_creation(self)

    def find_id(self, name):
        if name not in self.res_deployment:
            return None
        else:
            return self.res_deployment[name].get_id()

    def _res_clean(self, exec=True):
        if self.cliLog:
            try:
                with open(self.cliLog, "a") as file:
                    heading = "~~~~~~~~~~~~~~~~~~~ TERMINATION ~~~~~~~~~~~~~~~~~~~~\n"
                    file.write(heading)
            except Exception as e:
                print(e)
                traceback.print_exc(file=sys.stdout)


        if any(self.res_deployment.values()):
            for name in self._termination_sort():
                res = self.res_deployment[name]
                name_list = res.exec_termination(self, exec)
                # print("debug:name_list=", name_list)
                if name_list:
                    idx = 0
                    for nm in name_list:
                        tmp = self.term_seq.index(nm)
                        idx = max(tmp, idx)

                    # print("debug:max_idx=",idx)
                    self.term_seq.insert(idx+1, name)
                    # print("debug:self.term_seq=", self.term_seq)

                else:
                    self.res_deployment[name] = None

    def _termination_sort(self):
        while self.term_seq:
            yield self.term_seq.pop()

    def _creation_sort(self, res_deployment):
        pop_list = set()
        leng = len(res_deployment)
        candi_res = {}
        for name, res_obj in res_deployment.items():
            candi_res[name] = res_obj.get_creation_dependency()

        num = 0
        while len(pop_list) != leng:
            for name,s_value in candi_res.items():
                if name in pop_list:
                    continue
                else:
                    if not s_value:
                        pop_list.add(name)
                        # print("[Info]::Created List:", pop_list) #Yijun
                        # print("[Info]::Waiting List:", candi_res) #Yijun
                        yield name
                    else:
                        old = candi_res[name]
                        if old & pop_list:
                            candi_res[name].difference_update(pop_list)

            num += 1
            if num % 100 == 0:
                print("[Info]::Created List:", pop_list)
                print("[Info]::Waiting List:", candi_res)
                print_color(f"[Warning][awsAPI][_creation_sort]: the Loop reach {num} times", "yellow")
                res = input("Do you really have so many objects to create? or software hit dead loop? Continue or Quit[C/Q]")
                if res.lower() != 'c':
                    print_color("[Info][awsAPI][_creation_sort]: Quit the Application", "black")
                    sys.exit(1)

    def manual_termination(self, fileName):
        if not os.path.exists(fileName):
            print_color(f"[Error][aws][manual_termination]: no such file exist: {fileName}", "red")

        with open(fileName,'r') as f:
            term_cont = f.read()
            if "~ RUNMAN TERM ~" in term_cont:
                pattern = "(?s)~ RUNMAN TERM ~.*"
            elif "~ TERMINATION ~" in term_cont:
                pattern = "(?s)~ TERMINATION ~.*"

            cmd_list = re.compile(pattern).findall(term_cont)[0].split("\n")

            for cmd in cmd_list:
                if "~ TERMINATION ~" not in cmd and "~ RUNMAN TERM ~" not in cmd:
                    cmd = cmd.strip()
                    num = 0
                    while num <= 40:
                        resp = self.raw_cli_res(cmd)
                        if "does not exist" in resp:
                            break
                        elif "error occurred" in resp and "no route with destination-cidr-block 0.0.0.0/0" not in resp:
                            time.sleep(10)
                            num += 1
                            print(num)
                        else:
                            break

    def _syntax_check(self):
        res_set = set()
        dep_set = set()

        for res, content in self.res_yaml.items():
            tagName, resName = re.compile(r'(.*?)\((.*?)\)').findall(res)[0]
            res_set.add(tagName)
            try:
                bt = content["action"]["bind_to"]
            except:
                continue
            if type(bt).__name__ == "list":
                for item in content["action"]["bind_to"]:
                    dep_set.add(item)
            elif type(bt).__name__ == "str":
                dep_set.add(bt)

        res = dep_set.issubset(res_set)
        err = dep_set.difference(res_set)
        return res, err

    def fetch_address(self, res_name):
        if res_name not in self.res_deployment:
            print_color(f"[Warning][aws][fetch_address]: unknown res {res_name}","yellow")
            return None
        else:
            res_obj = self.res_deployment[res_name]
            if type(res_obj).__name__ == "EC2INSTANCE":
                IP = res_obj.fetch_PIP(self, res_name)
                if IP:
                    return IP
                print_color(f"[Warning][aws][fetch_address]: Can't find the IP from {res_name}", "yellow")
                return None
        print_color(f"[Warning][aws][fetch_address]: no support of {res_name}", "yellow")
        return None

    # @staticmethod
    def blind(self, resName, typeName=None, fullList=False, show=True):
        if not typeName:
            cmd = f"aws ec2 describe-tags --filters Name=tag-value,Values={resName}"
            res = self.raw_cli_res(cmd, show=show)
            pattern = r"ResourceId: (.*)"
            try:
                if not fullList:
                    id = re.compile(pattern).findall(res)[0].strip()
                else:
                    id = re.compile(pattern).findall(res)
            except IndexError:
                print_color(f"[Warning][aws][blind] not exist:{resName}", "yellow")
                return None
            else:
                return id
        else: #fullList not supported
            result = collections.defaultdict(lambda: None)
            try:
                if typeName == "EC2INSTANCE":
                    cmd = f"aws ec2 describe-instances --filters Name=tag-value,Values={resName}"
                    res = self.raw_cli_res(cmd, show=show)
                    pattern1 = r"PrivateIpAddress: (.*)"
                    private_ip = re.compile(pattern1).findall(res)[0].strip()
                    result["private_ip"] = private_ip
                    pattern2 = r"PublicIpAddress: (.*)"
                    public_ip = re.compile(pattern2).findall(res)[0].strip()
                    result["public_ip"] = public_ip
                    pattern3 = r"InstanceId: (.*)"
                    id = re.compile(pattern3).findall(res)[0].strip()
                    result["id"] = id
                    return result
                elif typeName == "NETWORK_INTERFACE":
                    cmd = f"aws ec2 describe-network-interfaces --filters Name=tag-value,Values={resName}"
                    res = self.raw_cli_res(cmd, show=show)
                    pattern1 = r"PrivateIpAddress: (.*)"
                    private_ip = re.compile(pattern1).findall(res)[0].strip()
                    result["private_ip"] = private_ip
                    pattern3 = r"InstanceId: (.*)"
                    id = re.compile(pattern3).findall(res)[0].strip()
                    result["id"] = id
                    return result
                elif typeName == "SECURITY_GROUP":
                    cmd = f"aws ec2 describe-security-groups --filters Name=tag-value,Values={resName}"
                    res = self.raw_cli_res(cmd, show=show)
                    pattern1 = r"GroupId: (.*)"
                    id = re.compile(pattern1).findall(res)[0].strip()
                    result["id"] = id
                    return result

                elif typeName == "SUBNET":
                    cmd = f"aws ec2 describe-subnets --filters Name=tag-value,Values={resName}"
                    res = self.raw_cli_res(cmd, show=show)
                    pattern1 = r"SubnetId: (.*)"
                    id = re.compile(pattern1).findall(res)[0].strip()
                    result["id"] = id
                    return result
                elif typeName == "TARGET_GROUP":
                    cmd = f"aws elbv2 describe-target-groups --names {resName}"
                    res = self.raw_cli_res(cmd, show=show)
                    pattern1 = r"TargetGroupArn: (.*)"
                    id = re.compile(pattern1).findall(res)[0].strip()
                    result["id"] = id
                    return result

            except IndexError:
                print_color(f"[Warning][aws][blind] not exist:{resName}", "yellow")
                return None

            res = f"[Warning][aws][blind]: unsupproted type:{typeName}"
            print_color(res, "yellow")
            return result

if __name__ == "__main__":

    if len(sys.argv) > 1:
        config_file = sys.argv[1]
        record = config_file.replace(".config", ".log")
    else:
        config_file = "aws_tb_pytest_west_1_ASA_dist72.config"
        record = True

    setting = {}
    # cfg = {"default": {"region": "shanghai", "output": "json"}}
    # cda = {"default": {"access-id": "1234", "secret-id": "3456"}}
    home_dir = os.getenv("HOME")
    try:
        with open(f"{home_dir}/.aws/config_auto", "r") as f:
            cfg = f.read()
        with open(f"{home_dir}/.aws/credentials_auto", "r") as f:
            cda = f.read()

        setting["config"] = cfg
        setting["credentials"] = cda
    except:
        pass

    obj = aws(setting, record=record, debug=True)
    atexit.register(obj.close)

    import signal
    def signal_handler(signal, frame):
        print('Someone pressed Ctrl+C!')
        if obj:
            obj.close(exec=True)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    res = obj.load_deployment(config_file)
    obj.start_deployment()

    print_color("~~~~~~~~~~~~~~~ Ready to Rock ~~~~~~~~~~~~~~", "pink")
    # time.sleep(1200)
    obj.close()
