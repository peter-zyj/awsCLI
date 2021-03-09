import os, sys
import re, time
import shutil, atexit
import subprocess
import yaml


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
    args[0] = '{0}{1}'.format(color, str(args[0]))
    args[-1] = '{1}{0}'.format(ENDCOLOR, str(args[-1]))
    message = "".join(args)

    format_str = style.format(message)
    if newLine:
        print(format_str)
    else:
        print(format_str, end="")


class aws(object):
    def __init__(self, configuration=None):
        self.config = False
        self.credentials = False
        self.home = os.getenv("HOME")
        self.prompt = "AWS-Auto#"
        self.resource = {}
        self.tobeCleanUP = {}
        self.cleanUp = False

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

    def close(self):
        if not self.cleanUp:
            self._config_restore()

    def __exit__(self):
        self.close()

    def __del__(self):
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

        self._res_term()

        if self.config:
            path_config_bk = self.home + "/.aws/config" + "_auto_bk"
            path_config_org = self.home + "/.aws/config"
            if not os.path.exists(path_config_bk):
                print("[ERROR]: No ~/.aws/config_auto_bk found!")
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
            else:
                shutil.move(path_credentials_bk, path_credentials_org)
                # os.popen(f"mv {path_credentials_bk} {path_credentials_org}")python exit-prog kill popen ahead
        else:
            os.remove(self.home + "/.aws/credentials")

        self.cleanUp = True
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

    def raw_cli(self, commandline, show=True):

        category, sub_class = self._res_filter(commandline)

        if show:
            print_color(self.prompt, "black", newLine=False)
            print_color(commandline, "blue")

        res1 = "AWS-Auto#" + commandline + "\n"
        # res2 = os.popen(commandline).read()  not working in class destructor
        p = subprocess.Popen(commandline, shell=True, stdout=subprocess.PIPE)
        out, err = p.communicate()
        res2 = out.decode()

        if not err and category:
            res_suite = self._res_deepHandle(category, res2)
            self.resource[category][sub_class] += res_suite

        if show:
            if not err:
                print_color(res2, "green")
            else:
                print_color(err, "red")
                print_color(res2, "red")

        return res1 + res2

    def _res_filter(self, commandline):
        category = None
        sub_class = None
        if "aws ec2 run-instances" in commandline:
            category = "EC2"
            sub_class = "INSTANCES"
            if "EC2" not in self.resource:
                self.resource[category] = {}
                self.tobeCleanUP[category] = []
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
                self.tobeCleanUP[category].append(temp)

            return yml["Instances"]

    def _res_term(self):
        print_color("Resource Clean Up", style="{0:#^50}")

        if "EC2" in self.tobeCleanUP:
            print_color(".....[CleanUP][EC2].......")
            for ins in self.tobeCleanUP["EC2"]:
                id = ins["InstanceId"]
                cmd = f"aws ec2 terminate-instances --instance-ids {id}"
                self.raw_cli(cmd)

        print_color("END", style="{0:#^50}")

    def list_resource(self, verbose=False):
        if verbose:
            print_color(yaml.dump(self.resource), "cyan")
        else:
            print_color(yaml.dump(self.tobeCleanUP), "magenta")


if __name__ == "__main__":
    setting = {}
    # cfg = {"default": {"region": "shanghai", "output": "json"}}
    # cda = {"default": {"access-id": "1234", "secret-id": "3456"}}
    with open("/Users/yijunzhu/.aws/config_auto", "r") as f:
        cfg = f.read()
    with open("/Users/yijunzhu/.aws/credentials_auto", "r") as f:
        cda = f.read()

    setting["config"] = cfg
    setting["credentials"] = cda

    obj = aws(setting)
    atexit.register(obj.close)

    res = obj.raw_cli("aws s3 ls")
    # res = obj.raw_cli("aws ec2 describe-instances")
    cmd = "aws ec2 run-instances --image-id ami-03d64741867e7bb94 --count 2 --instance-type t2.micro " \
          "--key-name testMonkey --security-group-ids sg-7e070b0f"
    res = obj.raw_cli(cmd)

    res = obj.raw_cli(cmd)
    obj.list_resource()
    obj.close()
    # print(res)
