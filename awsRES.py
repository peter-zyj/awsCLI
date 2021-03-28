import os, sys
import re, time, datetime
import shutil, atexit
import subprocess
import yaml

from awsAPI import aws


class resource(object):
    def __init__(self):
        self.creation_dependency = None
        self.termination_dependency = None
        self.keepAlive = False
        self.creation = None
        self.termination = None
        self.ID = None

    def get_creation_dependency(self):
        if self.creation_dependency:
            return set(self.creation_dependency)
        else:
            return set()

    def get_termination_dependency(self):
        if self.termination_dependency:
            return set(self.termination_dependency)
        else:
            return set()

    def get_creation(self):
        return self.creation

    def get_termination(self):
        return self.termination

    def get_id(self):
        if self.__class__.__name__ == "VPCE_SERVICE":
            return self.svcName
        else:
            return self.ID

    def load_deployment(self, fileName):
        print("No definition of load_deployment in object: ", self.__class__.__name__)

    def exec_creation(self):
        print("No definition of creation in object: ", self.__class__.__name__)

    def exec_termination(self):
        print("No definition of termination in object: ", self.__class__.__name__)


class INTERNET_GATEWAY(resource):
    def __init__(self, tagName, content):
        super().__init__()
        self.name = tagName
        self.raw_yaml = content
        self.creation = "aws ec2 create-internet-gateway"
        self.termination = "aws ec2 delete-internet-gateway"
        self.reName = "aws ec2 create-tags"
        self.ID = None
        self._cmd_composition()

    def _cmd_composition(self):
        for key, value in self.raw_yaml.items():
            if key != "action":
                if value and value != "None":
                    self.creation += " --" + key + " " + str(value)
                else:
                    self.creation += " --" + key
            else:
                self._action_handler(value)

        self.termination += " --internet-gateway-id" + " " + "self.ID"
        if self.name:
            self.reName += " --tag" + " " + f"Key=Name,Value={self.name}" + " " + "--resources" + " " + "self.ID"

    def _action_handler(self, action_yaml):
        for key, value in action_yaml.items():
            if key == "cleanUP":
                self.keepAlive = False if str(value).lower() == "true" else True

    def exec_creation(self, cli_handler):
        res = cli_handler.raw_cli_res(self.creation)
        self.ID = re.compile(r'InternetGatewayId: (.*)').findall(res)[0].strip()
        if self.name:
            self.reName = self.reName.replace("self.ID", str(self.ID))
            cli_handler.raw_cli_res(self.reName)

    def exec_termination(self, cli_handler):
        if not self.keepAlive:
            self.termination = self.termination.replace("self.ID", str(self.ID))
            cli_handler.raw_cli_res(self.termination)


class VPC(resource):
    def __init__(self, tagName, content):
        super().__init__()
        self.name = tagName
        self.raw_yaml = content
        self.creation = "aws ec2 create-vpc"
        self.termination = "aws ec2 delete-vpc"
        self.reName = "aws ec2 create-tags"
        self.attach = "aws ec2 attach-internet-gateway"
        self.detach = "aws ec2 detach-internet-gateway"
        self.ID = None
        self._cmd_composition()

    def _cmd_composition(self):
        for key, value in self.raw_yaml.items():
            if key != "action":
                if value and value != "None":
                    self.creation += " --" + key + " " + str(value)
                else:
                    self.creation += " --" + key
            else:
                self._action_handler(value)

        self.attach += " --vpc-id" + " " + "self.ID" + " " + "--internet-gateway-id" + " " + "{IGW_ID}"
        self.detach += " --vpc-id" + " " + "self.ID" + " " + "--internet-gateway-id" + " " + "{IGW_ID}"

        self.termination += " --vpc-id" + " " + "self.ID"
        if self.name:
            self.reName += " --tag" + " " + f"Key=Name,Value={self.name}" + " " + "--resources" + " " + "self.ID"

    def _action_handler(self, action_yaml):
        for key, value in action_yaml.items():
            if key == "bind_to":
                if type(value) == str:
                    self.creation_dependency = [value]
                else:
                    self.creation_dependency = value
            elif key == "cleanUP":
                self.keepAlive = False if str(value).lower() == "true" else True

    def exec_creation(self, cli_handler):
        res = cli_handler.raw_cli_res(self.creation)
        self.ID = re.compile(r'VpcId: (.*)').findall(res)[0].strip()
        if self.name:
            self.reName = self.reName.replace("self.ID", str(self.ID))
            cli_handler.raw_cli_res(self.reName)

        if self.attach and self.creation_dependency:
            for igw in self.creation_dependency:
                res_obj = cli_handler.res_deployment[igw]
                if type(res_obj).__name__ == "INTERNET_GATEWAY":
                    self.attach = re.sub(r"self.ID", self.ID, self.attach)
                    igw_id = cli_handler.find_id(igw)
                    self.attach = re.sub(r"\{.*?\}", igw_id, self.attach)
        cli_handler.raw_cli_res(self.attach)

    def exec_termination(self, cli_handler):
        if not self.keepAlive:

            if self.detach and self.creation_dependency:
                for igw in self.creation_dependency:
                    res_obj = cli_handler.res_deployment[igw]
                    if type(res_obj).__name__ == "INTERNET_GATEWAY":
                        self.detach = re.sub(r"self.ID", self.ID, self.detach)
                        igw_id = cli_handler.find_id(igw)
                        self.detach = re.sub(r"\{.*?\}", igw_id, self.detach)
            cli_handler.raw_cli_res(self.detach)

            self.termination = self.termination.replace("self.ID", str(self.ID))
            cli_handler.raw_cli_res(self.termination)


class SECURITY_GROUP(resource):
    def __init__(self, tagName, content):
        super().__init__()
        self.name = tagName
        self.raw_yaml = content
        self.creation = f"aws ec2 create-security-group --group-name {self.name}"
        self.termination = "aws ec2 delete-security-group"
        self.reName = "aws ec2 create-tags"
        self.rules = []
        self.ID = None
        self._cmd_composition()

    def _cmd_composition(self):
        for key, value in self.raw_yaml.items():
            if key != "action":
                if value and value != "None":
                    value = '"' + value + '"' if " " in value else value
                    self.creation += " --" + key + " " + str(value)
                else:
                    self.creation += " --" + key
            else:
                self._action_handler(value)

        self.termination += " --group-id" + " " + "self.ID"
        if self.name:
            self.reName += " --tag" + " " + f"Key=Name,Value={self.name}" + " " + "--resources" + " " + "self.ID"

    def _action_handler(self, action_yaml):
        for key, value in action_yaml.items():
            if key == "bind_to":
                if type(value) == str:
                    self.creation_dependency = [value]
                else:
                    self.creation_dependency = value
            elif key == "authorize-security-group-ingress":
                for rule in value:
                    cmd = "aws ec2 authorize-security-group-ingress --group-id self.ID"
                    for key2, value2 in rule.items():
                        cmd += " --" + key2 + " " + str(value2)
                    self.rules.append(cmd)
            elif key == "cleanUP":
                self.keepAlive = False if str(value).lower() == "true" else True

    def exec_creation(self, cli_handler):
        if self.creation_dependency:
            for vpc in self.creation_dependency:
                res_obj = cli_handler.res_deployment[vpc]
                if type(res_obj).__name__ == "VPC":
                    vpc_id = cli_handler.find_id(vpc)
                    str_vpcID = f"--vpc-id {vpc_id}"
                    self.creation = re.sub(r"--vpc-id .*?(?=( --|$))", str_vpcID, self.creation)

        res = cli_handler.raw_cli_res(self.creation)
        self.ID = re.compile(r'GroupId: (.*)').findall(res)[0].strip()
        if self.name:
            self.reName = self.reName.replace("self.ID", str(self.ID))
            cli_handler.raw_cli_res(self.reName)

        for rule in self.rules:
            rule = rule.replace("self.ID", str(self.ID))
            cli_handler.raw_cli_res(rule)

    def exec_termination(self, cli_handler):
        if not self.keepAlive:
            self.termination = self.termination.replace("self.ID", str(self.ID))
            cli_handler.raw_cli_res(self.termination)


class SUBNET(resource):
    def __init__(self, tagName, content):
        super().__init__()
        self.name = tagName
        self.raw_yaml = content
        self.creation = "aws ec2 create-subnet"
        self.termination = "aws ec2 delete-subnet"
        self.reName = "aws ec2 create-tags"
        self.ID = None
        self._cmd_composition()

    def _cmd_composition(self):
        for key, value in self.raw_yaml.items():
            if key != "action":
                if value and value != "None":
                    self.creation += " --" + key + " " + str(value)
                else:
                    self.creation += " --" + key
            else:
                self._action_handler(value)

        self.termination += " --subnet-id" + " " + "self.ID"
        if self.name:
            self.reName += " --tag" + " " + f"Key=Name,Value={self.name}" + " " + "--resources" + " " + "self.ID"

    def _action_handler(self, action_yaml):
        for key, value in action_yaml.items():
            if key == "bind_to":
                if type(value) == str:
                    self.creation_dependency = [value]
                else:
                    self.creation_dependency = value
            elif key == "cleanUP":
                self.keepAlive = False if str(value).lower() == "true" else True

    def exec_creation(self, cli_handler):
        if self.creation_dependency:
            for vpc in self.creation_dependency:
                res_obj = cli_handler.res_deployment[vpc]
                if type(res_obj).__name__ == "VPC":
                    vpc_id = cli_handler.find_id(vpc)
                    str_vpcID = f"--vpc-id {vpc_id}"
                    self.creation = re.sub(r"--vpc-id .*?(?=( --|$))", str_vpcID, self.creation)
        res = cli_handler.raw_cli_res(self.creation)
        self.ID = re.compile(r'SubnetId: (.*)').findall(res)[0].strip()
        if self.name:
            self.reName = self.reName.replace("self.ID", str(self.ID))
            cli_handler.raw_cli_res(self.reName)

    def exec_termination(self, cli_handler):
        if not self.keepAlive:
            self.termination = self.termination.replace("self.ID", str(self.ID))

            while True:
                res = cli_handler.raw_cli_res(self.termination)
                if "has dependencies and cannot be deleted" in res:
                    time.sleep(5)
                else:
                    break


class GATEWAY_LOAD_BALANCE(resource):
    def __init__(self, tagName, content):
        super().__init__()
        self.name = tagName
        self.raw_yaml = content
        self.creation = f"aws elbv2 create-load-balancer --name {self.name}"
        self.termination = "aws elbv2 delete-load-balancer"
        self.ID = None
        self._cmd_composition()

    def _cmd_composition(self):
        for key, value in self.raw_yaml.items():
            if key != "action":
                if value and value != "None":
                    self.creation += " --" + key + " " + str(value)
                else:
                    self.creation += " --" + key
            else:
                self._action_handler(value)

        self.termination += " --load-balancer-arn" + " " + "self.ID"

    def _action_handler(self, action_yaml):
        for key, value in action_yaml.items():
            if key == "bind_to":
                if type(value) == str:
                    self.creation_dependency = [value]
                else:
                    self.creation_dependency = value
            elif key == "cleanUP":
                self.keepAlive = False if str(value).lower() == "true" else True

    def exec_creation(self, cli_handler):
        if self.creation_dependency:
            str_subID = "--subnets"
            for sub in self.creation_dependency:
                res_obj = cli_handler.res_deployment[sub]
                if type(res_obj).__name__ == "SUBNET":
                    sub_id = cli_handler.find_id(sub)
                    str_subID += " " + sub_id
            if str_subID != "--subnets":
                self.creation = re.sub(r"--subnets .*?(?=( --|$))", str_subID, self.creation)

        res = cli_handler.raw_cli_res(self.creation)
        self.ID = re.compile(r'LoadBalancerArn: (.*)').findall(res)[0].strip()

    def exec_termination(self, cli_handler):
        if not self.keepAlive:
            self.termination = self.termination.replace("self.ID", str(self.ID))
            cli_handler.raw_cli_res(self.termination)


class TARGET_GROUP(resource):
    def __init__(self, tagName, content):
        super().__init__()
        self.name = tagName
        self.raw_yaml = content
        self.creation = f"aws elbv2 create-target-group --name {self.name}"
        self.termination = "aws elbv2 delete-target-group"
        self.ID = None
        self._cmd_composition()

    def _cmd_composition(self):
        for key, value in self.raw_yaml.items():
            if key != "action":
                if value and value != "None":
                    self.creation += " --" + key + " " + str(value)
                else:
                    self.creation += " --" + key
            else:
                self._action_handler(value)

        self.termination += " --target-group-arn" + " " + "self.ID"

    def _action_handler(self, action_yaml):
        for key, value in action_yaml.items():
            if key == "bind_to":
                if type(value) == str:
                    self.creation_dependency = [value]
                else:
                    self.creation_dependency = value
            elif key == "cleanUP":
                self.keepAlive = False if str(value).lower() == "true" else True

    def exec_creation(self, cli_handler):
        if self.creation_dependency:
            for vpc in self.creation_dependency:
                res_obj = cli_handler.res_deployment[vpc]
                if type(res_obj).__name__ == "VPC":
                    vpc_id = cli_handler.find_id(vpc)
                    str_vpcID = f"--vpc-id {vpc_id}"
                    self.creation = re.sub(r"--vpc-id .*?(?=( --|$))", str_vpcID, self.creation)

        res = cli_handler.raw_cli_res(self.creation)
        self.ID = re.compile(r'TargetGroupArn: (.*)').findall(res)[0].strip()

    def exec_termination(self, cli_handler):
        if not self.keepAlive:
            self.termination = self.termination.replace("self.ID", str(self.ID))
            cli_handler.raw_cli_res(self.termination)


class LISTENER(resource):
    def __init__(self, tagName, content):
        super().__init__()
        self.name = tagName
        self.raw_yaml = content
        self.creation = "aws elbv2 create-listener"
        self.termination = "aws elbv2 delete-listener"
        self.ID = None
        self._cmd_composition()

    def _cmd_composition(self):
        for key, value in self.raw_yaml.items():
            if key != "action":
                if value and value != "None":
                    self.creation += " --" + key + " " + str(value)
                else:
                    self.creation += " --" + key
            else:
                self._action_handler(value)

        self.termination += " --listener-arn" + " " + "self.ID"

    def _action_handler(self, action_yaml):
        for key, value in action_yaml.items():
            if key == "bind_to":
                if type(value) == str:
                    self.creation_dependency = [value]
                else:
                    self.creation_dependency = value
            elif key == "cleanUP":
                self.keepAlive = False if str(value).lower() == "true" else True

    def exec_creation(self, cli_handler):
        if self.creation_dependency:
            for res in self.creation_dependency:
                res_obj = cli_handler.res_deployment[res]
                if type(res_obj).__name__ == "TARGET_GROUP":
                    tg_id = cli_handler.find_id(res)
                    str_tgID = f"TargetGroupArn={tg_id}"
                    self.creation = re.sub(r"TargetGroupArn=.*?(?=(,| --|$))", str_tgID, self.creation)
                elif type(res_obj).__name__ == "GATEWAY_LOAD_BALANCE":
                    gwlb_id = cli_handler.find_id(res)
                    str_gwlbID = f"--load-balancer-arn {gwlb_id}"
                    self.creation = re.sub(r"--load-balancer-arn .*?(?=( --|$))", str_gwlbID, self.creation)
        res = cli_handler.raw_cli_res(self.creation)
        self.ID = re.compile(r'ListenerArn: (.*)').findall(res)[0].strip()

    def exec_termination(self, cli_handler):
        if not self.keepAlive:
            self.termination = self.termination.replace("self.ID", str(self.ID))
            cli_handler.raw_cli_res(self.termination)


class VPCE_SERVICE(resource):
    def __init__(self, tagName, content):
        super().__init__()
        self.name = tagName
        self.raw_yaml = content
        self.creation = "aws ec2 create-vpc-endpoint-service-configuration"
        self.termination = "aws ec2 delete-vpc-endpoint-service-configurations"
        self.reName = "aws ec2 create-tags"
        self.ID = None
        self.svcName = None
        self._cmd_composition()

    def _cmd_composition(self):
        for key, value in self.raw_yaml.items():
            if key != "action":
                if value and value != "None":
                    self.creation += " --" + key + " " + str(value)
                else:
                    self.creation += " --" + key
            else:
                self._action_handler(value)

        self.termination += " --service-ids" + " " + "self.ID"
        if self.name:
            self.reName += " --tag" + " " + f"Key=Name,Value={self.name}" + " " + "--resources" + " " + "self.ID"

    def _action_handler(self, action_yaml):
        for key, value in action_yaml.items():
            if key == "bind_to":
                if type(value) == str:
                    self.creation_dependency = [value]
                else:
                    self.creation_dependency = value
            elif key == "cleanUP":
                self.keepAlive = False if str(value).lower() == "true" else True

    def exec_creation(self, cli_handler):
        if self.creation_dependency:
            for res in self.creation_dependency:
                res_obj = cli_handler.res_deployment[res]
                if type(res_obj).__name__ == "GATEWAY_LOAD_BALANCE":
                    gwlb_id = cli_handler.find_id(res)
                    str_gwlbID = f"--gateway-load-balancer-arns {gwlb_id}"
                    self.creation = re.sub(r"--gateway-load-balancer-arns .*?(?=( --|$))", str_gwlbID, self.creation)

        while True:
            res = cli_handler.raw_cli_res(self.creation)
            if "must be in the active state" in res:
                time.sleep(5)
            else:
                break

        self.ID = re.compile(r'ServiceId: (.*)').findall(res)[0].strip()
        self.svcName = re.compile(r'ServiceName: (.*)').findall(res)[0].strip()

        if self.name:
            self.reName = self.reName.replace("self.ID", str(self.ID))
            cli_handler.raw_cli_res(self.reName)

    def exec_termination(self, cli_handler):
        if not self.keepAlive:
            self.termination = self.termination.replace("self.ID", str(self.ID))
            cli_handler.raw_cli_res(self.termination)


class GATEWAY_LOAD_BALANCE_ENDPOINT(resource):
    def __init__(self, tagName, content):
        super().__init__()
        self.name = tagName
        self.raw_yaml = content
        self.creation = "aws ec2 create-vpc-endpoint"
        self.termination = "aws ec2 delete-vpc-endpoints"
        self.reName = "aws ec2 create-tags"
        self.ID = None
        self._cmd_composition()

    def _cmd_composition(self):
        for key, value in self.raw_yaml.items():
            if key != "action":
                if value and value != "None":
                    self.creation += " --" + key + " " + str(value)
                else:
                    self.creation += " --" + key
            else:
                self._action_handler(value)

        self.termination += " --vpc-endpoint-ids" + " " + "self.ID"

        if self.name:
            self.reName += " --tag" + " " + f"Key=Name,Value={self.name}" + " " + "--resources" + " " + "self.ID"

    def _action_handler(self, action_yaml):
        for key, value in action_yaml.items():
            if key == "bind_to":
                if type(value) == str:
                    self.creation_dependency = [value]
                else:
                    self.creation_dependency = value
            elif key == "cleanUP":
                self.keepAlive = False if str(value).lower() == "true" else True

    def exec_creation(self, cli_handler):
        if self.creation_dependency:
            for res in self.creation_dependency:
                str_subID = "--subnet-ids"
                res_obj = cli_handler.res_deployment[res]
                if type(res_obj).__name__ == "VPC":
                    vpc_id = cli_handler.find_id(res)
                    str_vpcID = f"--vpc-id {vpc_id}"
                    self.creation = re.sub(r"--vpc-id .*?(?=( --|$))", str_vpcID, self.creation)
                elif type(res_obj).__name__ == "VPCE_SERVICE":
                    vpce_id = cli_handler.find_id(res)
                    str_vpceID = f"--service-name {vpce_id}"
                    self.creation = re.sub(r"--service-name .*?(?=( --|$))", str_vpceID, self.creation)
                elif type(res_obj).__name__ == "SUBNET":
                    sub_id = cli_handler.find_id(res)
                    str_subID += f" {sub_id}"

            if str_subID != "--subnet-ids":
                self.creation = re.sub(r"--subnet-ids .*?(?=( --|$))", str_subID, self.creation)

        res = cli_handler.raw_cli_res(self.creation)
        self.ID = re.compile(r'VpcEndpointId: (.*)').findall(res)[0].strip()

        if self.name:
            self.reName = self.reName.replace("self.ID", str(self.ID))
            cli_handler.raw_cli_res(self.reName)

    def exec_termination(self, cli_handler):
        if not self.keepAlive:
            self.termination = self.termination.replace("self.ID", str(self.ID))
            cli_handler.raw_cli_res(self.termination)


class ROUTE(resource):
    def __init__(self, tagName, content):
        super().__init__()
        self.name = tagName
        self.raw_yaml = content
        self.creation = "aws ec2 create-route"
        self.termination = "aws ec2 delete-route"
        self.rtb_id = None
        self.ID = None
        self._cmd_composition()

    def _cmd_composition(self):
        for key, value in self.raw_yaml.items():
            if key != "action":
                if value:
                    self.creation += " --" + key + " " +str(value)
                else:
                    self.creation += " --" + key
            else:
                self._action_handler(value)

        self.termination += " --route-table-id" + " " + "self.rtb_id" + " --destination-cidr-block" + \
                            " " + self.raw_yaml["destination-cidr-block"]

    def _action_handler(self, action_yaml):
        for key, value in action_yaml.items():
            if key == "bind_to":
                if type(value) == str:
                    self.creation_dependency = [value]
                else:
                    self.creation_dependency = value
            elif key == "cleanUP":
                self.keepAlive = False if str(value).lower() == "true" else True

    def exec_creation(self, cli_handler):
        # consider {VPC} case
        if self.creation_dependency:
            for res in self.creation_dependency:
                res_obj = cli_handler.res_deployment[res]
                if type(res_obj).__name__ == "VPC":
                    try:
                        resName = re.compile(r"--route-table-id @(.*?)@").findall(self.creation)[0]
                        if resName == res:
                            vpc_id = cli_handler.find_id(resName)
                            self.rtb_id = self._map_vps_route_id(cli_handler, vpc_id)
                            rtb_id = "--route-table-id " + self.rtb_id
                            self.creation = re.sub(r"--route-table-id @.*?@", rtb_id, self.creation)
                    except IndexError:
                        print("[Warning][ROUTE][exec_creation]: no VPC in command line, but it exist in dependency")
                elif type(res_obj).__name__ == "INTERNET_GATEWAY":
                    igw_id = cli_handler.find_id(res)
                    str_igwID = f"--gateway-id {igw_id}"
                    self.creation = re.sub(r"--gateway-id .*?(?=( --|$))", str_igwID, self.creation)
                elif type(res_obj).__name__ == "ROUTE_TABLE":
                    rt_id = cli_handler.find_id(res)
                    str_rtID = f"--route-table-id {rt_id}"
                    self.creation = re.sub(r"--route-table-id .*?(?=( --|$))", str_rtID, self.creation)
                elif type(res_obj).__name__ == "GATEWAY_LOAD_BALANCE_ENDPOINT":
                    gwlbe_id = cli_handler.find_id(res)
                    str_gwlbeID = f"--vpc-endpoint-id {gwlbe_id}"
                    self.creation = re.sub(r"--vpc-endpoint-id .*?(?=( --|$))", str_gwlbeID, self.creation)
        res = cli_handler.raw_cli_res(self.creation)


    def exec_termination(self, cli_handler):
        if not self.keepAlive:
            self.termination = self.termination.replace("self.rtb_id", str(self.rtb_id))
            cli_handler.raw_cli_res(self.termination)

    def _map_vps_route_id(self, cli_handler, vpc_id):
        try:
            res = cli_handler.raw_cli_res("aws ec2 describe-route-tables")
            pattern = f'(?s)RouteTableId(?:[^R]|R(?!outeTableId))*?VpcId: {vpc_id}'
            filter = re.compile(pattern).findall(res)[0]
            return re.compile(r"RouteTableId: (.*)").findall(filter)[0]
        except Exception as e:
            print("[Warning][ROUTE][_map_vps_route_id]:", e)


class ROUTE_TABLE(resource):
    def __init__(self, tagName, content):
        super().__init__()
        self.name = tagName
        self.raw_yaml = content
        self.creation = "aws ec2 create-route-table"
        self.termination = "aws ec2 delete-route-table"
        self.sub_route = []
        self.reName = None
        self.ID = None
        self._cmd_composition()

    def _cmd_composition(self):
        for key, value in self.raw_yaml.items():
            if key != "action":
                if value:
                    self.creation += " --" + key + " " + str(value)
                else:
                    self.creation += " --" + key
            else:
                self._action_handler(value)

        self.termination += " --route-table-id" + " " + "self.ID"
        if self.name:
            self.reName += " --tag" + " " + f"Key=Name,Value={self.name}" + " " + "--resources" + " " + "self.ID"

    def _action_handler(self, action_yaml):
        for key, value in action_yaml.items():
            if key == "bind_to":
                if type(value) == str:
                    self.creation_dependency = [value]
                else:
                    self.creation_dependency = value
            elif key == "sub_route":
                for rt in value:
                    sub_route = ROUTE("sub-route", rt)
                    if sub_route.creation_dependency:
                        self.creation_dependency += sub_route.creation_dependency
                    self.sub_route.append(sub_route)
            elif key == "cleanUP":
                self.keepAlive = False if str(value).lower() == "true" else True

    def exec_creation(self, cli_handler):
        # create rt_table
        # add route under rt table
        if self.creation_dependency:
            for vpc in self.creation_dependency:
                res_obj = cli_handler.res_deployment[vpc]
                if type(res_obj).__name__ == "VPC":
                    vpc_id = cli_handler.find_id(vpc)
                    str_vpcID = f"--vpc-id {vpc_id}"
                    self.creation = re.sub(r"--vpc-id .*?(?=( --|$))", str_vpcID, self.creation)

        res = cli_handler.raw_cli_res(self.creation)
        self.ID = re.compile(r'RouteTableId: (.*)').findall(res)[0].strip()

        if self.name:
            self.reName = self.reName.replace("self.ID", str(self.ID))
            cli_handler.raw_cli_res(self.reName)

        for rt in self.sub_route:
            rt.exec_creation(cli_handler)

    def exec_termination(self, cli_handler):
        if not self.keepAlive:
            self.termination = self.termination.replace("self.ID", str(self.ID))
            cli_handler.raw_cli_res(self.termination)


class ROUTE_ASSOCIATE(resource):
    def __init__(self, tagName, content):
        super().__init__()
        self.name = tagName
        self.raw_yaml = content
        self.creation = "aws ec2 associate-route-table"
        self.termination = "aws ec2 disassociate-route-table"
        self.ID = None
        self._cmd_composition()

    def _cmd_composition(self):
        for key, value in self.raw_yaml.items():
            if key != "action":
                if value:
                    self.creation += " --" + key + str(value)
                else:
                    self.creation += " --" + key
            else:
                self._action_handler(value)

        self.termination += "--association-id" + " " + "self.ID"

    def _action_handler(self, action_yaml):
        for key, value in action_yaml.items():
            if key == "bind_to":
                if type(value) == str:
                    self.creation_dependency = [value]
                else:
                    self.creation_dependency = value
            elif key == "cleanUP":
                self.keepAlive = False if str(value).lower() == "true" else True

    def exec_creation(self, cli_handler):
        pass

    def exec_termination(self, cli_handler):
        pass


class REGISTER(resource):
    def __init__(self, tagName, content):
        super().__init__()
        self.name = tagName
        self.raw_yaml = content
        self.creation = "aws elbv2 register-targets"
        self.termination = "aws elbv2 deregister-targets"
        self.ID = None
        self._cmd_composition()

    def _cmd_composition(self):
        for key, value in self.raw_yaml.items():
            if key != "action":
                if value:
                    self.creation += " --" + key + str(value)
                else:
                    self.creation += " --" + key
            else:
                self._action_handler(value)

        self.termination = self.creation.replace("register-targets", "deregister-targets")

    def _action_handler(self, action_yaml):
        for key, value in action_yaml.items():
            if key == "bind_to":
                if type(value) == str:
                    self.creation_dependency = [value]
                else:
                    self.creation_dependency = value
            elif key == "cleanUP":
                self.keepAlive = False if str(value).lower() == "true" else True

    def exec_creation(self, cli_handler):
        pass

    def exec_termination(self, cli_handler):
        pass


class EC2INSTANCE(resource):
    def __init__(self, tagName, content):
        super().__init__()
        self.name = tagName
        self.raw_yaml = content
        self.creation = "aws ec2 run-instances"
        self.termination = "aws ec2 terminate-instance"
        self.reName = "aws ec2 create-tags"
        self.ID = None
        self.cmd = None
        self._cmd_composition()

    def _cmd_composition(self):
        for key, value in self.raw_yaml.items():
            if key != "action":
                if value:
                    self.creation += " --" + key + str(value)
                else:
                    self.creation += " --" + key
            else:
                self._action_handler(value)

        self.termination += "--instance-ids" + " " + "self.ID"
        if self.name:
            self.reName += "--tag" + " " + f"Key=Name,Value={self.name}" + " " + "--resources" + " " + "self.ID"

    def _action_handler(self, action_yaml):
        for key, value in action_yaml.items():
            if key == "bind_to":
                if type(value) == str:
                    self.creation_dependency = [value]
                else:
                    self.creation_dependency = value
            elif key == "cmd":
                self.cmd = value
            elif key == "cleanUP":
                self.keepAlive = False if str(value).lower() == "true" else True

    def exec_creation(self, cli_handler):
        # consider the scenario of count >= 2
        pass

    def exec_termination(self, cli_handler):
        pass


if __name__ == "__main__":
    res = EC2INSTANCE()
    res.exec_creation()