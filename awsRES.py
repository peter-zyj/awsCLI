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
                if value:
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
                if value:
                    self.creation += " --" + key + " " + str(value)
                else:
                    self.creation += " --" + key
            else:
                self._action_handler(value)

        self.attach += " --vpc-id" + " " + "self.ID" + " " + "--internet-gateway-id" + " " +"{IGW_ID}"
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
                if value:
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
                    igw_id = cli_handler.find_id(vpc)
                    str_vpcID = f"--vpc-id {igw_id} "
                    self.creation = re.sub(r"--vpc-id .*? ", str_vpcID, self.creation)

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
                if value:
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
                    igw_id = cli_handler.find_id(vpc)
                    str_vpcID = f"--vpc-id {igw_id} "
                    self.creation = re.sub(r"--vpc-id .*? ", str_vpcID, self.creation)

        res = cli_handler.raw_cli_res(self.creation)
        self.ID = re.compile(r'SubnetId: (.*)').findall(res)[0].strip()
        if self.name:
            self.reName = self.reName.replace("self.ID", str(self.ID))
            cli_handler.raw_cli_res(self.reName)


    def exec_termination(self, cli_handler):
        if not self.keepAlive:
            self.termination = self.termination.replace("self.ID", str(self.ID))
            cli_handler.raw_cli_res(self.termination)


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
                if value:
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
            self.creation = re.sub(r"--subnets .*? ", str_subID, self.creation)

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
        self.creation = "aws elbv2 create-target-group"
        self.termination = "aws elbv2 delete-target-group"
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

        self.termination += "--target-group-arn" + " " + "self.ID"

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


class LISTENER(resource):
    def __init__(self, tagName, content):
        super().__init__()
        self.name = tagName
        self.raw_yaml = content
        self.creation = "aws ec2 create-listener"
        self.termination = "aws ec2 delete-listener"
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

        self.termination += "--listener-arn" + " " + "self.ID"

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


class VPCE_SERVICE(resource):
    def __init__(self, tagName, content):
        super().__init__()
        self.name = tagName
        self.raw_yaml = content
        self.creation = "aws ec2 create-vpc-endpoint-service-configuration"
        self.termination = "aws ec2 delete-vpc-endpoint-service-configurations"
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

        self.termination += "--service-ids" + " " + "self.ID"

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


class GATEWAY_LOAD_BALANCE_ENDPOINT(resource):
    def __init__(self, tagName, content):
        super().__init__()
        self.name = tagName
        self.raw_yaml = content
        self.creation = "aws ec2 create-vpc-endpoint"
        self.termination = "aws ec2 delete-vpc-endpoints"
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

        self.termination += "--vpc-endpoint-ids" + " " + "self.ID"

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
                    self.creation += " --" + key + str(value)
                else:
                    self.creation += " --" + key
            else:
                self._action_handler(value)

        self.termination += "--route-table-id" + " " + "self.rtb_id" + "--destination-cidr-block" + \
                            self.raw_yaml["destination-cidr-block"]

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
        if re.compile(r"\{(.*?)\}").findall(self.creation) != []:
            vpc = re.compile(r"\{(.*?)\}").findall(self.creation)[0]
            # pre_cmd = "aws ec2 describe-route-tables"
            vpc_id = cli_handler.find_id(vpc)
            try:
                rtb_id = self._map_vps_route_id(cli_handler, vpc_id)
                self.rtb_id = rtb_id
            except Exception as e:
                print("[ERROR][ROUTE][_map_vps_route_id]:", e)
                return
            self.creation = re.sub(r"\{.*?\}", rtb_id, self.creation)

        res = cli_handler.raw_cli_res(self.creation)
        pass

    def exec_termination(self, cli_handler):
        pass

    def _map_vps_route_id(self, cli_handler, vpc_id):
        res = cli_handler.raw_cli_res("aws ec2 describe-route-tables")
        pattern = f'(?s)RouteTableId(?:[^R]|R(?!outeTableId))*?VpcId: {vpc_id})'
        filter = re.compile(pattern).findall(res)[0]
        return re.compile(r"RouteTableId: (.*)").findall(filter)[0]


class ROUTE_TABLE(resource):
    def __init__(self, tagName, content):
        super().__init__()
        self.name = tagName
        self.raw_yaml = content
        self.creation = "aws ec2 create-route-table"
        self.termination = "aws ec2 delete-route-table"
        self.sub_route = []
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

        self.termination += "--route-table-id" + " " + "self.ID"

    def _action_handler(self, action_yaml):
        for key, value in action_yaml.items():
            if key == "bind_to":
                if type(value) == str:
                    self.creation_dependency = [value]
                else:
                    self.creation_dependency = value
            elif key == "sub_route":
                for rt in value:
                    sub_route = ROUTE("noRTName", rt)
                    self.sub_route.append(sub_route)
            elif key == "cleanUP":
                self.keepAlive = False if str(value).lower() == "true" else True

    def exec_creation(self, cli_handler):
        # create rt_table
        # add route under rt table
        pass

    def exec_termination(self, cli_handler):
        pass


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
