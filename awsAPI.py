import os, sys
import re, time, datetime
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


class aws(object):
    def __init__(self, configuration=None,debug=False):
        self.config = False
        self.credentials = False
        self.home = os.getenv("HOME")
        self.prompt = "AWS-Auto#"
        self.res_deployment = None
        self.res_mapping = {}
        self.resource = {}
        self.tobeCleanUp = {}
        self.resCleanUp = debug
        self.cfgCleanUp = False

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
        if not self.resCleanUp:
            self._res_term()
            self.resCleanUp = True

        if not self.cfgCleanUp:
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

            self.cfgCleanUp = True

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
        p = subprocess.Popen(commandline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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

        return res1 + res2 + err.decode()

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

    def load_deployment(self, fileName):
        try:
            with open(fileName, "r") as f:
                cont =f.read()
        except FileNotFoundError as e:
            print(f"[ERROR][load_deplyment]:{e}")
            return
        self.res_deployment = yaml.load(cont,Loader=yaml.FullLoader)



    def start_deployment(self):

        for instance in self.res_deployment:
            num = self.res_deployment[instance]["count"]

            if not num:
                continue

            istName, type = re.compile(r'(.*?)\((.*?)\)').findall(instance)[0]

            if type.lower() == "ec2":

                cmd1 = "aws ec2 run-instances "
                for key,value in self.res_deployment[instance].items():
                    if key == "action":
                        continue
                    cmd1 += "--" + key + " " + str(value) + " "

                res1 = self.raw_cli(cmd1)
                pattern = r'InstanceId:(.*)'
                result = re.compile(pattern).findall(res1)
                if len(result) != num:
                    print_color("[ERROR][start_deployment]: Unmatched instances number between expected and real world", "red")
                    return

                for idx in range(num):
                    if num > 1:
                        name = f"{istName}_{idx}"
                    else:
                        name = istName
                    cmd2 = f"aws ec2 create-tags --tag 'Key=Name,Value={name}' --resources {result[idx].strip()}"
                    res2 = self.raw_cli(cmd2)
                    self.res_mapping[name] = result[idx].strip()




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

    # res = obj.raw_cli(cmd)
    obj.list_resource()
    # obj.close()

'''
internet gateway:
aws ec2 create-internet-gateway
aws ec2 create-tags --tag 'Key=Name,Value=Yijun-test' --resources igw-0cef12cfaaa984acf

(VPC attach dependency)
aws ec2 delete-internet-gateway --internet-gateway-id igw-0cef12cfaaa984acf



ig creation
vpc bind IG
VPC'main route add internet route 0.0.0.0/0


--region us-east-2
vpc:
aws ec2 describe-vpcs
aws ec2 create-vpc --cidr-block 10.0.0.0/16
aws ec2 create-tags --tag 'Key=Name,Value=Yijun-1' --resources vpc-04d55cd47598533ce
aws ec2 delete-vpc --vpc-id vpc-04d55cd47598533ce

bind vpc to IG:
aws ec2 attach-internet-gateway --vpc-id vpc-09518b536ccd73a17 --internet-gateway-id igw-0cef12cfaaa984acf

security group:
aws ec2 create-security-group --group-name Yijun-sg --description "My security group" --vpc-id vpc-09518b536ccd73a17
aws ec2 authorize-security-group-ingress --group-id sg-044bb3e58ed8d8c87 --protocol tcp --port 22 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id sg-044bb3e58ed8d8c87 --protocol tcp --port 80 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id sg-044bb3e58ed8d8c87 --protocol icmp --port all --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id sg-044bb3e58ed8d8c87 --protocol udp --port 6081 --cidr 0.0.0.0/0
aws ec2 delete-security-group --group-id sg-044bb3e58ed8d8c87

zones: TBD
aws ec2 describe-availability-zones
aws ec2 create-subnet --vpc-id vpc-04d55cd47598533ce --cidr-block 10.0.1.0/24 --availability-zone-id use2-az1

subnet:
aws ec2 describe-subnets
aws ec2 create-subnet --vpc-id vpc-04d55cd47598533ce --cidr-block 10.0.1.0/24
aws ec2 create-tags --tag 'Key=Name,Value=Yijun-1-sub1' --resources subnet-0908841c5ec6fbc8b
aws ec2 delete-subnet --subnet-id subnet-0908841c5ec6fbc8b

gwlb:
aws elbv2 describe-load-balancers
aws elbv2 create-load-balancer --name Yijun-gwlb --type gateway --subnets subnet-0ca4dea497eab3968
aws elbv2 delete-load-balancer 
--load-balancer-arn arn:aws:elasticloadbalancing:us-east-2:439462095416:loadbalancer/gwy/Yijun-gwlb/0c5676485ec64efd

target group:
aws elbv2 create-target-group --name Yijun-tgt --protocol GENEVE --port 6081 --vpc-id vpc-09518b536ccd73a17
aws elbv2 delete-target-group --target-group-arn 
arn:aws:elasticloadbalancing:us-east-2:439462095416:targetgroup/Yijun-tgt/0013b056c4ab337bda

new ec2(subnet bind to VPC):
aws ec2 run-instances --image-id ami-03d64741867e7bb94 --count 1 --instance-type t2.micro --key-name testMonkey 
--subnet-id subnet-0ca4dea497eab3968 --security-group-ids sg-08bd09e25908f1acd --associate-public-ip-address

sudo yum install python3 -y
sudo python3 -m http.server 80

# option:when SG not specified in instance creation cli:
# aws ec2 describe-instance-attribute --instance-id i-036313d57f8d6accc --attribute groupSet
# aws ec2 authorize-security-group-ingress --group-id sg-7e070b0f --protocol tcp --port 22 --cidr 0.0.0.0/0



aws elbv2 register-targets --target-group-arn 
arn:aws:elasticloadbalancing:us-east-2:439462095416:targetgroup/Yijun-tgt/00f81e321e2277b79b 
--targets Id=i-008d61520584c55ba

aws elbv2 deregister-targets --target-group-arn 
arn:aws:elasticloadbalancing:us-east-2:439462095416:targetgroup/Yijun-tgt/00f81e321e2277b79b 
--targets Id=i-008d61520584c55ba

aws elbv2 describe-target-health 
--target-group-arn arn:aws:elasticloadbalancing:us-east-2:439462095416:targetgroup/Yijun-tgt/00f81e321e2277b79b

listener:
aws elbv2 create-listener 
--load-balancer-arn arn:aws:elasticloadbalancing:us-east-2:439462095416:loadbalancer/gwy/Yijun-gwlb/6a457831f9919c8f 
--default-actions 
Type=forward,
TargetGroupArn=arn:aws:elasticloadbalancing:us-east-2:439462095416:targetgroup/Yijun-tgt/00f81e321e2277b79b

aws elbv2 delete-listener
--listener-arn arn:aws:elasticloadbalancing:us-east-2:439462095416:listener/gwy/Yijun-gwlb/6a457831f9919c8f/3e45c5f8d47d0d7c


gwlbe:
aws ec2 create-vpc-endpoint-service-configuration --gateway-load-balancer-arns 
arn:aws:elasticloadbalancing:us-east-2:439462095416:loadbalancer/gwy/Yijun-gwlb/6a457831f9919c8f --no-acceptance-required

aws ec2 delete-vpc-endpoint-service-configurations --service-ids vpce-svc-04715feea9278ffb4

aws ec2 create-vpc-endpoint --vpc-endpoint-type GatewayLoadBalancer 
--service-name com.amazonaws.vpce.us-east-2.vpce-svc-0840335b70927cf16 
--vpc-id vpc-09518b536ccd73a17 --subnet-ids subnet-0ca4dea497eab3968


| => aws ec2 create-vpc-endpoint --vpc-endpoint-type GatewayLoadBalancer --service-name com.amazonaws.vpce.us-east-2.vpce-svc-0840335b70927cf16 --vpc-id vpc-09518b536ccd73a17 --subnet-ids subnet-0ca4dea497eab3968
VpcEndpoint:
  CreationTimestamp: '2021-03-26T19:08:25.946000+00:00'
  NetworkInterfaceIds:
  - eni-021bbe0cb2d90621d
  OwnerId: '439462095416'
  RequesterManaged: false
  ServiceName: com.amazonaws.vpce.us-east-2.vpce-svc-0840335b70927cf16
  State: pending
  SubnetIds:
  - subnet-0ca4dea497eab3968
  VpcEndpointId: vpce-00021cca5da094b47
  VpcEndpointType: GatewayLoadBalancer
  VpcId: vpc-09518b536ccd73a17



aws ec2 delete-vpc-endpoints --vpc-endpoint-ids vpce-09fcb69ef29c01e5b


route tables:
aws ec2 create-route-table --vpc-id vpc-a01106c2
aws ec2 delete-route-table --route-table-id rtb-22574640
aws ec2 associate-route-table --route-table-id rtb-22574640 --subnet-id subnet-9d4a7b6c

aws ec2 disassociate-route-table --association-id rtbassoc-781d0d1a
aws ec2 create-route --route-table-id rtb-22574640 --destination-cidr-block 0.0.0.0/0 --gateway-id igw-c0a643a9

routes:
aws ec2 create-route --route-table-id rtb-0d0cd971e645a6c53 --destination-cidr-block 0.0.0.0/0 --gateway-id igw-0c4bc11847f55f073
aws ec2 describe-route-tables
            | => aws ec2 describe-route-tables // input VPCID, output RouteTableId
            RouteTables:
            - Associations:
              - AssociationState:
                  State: associated
                Main: true
                RouteTableAssociationId: rtbassoc-09ed0852b71515d06
                RouteTableId: rtb-0d0cd971e645a6c53
              OwnerId: '439462095416'
              PropagatingVgws: []
              RouteTableId: rtb-0d0cd971e645a6c53
              Routes:
              - DestinationCidrBlock: 10.0.0.0/16
                GatewayId: local
                Origin: CreateRouteTable
                State: active
              - DestinationCidrBlock: 0.0.0.0/0
                GatewayId: igw-0c4bc11847f55f073
                Origin: CreateRoute
                State: active
              Tags: []
              VpcId: vpc-09518b536ccd73a17        


aws ec2 delete-route --route-table-id rtb-0d0cd971e645a6c53 --destination-cidr-block 0.0.0.0/0

data-net
sg:
aws ec2 authorize-security-group-ingress --group-id sg-0171ce9bff523588d --protocol all --port all --cidr 0.0.0.0/0
aws ec2 authorize-security-group-egress --group-id sg-0171ce9bff523588d --protocol all --port all --cidr 0.0.0.0/0

ni
aws ec2 create-network-interface --subnet-id subnet-059231d15fe253b55 --description "Yijun-data-if" --groups sg-0171ce9bff523588d
aws ec2 create-tags --tag 'Key=Name,Value=Yijun-data-if0' --resources eni-06f303ecf53737d98

aws ec2 attach-network-interface --network-interface-id eni-06f303ecf53737d98 --instance-id i-1234567890abcdef0 --device-index 1
aws ec2 detach-network-interface --attachment-id eni-attach-66c4350a

aws ec2 delete-network-interface --network-interface-id eni-06f303ecf53737d98


aws ec2 run-instances --image-id ami-03dda840f4c3d816e --instance-type c5.xlarge --key-name testMonkey --count 1 \
 --subnet-id Yijun-mgm-subnet --security-group-ids allow-all --user-data file://day0.txt

Elastic IP::

aws ec2 describe-addresses
Addresses:
- AllocationId: eipalloc-00220e5b6a8afbbe3
  AssociationId: eipassoc-02b5744d5a5a8cd53
  Domain: vpc
  InstanceId: i-0dbc383e77c57cc8e
  NetworkBorderGroup: us-east-2
  NetworkInterfaceId: eni-0e625e8e91057cd8e
  NetworkInterfaceOwnerId: '439462095416'
  PrivateIpAddress: 10.0.1.101
  PublicIp: 3.137.130.137
  PublicIpv4Pool: amazon

| => aws ec2 allocate-address
AllocationId: eipalloc-007d40418314a2254
Domain: vpc
NetworkBorderGroup: us-east-2
PublicIp: 3.20.6.139
PublicIpv4Pool: amazon

| => aws ec2 associate-address --instance-id i-056efcabf550196ab --public-ip 3.21.141.121
AssociationId: eipassoc-09b71bc97898063ff

| => aws ec2 disassociate-address --public-ip 3.21.141.121


aws ec2 release-address --allocation-id eipalloc-007d40418314a2254
'''