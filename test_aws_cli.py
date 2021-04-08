import os, sys
import re, hashlib,time
import atexit

import pytest

from awsAPIv2 import aws
# import awsAPI_v2
# from awsRES import *

@pytest.fixture(scope="function", autouse=True)
def setup(request):
    global setting
    setting = {}
    with open("/Users/yijunzhu/.aws/config_auto", "r") as f:
        cfg = f.read()
    with open("/Users/yijunzhu/.aws/credentials_auto", "r") as f:
        cda = f.read()

    setting["config"] = cfg
    setting["credentials"] = cda

    with open("/Users/yijunzhu/.aws/config", "r") as f:
        bytes_str = f.read().encode()
        md5_default_config = hashlib.md5(bytes_str).digest()
    with open("/Users/yijunzhu/.aws/credentials", "r") as f:
        bytes_str = f.read().encode()
        md5_default_credentials = hashlib.md5(bytes_str).digest()

    def teardown():
        with open("/Users/yijunzhu/.aws/config", "r") as f:
            bytes_str = f.read().encode()
            md5_default_config_v = hashlib.md5(bytes_str).digest()
        with open("/Users/yijunzhu/.aws/credentials", "r") as f:
            bytes_str = f.read().encode()
            md5_default_credentials_v = hashlib.md5(bytes_str).digest()

        assert md5_default_config == md5_default_config_v
        assert md5_default_credentials == md5_default_credentials_v

    request.addfinalizer(teardown)

def test_default_configure_file():
    obj = aws()
    obj.close()

def test_special_configure():
    setting = {}
    cfg = {"default": {"region": "shanghai", "output": "yaml"}}
    cda = {"default": {"access-id": "1234", "secret-id": "3456"}}
    setting["config"] = cfg
    setting["credentials"] = cda

    obj = aws(setting)
    obj.close()

def test_private_configure_file():
    obj = aws(setting)
    obj.close()

def test_show_ec2_instances():
    obj = aws(setting)
    atexit.register(obj.close)
    assert "EC2" not in obj.tobeCleanUp

    res = obj.raw_cli("aws ec2 describe-instances", False)
    assert "EC2" not in obj.tobeCleanUp

    obj.close()

def test_new_ec2_instances():
    obj = aws(setting)
    atexit.register(obj.close)
    assert "EC2" not in obj.tobeCleanUp

    cmd = "aws ec2 run-instances --image-id ami-03d64741867e7bb94 --count 2 --instance-type t2.micro " \
          "--key-name testMonkey --security-group-ids sg-7e070b0f"
    obj.raw_cli(cmd)

    assert obj.tobeCleanUp["EC2"] != []
    obj.close()

def test_backup_resource_file():
    obj = aws(setting)
    atexit.register(obj.close)

    cmd = "aws ec2 run-instances --image-id ami-03d64741867e7bb94 --count 2 --instance-type t2.micro " \
          "--key-name testMonkey --security-group-ids sg-7e070b0f"
    obj.raw_cli(cmd)

    obj.res_record("auto_log")

    obj.close()
    assert os.path.exists("auto_log")

@pytest.mark.keypair
def test_key_generation():
    obj = aws(setting)
    atexit.register(obj.close)

    obj.key_generation()
    assert os.path.exists("key_auto.pem")
    obj.close()
    assert not os.path.exists("key_auto.pem")

@pytest.mark.dp
def test_deploy():
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment("aws_cli.config")
    obj.start_deployment()

    obj.res_record()
    obj.close()

@pytest.mark.deploy
@pytest.mark.internetGW
def test_IG():
    cont ='''
Auto_IG_App(INTERNET_GATEWAY):
  action:
    cleanUP: True
'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

    res = obj.raw_cli("aws ec2 describe-internet-gateways")
    assert "Auto_IG_App" in res
    obj.close()

    obj2 = aws(setting)
    atexit.register(obj2.close)
    res2 = obj2.raw_cli("aws ec2 describe-internet-gateways")
    assert "Auto_IG_App" not in res2
    obj2.close()

@pytest.mark.deploy
@pytest.mark.vpc
def test_VPC():
    cont ='''
Auto_IG_App(INTERNET_GATEWAY):
  action:
    cleanUP: True
Auto_VPC_App(VPC):
  cidr-block: 10.0.0.0/16
  action:
    bind_to: Auto_IG_App
    cleanUP: True
'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

    res = obj.raw_cli("aws ec2 describe-vpcs")
    assert "Auto_VPC_App" in res
    obj.close()

    obj2 = aws(setting)
    atexit.register(obj2.close)
    res2 = obj2.raw_cli("aws ec2 describe-vpcs")
    assert "Auto_VPC_App" not in res2

    obj2.close()

@pytest.mark.deploy
@pytest.mark.sg
def test_SG():
    cont ='''
Auto_IG_App(INTERNET_GATEWAY):
  action:
    cleanUP: True
Auto_VPC_App(VPC):
  cidr-block: 10.0.0.0/16
  action:
    bind_to: Auto_IG_App
    cleanUP: True
Auto_SG_App(SECURITY_GROUP):
  vpc-id: Auto_VPC_App
  description: My security group
  action:
    authorize-security-group-ingress:
      - protocol: tcp
        port: 22
        cidr: 0.0.0.0/0
      - protocol: tcp
        port: 80
        cidr: 0.0.0.0/0
      - protocol: icmp
        port: all
        cidr: 0.0.0.0/0
      - protocol: udp
        port: 6081
        cidr: 0.0.0.0/0
    bind_to: Auto_VPC_App
    cleanUP: True
'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

    res = obj.raw_cli("aws ec2 describe-security-groups")
    assert "Auto_SG_App" in res
    time.sleep(20)
    obj.close()

    obj2 = aws(setting)
    atexit.register(obj2.close)
    res2 = obj2.raw_cli("aws ec2 describe-security-groups")
    assert "Auto_SG_App" not in res2


@pytest.mark.deploy1
@pytest.mark.sub
def test_SUB():
    cont ='''
Auto_IG_App(INTERNET_GATEWAY):
  action:
    cleanUP: True
Auto_VPC_App(VPC):
  cidr-block: 10.0.0.0/16
  action:
    bind_to: Auto_IG_App
    cleanUP: True
Auto_SG_App(SECURITY_GROUP):
  vpc-id: Auto_VPC_App
  description: My security group
  action:
    authorize-security-group-ingress:
      - protocol: tcp
        port: 22
        cidr: 0.0.0.0/0
      - protocol: tcp
        port: 80
        cidr: 0.0.0.0/0
      - protocol: icmp
        port: all
        cidr: 0.0.0.0/0
      - protocol: udp
        port: 6081
        cidr: 0.0.0.0/0
    bind_to: Auto_VPC_App
    cleanUP: True
Auto_SUB_App_1(SUBNET):
  vpc-id: Auto_VPC_App
  cidr-block: 10.0.1.0/24
  action:
    bind_to: Auto_VPC_App
    cleanUP: True
'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

    res = obj.raw_cli("aws ec2 describe-subnets")
    assert "Auto_SUB_App_1" in res

    obj.close()

    obj2 = aws(setting)
    atexit.register(obj2.close)
    res2 = obj2.raw_cli("aws ec2 describe-subnets")
    assert "Auto_SUB_App_1" not in res2


@pytest.mark.deploy
@pytest.mark.gwlb
def test_GWLB():
    cont ='''
Auto_IG_App(INTERNET_GATEWAY):
  action:
    cleanUP: True
Auto_VPC_App(VPC):
  cidr-block: 10.0.0.0/16
  action:
    bind_to: Auto_IG_App
    cleanUP: True
Auto_SG_App(SECURITY_GROUP):
  vpc-id: Auto_VPC_App
  description: My security group
  action:
    authorize-security-group-ingress:
      - protocol: tcp
        port: 22
        cidr: 0.0.0.0/0
      - protocol: tcp
        port: 80
        cidr: 0.0.0.0/0
      - protocol: icmp
        port: all
        cidr: 0.0.0.0/0
      - protocol: udp
        port: 6081
        cidr: 0.0.0.0/0
    bind_to: Auto_VPC_App
    cleanUP: True
Auto_SUB_Sec(SUBNET):
  vpc-id: Auto_VPC_App
  cidr-block: 10.0.1.0/24
  action:
    bind_to: Auto_VPC_App
    cleanUP: True
Auto-GWLB(GATEWAY_LOAD_BALANCE):
  type: gateway
  subnets: Auto_SUB_Sec
  action:
    bind_to: Auto_SUB_Sec
    cleanUP: True
'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

    res = obj.raw_cli("aws elbv2 describe-load-balancers")
    assert "Auto-GWLB" in res

    obj.close()

    obj2 = aws(setting)
    atexit.register(obj2.close)
    res2 = obj2.raw_cli("aws elbv2 describe-load-balancers")
    assert "Auto-GWLB" not in res2

@pytest.mark.deploy
@pytest.mark.tg
def test_TG():
    cont ='''
Auto_IG_App(INTERNET_GATEWAY):
  action:
    cleanUP: True
Auto_VPC_App(VPC):
  cidr-block: 10.0.0.0/16
  action:
    bind_to: Auto_IG_App
    cleanUP: True
Auto_SG_App(SECURITY_GROUP):
  vpc-id: Auto_VPC_App
  description: My security group
  action:
    authorize-security-group-ingress:
      - protocol: tcp
        port: 22
        cidr: 0.0.0.0/0
      - protocol: tcp
        port: 80
        cidr: 0.0.0.0/0
      - protocol: icmp
        port: all
        cidr: 0.0.0.0/0
      - protocol: udp
        port: 6081
        cidr: 0.0.0.0/0
    bind_to: Auto_VPC_App
    cleanUP: True
Auto_SUB_Sec(SUBNET):
  vpc-id: Auto_VPC_App
  cidr-block: 10.0.1.0/24
  action:
    bind_to: Auto_VPC_App
    cleanUP: True
Auto-GWLB(GATEWAY_LOAD_BALANCE):
  type: gateway
  subnets: Auto_SUB_Sec
  action:
    bind_to: Auto_SUB_Sec
    cleanUP: True
Auto-TG(TARGET_GROUP):
  protocol: GENEVE
  port: 6081
  vpc-id: Auto_VPC_App
  action:
    bind_to: Auto_VPC_App
    cleanUP: True
'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

    res = obj.raw_cli("aws elbv2 describe-target-groups")
    assert "Auto-TG" in res

    obj.close()

    obj2 = aws(setting)
    atexit.register(obj2.close)
    res2 = obj2.raw_cli("aws elbv2 describe-target-groups")
    assert "Auto-TG" not in res2

@pytest.mark.deploy
@pytest.mark.list
def test_LIST():
    cont ='''
Auto_IG_App(INTERNET_GATEWAY):
  action:
    cleanUP: True
Auto_VPC_App(VPC):
  cidr-block: 10.0.0.0/16
  action:
    bind_to: Auto_IG_App
    cleanUP: True
Auto_SG_App(SECURITY_GROUP):
  vpc-id: Auto_VPC_App
  description: My security group
  action:
    authorize-security-group-ingress:
      - protocol: tcp
        port: 22
        cidr: 0.0.0.0/0
      - protocol: tcp
        port: 80
        cidr: 0.0.0.0/0
      - protocol: icmp
        port: all
        cidr: 0.0.0.0/0
      - protocol: udp
        port: 6081
        cidr: 0.0.0.0/0
    bind_to: Auto_VPC_App
    cleanUP: True
Auto_SUB_Sec(SUBNET):
  vpc-id: Auto_VPC_App
  cidr-block: 10.0.1.0/24
  action:
    bind_to: Auto_VPC_App
    cleanUP: True
Auto-GWLB(GATEWAY_LOAD_BALANCE):
  type: gateway
  subnets: Auto_SUB_Sec
  action:
    bind_to: Auto_SUB_Sec
    cleanUP: True
Auto-TG(TARGET_GROUP):
  protocol: GENEVE
  port: 6081
  vpc-id: Auto_VPC_App
  action:
    bind_to: Auto_VPC_App
    cleanUP: True
Auto-LIST(LISTENER):
  load-balancer-arn: Auto-GWLB
  default-actions: Type=forward,TargetGroupArn=Auto-TG
  action:
    bind_to: 
      - Auto-GWLB
      - Auto-TG
    cleanUP: True
'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

    gwlb_id = obj.find_id("Auto-GWLB")
    res = obj.raw_cli(f"aws elbv2 describe-listeners --load-balancer-arn {gwlb_id}")
    list_id = obj.find_id("Auto-LIST")
    assert list_id in res

    obj.close()

    obj2 = aws(setting)
    atexit.register(obj2.close)
    res2 = obj2.raw_cli("aws elbv2 describe-load-balancers")
    assert "Auto-GWLB" not in res2

@pytest.mark.deploy
@pytest.mark.gwlbs
def test_GWLBS():
    cont ='''
Auto_IG_App(INTERNET_GATEWAY):
  action:
    cleanUP: True
Auto_VPC_App(VPC):
  cidr-block: 10.0.0.0/16
  action:
    bind_to: Auto_IG_App
    cleanUP: True
Auto_SG_App(SECURITY_GROUP):
  vpc-id: Auto_VPC_App
  description: My security group
  action:
    authorize-security-group-ingress:
      - protocol: tcp
        port: 22
        cidr: 0.0.0.0/0
      - protocol: tcp
        port: 80
        cidr: 0.0.0.0/0
      - protocol: icmp
        port: all
        cidr: 0.0.0.0/0
      - protocol: udp
        port: 6081
        cidr: 0.0.0.0/0
    bind_to: Auto_VPC_App
    cleanUP: True
Auto_SUB_Sec(SUBNET):
  vpc-id: Auto_VPC_App
  cidr-block: 10.0.1.0/24
  action:
    bind_to: Auto_VPC_App
    cleanUP: True
Auto-GWLB(GATEWAY_LOAD_BALANCE):
  type: gateway
  subnets: Auto_SUB_Sec
  action:
    bind_to: Auto_SUB_Sec
    cleanUP: True
Auto-TG(TARGET_GROUP):
  protocol: GENEVE
  port: 6081
  vpc-id: Auto_VPC_App
  action:
    bind_to: Auto_VPC_App
    cleanUP: True
Auto-LIST(LISTENER):
  load-balancer-arn: Auto-GWLB
  default-actions: Type=forward,TargetGroupArn=Auto-TG
  action:
    bind_to: 
      - Auto-GWLB
      - Auto-TG
    cleanUP: True
Auto-VPCE-Serv(VPCE_SERVICE):
  gateway-load-balancer-arns: Auto-GWLB
  no-acceptance-required:
  action:
    bind_to: Auto-GWLB
    cleanUP: True
'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

    res = obj.raw_cli("aws ec2 describe-vpc-endpoint-service-configurations")
    assert "Auto-VPCE-Serv" in res

    obj.close()

    obj2 = aws(setting)
    atexit.register(obj2.close)
    res2 = obj2.raw_cli("aws ec2 describe-vpc-endpoint-service-configurations")
    assert "Auto-VPCE-Serv" not in res2

@pytest.mark.deploy
@pytest.mark.gwlbe
def test_GWLBE():
    cont ='''
Auto_IG_App(INTERNET_GATEWAY):
  action:
    cleanUP: True
Auto_VPC_App(VPC):
  cidr-block: 10.0.0.0/16
  action:
    bind_to: Auto_IG_App
    cleanUP: True
Auto_SG_App(SECURITY_GROUP):
  vpc-id: Auto_VPC_App
  description: My security group
  action:
    authorize-security-group-ingress:
      - protocol: tcp
        port: 22
        cidr: 0.0.0.0/0
      - protocol: tcp
        port: 80
        cidr: 0.0.0.0/0
      - protocol: icmp
        port: all
        cidr: 0.0.0.0/0
      - protocol: udp
        port: 6081
        cidr: 0.0.0.0/0
    bind_to: Auto_VPC_App
    cleanUP: True
Auto_SUB_Sec(SUBNET):
  vpc-id: Auto_VPC_App
  cidr-block: 10.0.1.0/24
  action:
    bind_to: Auto_VPC_App
    cleanUP: True
Auto-GWLB(GATEWAY_LOAD_BALANCE):
  type: gateway
  subnets: Auto_SUB_Sec
  action:
    bind_to: Auto_SUB_Sec
    cleanUP: True
Auto-TG(TARGET_GROUP):
  protocol: GENEVE
  port: 6081
  vpc-id: Auto_VPC_App
  action:
    bind_to: Auto_VPC_App
    cleanUP: True
Auto-LIST(LISTENER):
  load-balancer-arn: Auto-GWLB
  default-actions: Type=forward,TargetGroupArn=Auto-TG
  action:
    bind_to: 
      - Auto-GWLB
      - Auto-TG
    cleanUP: True
Auto-VPCE-Serv(VPCE_SERVICE):
  gateway-load-balancer-arns: Auto-GWLB
  no-acceptance-required:
  action:
    bind_to: Auto-GWLB
    cleanUP: True
Auto-GWLBE(GATEWAY_LOAD_BALANCE_ENDPOINT):
  vpc-endpoint-type: GatewayLoadBalancer
  service-name: Auto-VPCE-Serv
  vpc-id: Auto_VPC_App
  subnet-ids: Auto_SUB_Sec
  action:
    bind_to:
      - Auto-VPCE-Serv
      - Auto_VPC_App
      - Auto_SUB_Sec
    cleanUP: True
'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

    res = obj.raw_cli("aws ec2 describe-vpc-endpoints")
    assert "Auto-GWLBE" in res

    obj.close()

    obj2 = aws(setting)
    atexit.register(obj2.close)
    res2 = obj2.raw_cli("aws ec2 describe-vpc-endpoints")
    assert "Auto-GWLBE" not in res2


@pytest.mark.deploy
@pytest.mark.route
def test_ROUTE():
    cont ='''
Auto_IG_App(INTERNET_GATEWAY):
  action:
    cleanUP: True
Auto_VPC_App(VPC):
  cidr-block: 10.0.0.0/16
  action:
    bind_to: Auto_IG_App
    cleanUP: True
Auto_SG_App(SECURITY_GROUP):
  vpc-id: Auto_VPC_App
  description: My security group
  action:
    authorize-security-group-ingress:
      - protocol: tcp
        port: 22
        cidr: 0.0.0.0/0
      - protocol: tcp
        port: 80
        cidr: 0.0.0.0/0
      - protocol: icmp
        port: all
        cidr: 0.0.0.0/0
      - protocol: udp
        port: 6081
        cidr: 0.0.0.0/0
    bind_to: Auto_VPC_App
    cleanUP: True
Auto_SUB_Sec(SUBNET):
  vpc-id: Auto_VPC_App
  cidr-block: 10.0.1.0/24
  action:
    bind_to: Auto_VPC_App
    cleanUP: True
Auto-GWLB(GATEWAY_LOAD_BALANCE):
  type: gateway
  subnets: Auto_SUB_Sec
  action:
    bind_to: Auto_SUB_Sec
    cleanUP: True
Auto-TG(TARGET_GROUP):
  protocol: GENEVE
  port: 6081
  vpc-id: Auto_VPC_App
  action:
    bind_to: Auto_VPC_App
    cleanUP: True
Auto-LIST(LISTENER):
  load-balancer-arn: Auto-GWLB
  default-actions: Type=forward,TargetGroupArn=Auto-TG
  action:
    bind_to: 
      - Auto-GWLB
      - Auto-TG
    cleanUP: True
Auto-VPCE-Serv(VPCE_SERVICE):
  gateway-load-balancer-arns: Auto-GWLB
  no-acceptance-required:
  action:
    bind_to: Auto-GWLB
    cleanUP: True
Auto-GWLBE(GATEWAY_LOAD_BALANCE_ENDPOINT):
  vpc-endpoint-type: GatewayLoadBalancer
  service-name: Auto-VPCE-Serv
  vpc-id: Auto_VPC_App
  subnet-ids: Auto_SUB_Sec
  action:
    bind_to:
      - Auto-VPCE-Serv
      - Auto_VPC_App
      - Auto_SUB_Sec
    cleanUP: True
Auto_RT_Sec_Main(ROUTE):
  route-table-id: '@Auto_VPC_App@'
  destination-cidr-block: 9.8.7.6/24
  gateway-id: Auto_IG_App
  action:
    bind_to:
      - Auto_IG_App
      - Auto_VPC_App
    cleanUP: True
'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

    res = obj.raw_cli("aws ec2 describe-route-tables")
    assert "9.8.7.0" in res

    obj.close()

    obj2 = aws(setting)
    atexit.register(obj2.close)
    res2 = obj2.raw_cli("aws ec2 describe-route-tables")
    assert "9.8.7.0" not in res2


@pytest.mark.deploy
@pytest.mark.routetb
def test_ROUTE_TABLE():
    cont ='''
Auto_IG_App(INTERNET_GATEWAY):
  action:
    cleanUP: True
Auto_VPC_App(VPC):
  cidr-block: 10.0.0.0/16
  action:
    bind_to: Auto_IG_App
    cleanUP: True
Auto_SG_App(SECURITY_GROUP):
  vpc-id: Auto_VPC_App
  description: My security group
  action:
    authorize-security-group-ingress:
      - protocol: tcp
        port: 22
        cidr: 0.0.0.0/0
      - protocol: tcp
        port: 80
        cidr: 0.0.0.0/0
      - protocol: icmp
        port: all
        cidr: 0.0.0.0/0
      - protocol: udp
        port: 6081
        cidr: 0.0.0.0/0
    bind_to: Auto_VPC_App
    cleanUP: True
Auto_SUB_Sec(SUBNET):
  vpc-id: Auto_VPC_App
  cidr-block: 10.0.1.0/24
  action:
    bind_to: Auto_VPC_App
    cleanUP: True
Auto-GWLB(GATEWAY_LOAD_BALANCE):
  type: gateway
  subnets: Auto_SUB_Sec
  action:
    bind_to: Auto_SUB_Sec
    cleanUP: True
Auto-TG(TARGET_GROUP):
  protocol: GENEVE
  port: 6081
  vpc-id: Auto_VPC_App
  action:
    bind_to: Auto_VPC_App
    cleanUP: True
Auto-LIST(LISTENER):
  load-balancer-arn: Auto-GWLB
  default-actions: Type=forward,TargetGroupArn=Auto-TG
  action:
    bind_to: 
      - Auto-GWLB
      - Auto-TG
    cleanUP: True
Auto-VPCE-Serv(VPCE_SERVICE):
  gateway-load-balancer-arns: Auto-GWLB
  no-acceptance-required:
  action:
    bind_to: Auto-GWLB
    cleanUP: True
Auto-GWLBE(GATEWAY_LOAD_BALANCE_ENDPOINT):
  vpc-endpoint-type: GatewayLoadBalancer
  service-name: Auto-VPCE-Serv
  vpc-id: Auto_VPC_App
  subnet-ids: Auto_SUB_Sec
  action:
    bind_to:
      - Auto-VPCE-Serv
      - Auto_VPC_App
      - Auto_SUB_Sec
    cleanUP: True
Auto_RT_Sec_Main(ROUTE):
  route-table-id: '@Auto_VPC_App@'
  destination-cidr-block: 9.8.7.6/24
  gateway-id: Auto_IG_App
  action:
    bind_to:
      - Auto_IG_App
      - Auto_VPC_App
    cleanUP: True
Auto_RTT_Sec(ROUTE_TABLE):
  vpc-id: Auto_VPC_App
  action:
    sub_route:
      - route-table-id: Auto_RTT_Sec
        destination-cidr-block: 1.2.3.4/24
        vpc-endpoint-id: Auto-GWLBE
        action:
          bind_to: 
            - Auto-GWLBE
            - Auto_RTT_Sec
    bind_to: Auto_VPC_App
    cleanUP: True
'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

    res = obj.raw_cli("aws ec2 describe-route-tables")
    assert "1.2.3.0" in res
    assert "Auto_RTT_Sec" in res

    obj.close()

    obj2 = aws(setting)
    atexit.register(obj2.close)
    res2 = obj2.raw_cli("aws ec2 describe-route-tables")
    assert "1.2.3.0" not in res2
    assert "Auto_RTT_Sec" not in res2


@pytest.mark.deploy
@pytest.mark.asso
def test_ASSOCIATION():
    cont ='''
Auto_IG_App(INTERNET_GATEWAY):
  action:
    cleanUP: True
Auto_VPC_App(VPC):
  cidr-block: 10.0.0.0/16
  action:
    bind_to: Auto_IG_App
    cleanUP: True
Auto_SG_App(SECURITY_GROUP):
  vpc-id: Auto_VPC_App
  description: My security group
  action:
    authorize-security-group-ingress:
      - protocol: tcp
        port: 22
        cidr: 0.0.0.0/0
      - protocol: tcp
        port: 80
        cidr: 0.0.0.0/0
      - protocol: icmp
        port: all
        cidr: 0.0.0.0/0
      - protocol: udp
        port: 6081
        cidr: 0.0.0.0/0
    bind_to: Auto_VPC_App
    cleanUP: True
Auto_SUB_Sec(SUBNET):
  vpc-id: Auto_VPC_App
  cidr-block: 10.0.1.0/24
  action:
    bind_to: Auto_VPC_App
    cleanUP: True
Auto-GWLB(GATEWAY_LOAD_BALANCE):
  type: gateway
  subnets: Auto_SUB_Sec
  action:
    bind_to: Auto_SUB_Sec
    cleanUP: True
Auto-TG(TARGET_GROUP):
  protocol: GENEVE
  port: 6081
  vpc-id: Auto_VPC_App
  action:
    bind_to: Auto_VPC_App
    cleanUP: True
Auto-LIST(LISTENER):
  load-balancer-arn: Auto-GWLB
  default-actions: Type=forward,TargetGroupArn=Auto-TG
  action:
    bind_to: 
      - Auto-GWLB
      - Auto-TG
    cleanUP: True
Auto-VPCE-Serv(VPCE_SERVICE):
  gateway-load-balancer-arns: Auto-GWLB
  no-acceptance-required:
  action:
    bind_to: Auto-GWLB
    cleanUP: True
Auto-GWLBE(GATEWAY_LOAD_BALANCE_ENDPOINT):
  vpc-endpoint-type: GatewayLoadBalancer
  service-name: Auto-VPCE-Serv
  vpc-id: Auto_VPC_App
  subnet-ids: Auto_SUB_Sec
  action:
    bind_to:
      - Auto-VPCE-Serv
      - Auto_VPC_App
      - Auto_SUB_Sec
    cleanUP: True
Auto_RT_Sec_Main(ROUTE):
  route-table-id: '@Auto_VPC_App@'
  destination-cidr-block: 9.8.7.6/24
  gateway-id: Auto_IG_App
  action:
    bind_to:
      - Auto_IG_App
      - Auto_VPC_App
    cleanUP: True
Auto_RTT_Sec(ROUTE_TABLE):
  vpc-id: Auto_VPC_App
  action:
    sub_route:
      - route-table-id: Auto_RTT_Sec
        destination-cidr-block: 1.2.3.4/24
        vpc-endpoint-id: Auto-GWLBE
        action:
          bind_to: 
            - Auto-GWLBE
            - Auto_RTT_Sec
    bind_to: Auto_VPC_App
    cleanUP: True
Auto_ASSO_Sub_1(ROUTE_ASSOCIATE):
  route-table-id: Auto_RTT_Sec
  subnet-id: Auto_SUB_Sec
  action:
    bind_to:
      - Auto_RTT_Sec
      - Auto_SUB_Sec
    cleanUP: True
'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

    asso_id = obj.find_id("Auto_SUB_Sec")
    res = obj.raw_cli("aws ec2 describe-route-tables")
    assert asso_id in res

    obj.close()

    obj2 = aws(setting)
    atexit.register(obj2.close)
    res2 = obj2.raw_cli("aws ec2 describe-route-tables")
    assert asso_id not in res2

@pytest.mark.deploy
@pytest.mark.ec2
def test_EC2INSTANCE():
    cont ='''
Auto_IG_App(INTERNET_GATEWAY):
  action:
    cleanUP: True
Auto_VPC_App(VPC):
  cidr-block: 10.0.0.0/16
  action:
    bind_to: Auto_IG_App
    cleanUP: True
Auto_SG_App(SECURITY_GROUP):
  vpc-id: Auto_VPC_App
  description: My security group
  action:
    authorize-security-group-ingress:
      - protocol: tcp
        port: 22
        cidr: 0.0.0.0/0
      - protocol: tcp
        port: 80
        cidr: 0.0.0.0/0
      - protocol: icmp
        port: all
        cidr: 0.0.0.0/0
      - protocol: udp
        port: 6081
        cidr: 0.0.0.0/0
    bind_to: Auto_VPC_App
    cleanUP: True
Auto_SUB_Sec(SUBNET):
  vpc-id: Auto_VPC_App
  cidr-block: 10.0.1.0/24
  action:
    bind_to: Auto_VPC_App
    cleanUP: True
Auto_EC2_Sec(EC2INSTANCE):
  image-id: ami-03d64741867e7bb94
  instance-type: t2.micro
  key-name: testMonkey
  security-group-ids: Auto_SG_Sec
  count: 1
  subnet-id: Auto_SUB_Sec
  associate-public-ip-address: None
  action:
    bind_to:
      - Auto_SG_App
      - Auto_SUB_Sec
    cmd: 
      - date
      - sudo yum install python3 -y
      - hostname
    cleanUP: True
'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()
    res = obj.raw_cli("aws ec2 describe-instances")
    assert "Auto_EC2_Sec" in res

    id = obj.find_id("Auto_EC2_Sec")["Auto_EC2_Sec"]

    obj.close()

    obj2 = aws(setting)
    atexit.register(obj2.close)
    res2 = obj2.raw_cli(f"aws ec2 describe-instances --instance-ids {id}")
    assert "Auto_EC2_Sec" in res2
    assert "terminated" in res2

@pytest.mark.deploy
@pytest.mark.data
def test_EC2INSTANCE_DATA():
    cont ='''
Debug_IG_App(INTERNET_GATEWAY):
  action:
    cleanUP: True
Debug_VPC_App(VPC):
  cidr-block: 10.0.0.0/16
  action:
    bind_to: Debug_IG_App
    cleanUP: True
Debug_SG_App(SECURITY_GROUP):
  vpc-id: Debug_VPC_App
  description: My security group
  action:
    authorize-security-group-ingress:
      - protocol: tcp
        port: 22
        cidr: 0.0.0.0/0
      - protocol: tcp
        port: 80
        cidr: 0.0.0.0/0
      - protocol: icmp
        port: all
        cidr: 0.0.0.0/0
      - protocol: udp
        port: 6081
        cidr: 0.0.0.0/0
    bind_to: Debug_VPC_App
    cleanUP: True
Debug_SUB_Sec(SUBNET):
  vpc-id: Debug_VPC_App
  cidr-block: 10.0.1.0/24
  action:
    bind_to: Debug_VPC_App
    cleanUP: True
Debug_EC2_Sec(EC2INSTANCE):
  image-id: ami-08962a4068733a2b6
  instance-type: t2.micro
  key-name: testMonkey
  security-group-ids: Debug_SG_App
  count: 1
  subnet-id: Debug_SUB_Sec
  associate-public-ip-address: None
  action:
    bind_to:
      - Debug_SG_App
      - Debug_SUB_Sec
    cmd: 
      - sudo git clone https://github.com/sentialabs/geneve-proxy.git
      - sudo cd geneve-proxy
      - sudo script "sudo screen;sudo python3 main.py&;pwd;killall script;" /dev/null
    cleanUP: True
Debug_NWInterface_Sec(NETWORK_INTERFACE):
  subnet-id: Debug_SUB_Sec
  description: Debug Data Network for Security
  groups: Debug_SG_App
  action:
    bind_to: 
      - Debug_SG_App
      - Debug_SUB_Sec
    cleanUP: True
Debug_NWInterface_Sec_Bind(BIND):
  network-interface-id: Debug_NWInterface_Sec
  instance-id: Debug_EC2_Sec
  device-index: 1
  action:
    bind_to: 
      - Debug_NWInterface_Sec
      - Debug_EC2_Sec
    cleanUP: True    

'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()
    res = obj.raw_cli("aws ec2 describe-network-interfaces",show=False)

    print("Debug start ~~~~~~~~~~~~~~")
    time.sleep(1200)
    assert "Debug_NWInterface_Sec" in res
    obj.close()

    obj2 = aws(setting)
    atexit.register(obj2.close)
    res2 = obj2.raw_cli("aws ec2 describe-network-interfaces",show=False)
    assert "Debug_NWInterface_Sec" not in res2

@pytest.mark.deploy
@pytest.mark.reg
def test_REGISTER():
    cont ='''
Auto_IG_App(INTERNET_GATEWAY):
  action:
    cleanUP: True
Auto_VPC_App(VPC):
  cidr-block: 10.0.0.0/16
  action:
    bind_to: Auto_IG_App
    cleanUP: True
Auto_SG_App(SECURITY_GROUP):
  vpc-id: Auto_VPC_App
  description: My security group
  action:
    authorize-security-group-ingress:
      - protocol: tcp
        port: 22
        cidr: 0.0.0.0/0
      - protocol: tcp
        port: 80
        cidr: 0.0.0.0/0
      - protocol: icmp
        port: all
        cidr: 0.0.0.0/0
      - protocol: udp
        port: 6081
        cidr: 0.0.0.0/0
    bind_to: Auto_VPC_App
    cleanUP: True
Auto_SUB_Sec(SUBNET):
  vpc-id: Auto_VPC_App
  cidr-block: 10.0.1.0/24
  action:
    bind_to: Auto_VPC_App
    cleanUP: True
Auto-GWLB(GATEWAY_LOAD_BALANCE):
  type: gateway
  subnets: Auto_SUB_Sec
  action:
    bind_to: Auto_SUB_Sec
    cleanUP: True
Auto-TG(TARGET_GROUP):
  protocol: GENEVE
  port: 6081
  vpc-id: Auto_VPC_App
  action:
    bind_to: Auto_VPC_App
    cleanUP: True
Auto-LIST(LISTENER):
  load-balancer-arn: Auto-GWLB
  default-actions: Type=forward,TargetGroupArn=Auto-TG
  action:
    bind_to: 
      - Auto-GWLB
      - Auto-TG
    cleanUP: True
Auto-VPCE-Serv(VPCE_SERVICE):
  gateway-load-balancer-arns: Auto-GWLB
  no-acceptance-required:
  action:
    bind_to: Auto-GWLB
    cleanUP: True
Auto-GWLBE(GATEWAY_LOAD_BALANCE_ENDPOINT):
  vpc-endpoint-type: GatewayLoadBalancer
  service-name: Auto-VPCE-Serv
  vpc-id: Auto_VPC_App
  subnet-ids: Auto_SUB_Sec
  action:
    bind_to:
      - Auto-VPCE-Serv
      - Auto_VPC_App
      - Auto_SUB_Sec
    cleanUP: True
Auto_RT_Sec_Main(ROUTE):
  route-table-id: '@Auto_VPC_App@'
  destination-cidr-block: 9.8.7.6/24
  gateway-id: Auto_IG_App
  action:
    bind_to:
      - Auto_IG_App
      - Auto_VPC_App
    cleanUP: True
Auto_RTT_Sec(ROUTE_TABLE):
  vpc-id: Auto_VPC_App
  action:
    sub_route:
      - route-table-id: Auto_RTT_Sec
        destination-cidr-block: 1.2.3.4/24
        vpc-endpoint-id: Auto-GWLBE
        action:
          bind_to: 
            - Auto-GWLBE
            - Auto_RTT_Sec
    bind_to: Auto_VPC_App
    cleanUP: True
Auto_ASSO_Sub_1(ROUTE_ASSOCIATE):
  route-table-id: Auto_RTT_Sec
  subnet-id: Auto_SUB_Sec
  action:
    bind_to:
      - Auto_RTT_Sec
      - Auto_SUB_Sec
    cleanUP: True
Auto_EC2_Sec(EC2INSTANCE):
  image-id: ami-03d64741867e7bb94
  instance-type: t2.micro
  key-name: testMonkey
  security-group-ids: Auto_SG_Sec
  count: 1
  subnet-id: Auto_SUB_Sec
  associate-public-ip-address: None
  action:
    bind_to:
      - Auto_SG_App
      - Auto_SUB_Sec
    cmd: 
      - date
      - sudo yum install python3 -y
      - hostname
    cleanUP: True
Auto_TG_Instance(REGISTER):
  target-group-arn: Auto-TG
  targets: Id=Auto_EC2_Sec
  action:
    bind_to:
      - Auto-TG
      - Auto_EC2_Sec
    cleanUP: True
'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

    id = obj.find_id("Auto_EC2_Sec")["Auto_EC2_Sec"]
    tg_id = obj.find_id("Auto-TG")
    res = obj.raw_cli(f"aws elbv2 describe-target-health --target-group-arn {tg_id}")
    assert id in res

    obj.close()

    obj2 = aws(setting)
    atexit.register(obj2.close)
    res2 = obj2.raw_cli(f"aws elbv2 describe-target-groups")
    assert "Auto-TG" not in res2

@pytest.mark.deploy
@pytest.mark.ec22
def test_EC2INSTANCE2():
    cont ='''
Auto_IG_App(INTERNET_GATEWAY):
  action:
    cleanUP: True
Auto_VPC_App(VPC):
  cidr-block: 10.0.0.0/16
  action:
    bind_to: Auto_IG_App
    cleanUP: True
Auto_SG_App(SECURITY_GROUP):
  vpc-id: Auto_VPC_App
  description: My security group
  action:
    authorize-security-group-ingress:
      - protocol: tcp
        port: 22
        cidr: 0.0.0.0/0
      - protocol: tcp
        port: 80
        cidr: 0.0.0.0/0
      - protocol: icmp
        port: all
        cidr: 0.0.0.0/0
      - protocol: udp
        port: 6081
        cidr: 0.0.0.0/0
    bind_to: Auto_VPC_App
    cleanUP: True
Auto_SUB_Sec(SUBNET):
  vpc-id: Auto_VPC_App
  cidr-block: 10.0.1.0/24
  action:
    bind_to: Auto_VPC_App
    cleanUP: True
Auto_EC2_Sec(EC2INSTANCE):
  image-id: ami-03d64741867e7bb94
  instance-type: t2.micro
  key-name: testMonkey
  security-group-ids: Auto_SG_Sec
  count: 2
  subnet-id: Auto_SUB_Sec
  associate-public-ip-address: None
  action:
    bind_to:
      - Auto_SG_App
      - Auto_SUB_Sec
    cmd: 
      - date
      - sudo yum install python3 -y
      - hostname
    cleanUP: True
'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

    res = obj.raw_cli("aws ec2 describe-instances")
    assert "Auto_EC2_Sec_0" in res
    assert "Auto_EC2_Sec_1" in res

    id_0 = obj.find_id("Auto_EC2_Sec")["Auto_EC2_Sec_0"]
    id_1 = obj.find_id("Auto_EC2_Sec")["Auto_EC2_Sec_1"]

    obj.close()

    obj2 = aws(setting)
    atexit.register(obj2.close)
    res2 = obj2.raw_cli(f"aws ec2 describe-instances --instance-ids {id_0}")
    res3 = obj2.raw_cli(f"aws ec2 describe-instances --instance-ids {id_1}")
    assert "Auto_EC2_Sec_0" in res2
    assert "terminated" in res2
    assert "Auto_EC2_Sec_1" in res3
    assert "terminated" in res3


@pytest.mark.deploy
@pytest.mark.asav
def test_ASAv():
    cont ='''
Auto_IG_App(INTERNET_GATEWAY):
  action:
    cleanUP: True
Auto_VPC_App(VPC):
  cidr-block: 10.0.0.0/16
  action:
    bind_to: Auto_IG_App
    cleanUP: True
Auto_SG_App(SECURITY_GROUP):
  vpc-id: Auto_VPC_App
  description: My security group
  action:
    authorize-security-group-ingress:
      - protocol: tcp
        port: 22
        cidr: 0.0.0.0/0
      - protocol: tcp
        port: 80
        cidr: 0.0.0.0/0
      - protocol: icmp
        port: all
        cidr: 0.0.0.0/0
      - protocol: udp
        port: 6081
        cidr: 0.0.0.0/0
    bind_to: Auto_VPC_App
    cleanUP: True
Auto_SUB_Sec(SUBNET):
  vpc-id: Auto_VPC_App
  cidr-block: 10.0.1.0/24
  action:
    bind_to: Auto_VPC_App
    cleanUP: True
Auto_EC2_ASA(EC2INSTANCE):
  image-id: ami-03dda840f4c3d816e
  instance-type: c5.xlarge
  key-name: testMonkey
  security-group-ids: Auto_SG_Sec
  count: 1
  subnet-id: Auto_SUB_Sec
  user-data: file://day0_64.txt
  associate-public-ip-address: None
  action:
    bind_to:
      - Auto_SG_App
      - Auto_SUB_Sec
    cleanUP: True
'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

    res = obj.raw_cli("aws ec2 describe-instances")
    assert "Auto_EC2_ASA" in res

    obj.close()

    obj2 = aws(setting)
    atexit.register(obj2.close)

    res2 = obj2.raw_cli("aws ec2 describe-instances")
    assert "Auto_EC2_ASA" not in res2


@pytest.mark.disorder
def test_disorder():
    cont ='''
Auto_VPC_App(VPC):
  cidr-block: 10.0.0.0/16
  action:
    bind_to: Auto_IG_App
    cleanUP: True
Auto_IG_App(INTERNET_GATEWAY):
  action:
    cleanUP: True
'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

    res = obj.raw_cli("aws ec2 describe-vpcs")
    assert "Auto_VPC_App" in res
    obj.close()

    obj2 = aws(setting)
    atexit.register(obj2.close)
    res2 = obj2.raw_cli("aws ec2 describe-vpcs")
    assert "Auto_VPC_App" not in res2

@pytest.mark.term
def test_manual_termination():
    obj = aws(setting, record=False)
    atexit.register(obj.close)

    name = "aws_cli_19-41-07_07-04-2021"
    obj.manual_termination(name)

    obj.close()

#....
def test_auto_config_CleanUp():
    obj = aws()