import os, sys
import re, hashlib,time
import atexit

import pytest

from awsAPIv3 import aws
from lib_yijun import *
# import awsAPI_v2
# from awsRES import *

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

def load_asa_config(asa_address, debug=False):
    import pexpect
    print("Mark: ~~~~~~Enter load_asa_config~~~~~~")
    # asa_address = "ssh -i 'testDog.pem' admin@3.142.241.180"

    conn = pexpect.spawn(asa_address)
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("en")
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("copy http://20.0.250.10/geneve.smp disk0:/.")
    conn, result, cont = Geneve_reply(conn, timeout=120, debug=debug)

    conn.sendline("conf term")
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("boot system disk0:/geneve.smp")
    conn, result, cont = Geneve_reply(conn)

    if debug:
        print("~~~~~~Debug~~~~~~~")
        print('WAITED', wait(600))
        pytest.skip("Time to debug ASA error before reload")

    conn.sendline("reload")
    conn, result, cont = Geneve_reply(conn, debug=debug)

    print('WAITED', wait(600))
    conn.close(); del conn

    conn = pexpect.spawn(asa_address)
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("en")
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("conf term")
    conn, result, cont = Geneve_reply(conn)

    #asa load pytest_day999.txt
    Geneve_load(conn, "pytest_day999.txt")

    conn.sendline("show run")
    conn, result, cont = Geneve_reply(conn)
    assert "20.0.1.101" in cont

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

@pytest.mark.setting
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
@pytest.mark.asaTest
def test_ASATEST():
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

@pytest.mark.jb
def test_jb():
    cont ='''
Test-EC2-App-JB(EC2INSTANCE):
  image-id: ami-031b673f443c2172c
  instance-type: t2.micro
  key-name: testDog
  security-group-ids: sg-00f1b2c54a7bc855b
  count: 1
  subnet-id: subnet-0648f9342db2d7b86
  associate-public-ip-address: None
  private-ip-address: 10.0.250.10
  action:
    cmd:
      - sudo apt install net-tools
      - sudo apt update
      - sudo hostname Test-EC2-App-JB
      - sudo apt install auditd -y
      - sudo apt install python3-pip -y
      - sudo apt install iperf -y
      - sudo pip3 install scapy
      - sudo sed -i 's/.*PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config
      - sudo sed -i 's/.*PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
      - sudo systemctl restart sshd
      - sudo echo -e 'cisco123!\\ncisco123!\\n' | sudo passwd root
    transfer:
      - from:./testDog.pem to:/home/ubuntu/.
    cleanUP: False
'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

@pytest.mark.asa
def test_ASA():
    cont ='''
Test-EC2-ASA-debug(EC2INSTANCE):
  image-id: ami-01cab33393210e391
  instance-type: c5.xlarge
  key-name: testDog
  security-group-ids: sg-00444615bb2e31e4a
  count: 1
  subnet-id: subnet-07c5ed96af9cbb194
  associate-public-ip-address: None
  private-ip-address: 20.0.250.11
  user-data: file://pytest_day0_64.txt
  action:
    cleanUP: True

'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

    time.sleep(120)
    asa_ip = obj.fetch_address("Test-EC2-ASA-debug")
    asa_address = f"ssh -i 'testDog.pem' admin@{asa_ip}"

    load_asa_config(asa_address, debug=False)

@pytest.mark.elip
def test_ELASTIC_IP():
    cont ='''
Pytest-EC2(EC2INSTANCE):
  image-id: ami-08962a4068733a2b6
  instance-type: t2.micro
  key-name: testMonkey
  security-group-ids: sg-0623ef76b526af3e3
  count: 1
  subnet-id: subnet-0c2bc5c9f2d6eb528
  private-ip-address: 20.0.250.111
  action:
    cleanUP: True

Pytest_EIP(ELASTIC_IP):
  instance-id: Pytest-EC2
  action:
    bind_to:
      - Pytest-EC2
    cleanUP: True
    
# Pytest_EIP(ELASTIC_IP):
#     cleanUP: True
# 
# Pytest_EIP_Bind(BIND):
#  public-ip: Pytest_EIP
#  instance-id: Pytest-EC2
#  action:
#    bind_to:
#      - Pytest-EC2
#    cleanUP: True
'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

@pytest.mark.config
def test_ASA_CONFIG():
    cont = '''
Pytest_ASA(EC2INSTANCE):
  image-id: ami-03dda840f4c3d816e
  instance-type: c5.xlarge
  key-name: testMonkey
  security-group-ids: sg-035d152f039e6a6cf
  count: 1
  subnet-id: subnet-0d850495b884e6216
  user-data: file://pytest_day0.txt
  associate-public-ip-address: None
  private-ip-address: 20.0.250.111
  action:
    cleanUP: True
    
Pytest_NWInterface_ASA(NETWORK_INTERFACE):
  subnet-id: subnet-0c098ad4acd589c10
  description: Test Data Network for ASA
  groups: sg-0d5dd3fd9ea7d00f8
  private-ip-address: 20.0.1.211
  action:
    cleanUP: True

Pytest_NWInterface_ASA_Bind(BIND):
  network-interface-id: Pytest_NWInterface_ASA
  instance-id: Pytest_ASA
  device-index: 1
  action:
    bind_to:
      - Pytest_NWInterface_ASA
      - Pytest_ASA
    cleanUP: True
    '''
    # obj = aws(setting)
    # atexit.register(obj.close)
    #
    # obj.load_deployment(content=cont)
    # obj.start_deployment()
    #
    # asa_ip = obj.fetch_address("Pytest_ASA")
    # asa_jb_ip = obj.fetch_address("Pytest_ASA_JB")
    #
    # assert asa_ip is not None
    # assert asa_jb_ip is not None
    #
    # # JB
    # asa_jb_copy = f"scp -i 'testMonkey.pem' geneve.smp ubuntu@{asa_jb_ip}:/var/www/html/."
    # os.popen(asa_jb_copy)
    #
    # #ASA
    # asa_address = f"ssh -i 'testMonkey.pem' admin@{asa_ip}"
    # print("debug:asa_addres=",asa_address)
    import lib_yijun
    import pexpect

    asa_address = "ssh -i 'testMonkey.pem' admin@3.142.241.180"

    # print('WAITED', wait(600))
    conn = pexpect.spawn(asa_address)
    conn, result, cont = lib_yijun.Geneve_reply(conn)

    conn.sendline("en")
    conn, result, cont = lib_yijun.Geneve_reply(conn)

    conn.sendline("copy http://20.0.250.20/geneve.smp disk0:/.")
    conn, result, cont = lib_yijun.Geneve_reply(conn)

    conn.sendline("conf term")
    conn, result, cont = lib_yijun.Geneve_reply(conn)

    conn.sendline("boot system disk0:/geneve.smp")
    conn, result, cont = lib_yijun.Geneve_reply(conn)

    conn.sendline("reload")
    conn, result, cont = lib_yijun.Geneve_reply(conn)

    print('WAITED', wait(600))
    conn.close(); del conn

    conn = pexpect.spawn(asa_address)
    conn, result, cont = lib_yijun.Geneve_reply(conn)

    conn.sendline("en")
    conn, result, cont = lib_yijun.Geneve_reply(conn)

    conn.sendline("conf term")
    conn, result, cont = lib_yijun.Geneve_reply(conn)

    #asa load pytest_day999.txt
    lib_yijun.Geneve_load(conn, "pytest_day999.txt")

    conn.sendline("show run")
    conn, result, cont = lib_yijun.Geneve_reply(conn)
    assert "20.0.1.211" in cont


@pytest.mark.jump
def test_JB_CONTROL():
    cont = '''
Pytest-EC2-JB(EC2INSTANCE):
  image-id: ami-08962a4068733a2b6
  instance-type: t2.micro
  key-name: testMonkey
  security-group-ids: sg-035d152f039e6a6cf
  count: 1
  subnet-id: subnet-0d850495b884e6216
  associate-public-ip-address: None
  private-ip-address: 20.0.250.222
  action:
    cmd:
      - sudo hostname Pytest-EC2-JB
    transfer:
      - from:./testMonkey.pem to:/home/ubuntu/.
    cleanUP: True

Pytest-EC2-INSIDE(EC2INSTANCE):
  image-id: ami-08962a4068733a2b6
  instance-type: t2.micro
  key-name: testMonkey
  security-group-ids: sg-035d152f039e6a6cf
  count: 1
  subnet-id: subnet-0d850495b884e6216
  private-ip-address: 20.0.250.223
  action:
    cleanUP: True
'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

    jb_ip = obj.fetch_address("Pytest-EC2-JB")

    print("debug:jb_address=",jb_ip)

    print('Wait for the instance Boot Up!')
    print('WAITED', wait(30))
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # ssh.connect("18.191.189.206", username='ubuntu', password='', key_filename="testMonkey.pem")
    ssh.connect(jb_ip, username='ubuntu', password='', key_filename="testMonkey.pem")

    # ssh.exec_command("ssh -i 'testMonkey.pem' ubuntu@10.0.1.201 'hostname'")[1].readlines()
    _, stdout, _ = ssh.exec_command("ping 8.8.8.8 -c 1")
    stdout.channel.recv_exit_status()
    resp1 = "".join(stdout.readlines())
    # print("debug::1",resp1)
    assert "0% packet loss" in resp1

    while True:
        _, stdout, _ = ssh.exec_command("ssh -i 'testMonkey.pem' -o StrictHostKeyChecking=no "
                                        "-o UserKnownHostsFile=/dev/null ubuntu@20.0.250.223 'ping 8.8.8.8 -c 1'")
        stdout.channel.recv_exit_status()
        resp2 = "".join(stdout.readlines())
        if not resp2:
            print("～～～～～～empty~~~~~~~~")
            continue
        else:
            break

    assert "100% packet loss" in resp2

@pytest.mark.ftd
def test_FTD():
    cont = '''
Pytest-EC2-FTD(EC2INSTANCE):
  image-id: Pytest-AMI-FTD
  instance-type: d2.2xlarge
  key-name: testDog
  security-group-ids: Test-1-169_SG_Sec_MGMT
  count: 1
  subnet-id: Test-1-169_SUB_Sec_MGMT
  associate-public-ip-address: None
  private-ip-address: 20.0.250.12
  action:
    query_from:
        - Test-1-169_SUB_Sec_MGMT
        - Test-1-169_SG_Sec_MGMT
    bind_to:
        - Pytest-AMI-FTD
    cleanUP: True

Pytest-AMI-FTD(AMICOPY):
  source-image-id: ami-06aac12eabffe610d
  source-region: us-east-2
  region: us-west-1
  name: ftdv
  action:
    cleanUP: True 

Pytest_SUB_Sec_2_DATA(SUBNET):   
  vpc-id: Test-1-169_VPC_Sec
  cidr-block: 20.0.2.0/24
  availability-zone: '{Test-1-169_SUB_App_1_MGMT}'
  action:
    query_from:
      - Test-1-169_VPC_Sec
      - Test-1-169_SUB_App_1_MGMT
    cleanUP: True
Pytest_SUB_Sec_3_DATA(SUBNET):
  vpc-id: Test-1-169_VPC_Sec
  cidr-block: 20.0.3.0/24
  availability-zone: '{Test-1-169_SUB_App_1_MGMT}'
  action:
    query_from:
      - Test-1-169_VPC_Sec
      - Test-1-169_SUB_App_1_MGMT     
    cleanUP: True

Pytest_NWInterface_FTD1(NETWORK_INTERFACE):
  subnet-id: Test-1-169_SUB_Sec_DATA
  description: pytest Data Network for ASA
  groups: Test-1-169_SG_Sec_DATA
  private-ip-address: 20.0.1.102
  action:
    query_from:
        - Test-1-169_SUB_Sec_DATA
        - Test-1-169_SG_Sec_DATA
    cleanUP: True
Pytest_NWInterface_FTD2(NETWORK_INTERFACE):
  subnet-id: Pytest_SUB_Sec_2_DATA
  description: Test-1-169 Data Network2 for ASA
  groups: Test-1-169_SG_Sec_DATA
  private-ip-address: 20.0.2.102
  action:
    query_from:
        - Test-1-169_SG_Sec_DATA
    bind_to:
        - Pytest_SUB_Sec_2_DATA
    cleanUP: True
Pytest_NWInterface_FTD3(NETWORK_INTERFACE):
  subnet-id: Pytest_SUB_Sec_3_DATA
  description: Test-1-169 Data Network3 for ASA
  groups: Test-1-169_SG_Sec_DATA
  private-ip-address: 20.0.3.102
  action:
    query_from:
        - Test-1-169_SG_Sec_DATA
    bind_to:
        - Pytest_SUB_Sec_3_DATA
    cleanUP: True

Pytest_NWInterface_FTD_1_Bind(BIND):
  network-interface-id: Pytest_NWInterface_FTD1
  instance-id: Pytest-EC2-FTD
  device-index: 1
  action:
    bind_to:
      - Pytest_NWInterface_FTD1
      - Pytest-EC2-FTD
    cleanUP: True
Pytest_NWInterface_FTD_2_Bind(BIND):
  network-interface-id: Pytest_NWInterface_FTD2
  instance-id: Pytest-EC2-FTD
  device-index: 2
  action:
    bind_to:
      - Pytest_NWInterface_FTD2
      - Pytest-EC2-FTD
    cleanUP: True
Pytest_NWInterface_FTD_3_Bind(BIND):
  network-interface-id: Pytest_NWInterface_FTD3
  instance-id: Pytest-EC2-FTD
  device-index: 3
  action:
    bind_to:
      - Pytest_NWInterface_FTD3
      - Pytest-EC2-FTD
    cleanUP: True
'''
    obj = aws(setting, debug=True)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

@pytest.mark.fmc
def test_FMC():
    cont = '''
Pytest-EC2-FMC(EC2INSTANCE):
  image-id: Pytest-AMI-FMC
  instance-type: d2.2xlarge
  key-name: testDog
  security-group-ids: Test-1-169_SG_Sec_MGMT
  count: 1
  subnet-id: Test-1-169_SUB_Sec_MGMT
  associate-public-ip-address: None
  private-ip-address: 20.0.250.13
  action:
    query_from:
        - Test-1-169_SUB_Sec_MGMT
        - Test-1-169_SG_Sec_MGMT
    bind_to:
        - Pytest-AMI-FMC
    cleanUP: True

Pytest-AMI-FMC(AMICOPY):
  source-image-id: ami-0e8f534eeea33536b
  source-region: us-west-2
  region: us-west-1
  name: fmcv
  action:
    cleanUP: True 
'''
    obj = aws(setting, debug=True)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()


@pytest.mark.amiBuilder
def test_AMI_BUILDER():
    cont = '''
Test-EC2-Ami-Builder(EC2INSTANCE):
  image-id: ami-031b673f443c2172c
  instance-type: t2.micro
  key-name: testDog
  security-group-ids: sg-05e17a6782a8b59cf
  count: 1
  subnet-id: subnet-0d3b78a1b8b44a3cd
  associate-public-ip-address: None
  private-ip-address: 10.0.250.20
  action:
    cmd:
      - sudo apt install net-tools
      - sudo hostname Test-EC2-Ami-Builder
      - sudo chmod -R 777 /home/ubuntu
    transfer:
      - from:./testDog.pem to:/home/ubuntu/.
      - from:./qcow2_image to:home/ubuntu/.
      - from:./fixup_ftd to:home/ubuntu/.
    cleanUP: True
'''
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

    resize_cmd = "sudo chmod +x /mnt/fixup.sh;" \
                 "sudo /mnt/fixup.sh preinstall;" \
                 "sudo /mnt/fixup.sh doinstall;" \
                 "sudo /mnt/fixup.sh postinstall"

    builder_ip = obj.fetch_address("Test-EC2-Ami-Builder")

    pattern = "VolumeId: (.*)"
    volumn_id = {"aws ec2 describe-instances --instance-id i-043c56b84150b98b1"}

    snapshot_creation = 'aws ec2 create-snapshot --volume-id vol-1234567890abcdef0 ' \
                        '--description "This is my root volume snapshot"'

    ami_generate = 'aws ec2 create-image \
                        --instance-id i-1234567890abcdef0 \
                        --name "My server" \
                        --description "An AMI for my server"'

    print("debug:builder_ip_address=",builder_ip)

    print('Wait for the instance Boot Up!')
    print('WAITED', wait(30))
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # ssh.connect("18.191.189.206", username='ubuntu', password='', key_filename="testMonkey.pem")
    ssh.connect(builder_ip, username='ubuntu', password='', key_filename="testDog.pem")

    _, stdout, _ = ssh.exec_command("resize_cmd")
    stdout.channel.recv_exit_status()
    resp1 = "".join(stdout.readlines())
    # print("debug::1",resp1)
    assert "0% packet loss" in resp1

    # while True:
    #     _, stdout, _ = ssh.exec_command("ssh -i 'testMonkey.pem' -o StrictHostKeyChecking=no "
    #                                     "-o UserKnownHostsFile=/dev/null ubuntu@20.0.250.223 'ping 8.8.8.8 -c 1'")
    #     stdout.channel.recv_exit_status()
    #     resp2 = "".join(stdout.readlines())
    #     if not resp2:
    #         print("～～～～～～empty~~~~~~~~")
    #         continue
    #     else:
    #         break

    # assert "100% packet loss" in resp2


@pytest.mark.new
def test_new_testbed():
    obj = aws(setting, debug=False)
    atexit.register(obj.close)

    obj.load_deployment(fileName="aws_tb_pytest_west_1.config")
    obj.start_deployment()

    print("Rock and Roll!")

    obj.close()

@pytest.mark.term
def test_manual_termination():
    obj = aws(setting, record=False)
    atexit.register(obj.close)

    name = "aws_cli_12-17-47_14-06-2021"
    obj.manual_termination(name)

    obj.close()

@pytest.mark.extraFTD
def test_replace_exFTD():
    cont = '''
Del_PytestExtra_NWInterface_FTD1(TERMINATION):
  type: NETWORK_INTERFACE
  action:
    bind_to:
        - Del_PytestExtra-EC2-FTD
Del_PytestExtra_NWInterface_FTD2(TERMINATION):
  type: NETWORK_INTERFACE
  action:
    bind_to:
        - Del_PytestExtra-EC2-FTD
Del_PytestExtra_NWInterface_FTD3(TERMINATION):
  type: NETWORK_INTERFACE
  action:
    bind_to:
        - Del_PytestExtra-EC2-FTD

Del_PytestExtra_SUB_Sec_2_DATA(TERMINATION):
  type: SUBNET
  action:
    bind_to:
        - Del_PytestExtra_NWInterface_FTD2
Del_PytestExtra_SUB_Sec_3_DATA(TERMINATION):
  type: SUBNET
  action:
    bind_to:
        - Del_PytestExtra_NWInterface_FTD3

Del_PytestExtra-AMI-FTD(TERMINATION):
  # id: ami-0d846ab5ee3c4de5a
  type: AMICOPY
  action:
    bind_to:
        - Del_PytestExtra-EC2-FTD

Del_PytestExtra-EC2-FTD(TERMINATION):
  # id: i-0dfac8028eeb2df7c
  type: EC2INSTANCE       

PytestExtra-EC2-FTD(EC2INSTANCE):
  image-id: PytestExtra-AMI-FTD
  instance-type: d2.2xlarge
  key-name: testDog
  security-group-ids: Test-1-169_SG_Sec_MGMT
  count: 1
  subnet-id: Test-1-169_SUB_Sec_MGMT
  associate-public-ip-address: None
  private-ip-address: 20.0.250.22
  action:
    query_from:
        - Test-1-169_SUB_Sec_MGMT
        - Test-1-169_SG_Sec_MGMT
    bind_to:
        - PytestExtra-AMI-FTD
        - Del_PytestExtra-EC2-FTD
    cleanUP: True

PytestExtra-AMI-FTD(AMICOPY):
  source-image-id: ami-08473057344d9dd0d
  source-region: us-west-2
  region: us-west-1
  name: ftdv
  action:
    bind_to:
        - Del_PytestExtra-AMI-FTD
    cleanUP: True 

PytestExtra_SUB_Sec_2_DATA(SUBNET):   
  vpc-id: Test-1-169_VPC_Sec
  cidr-block: 20.0.22.0/24
  availability-zone: '{Test-1-169_SUB_App_1_MGMT}'
  action:
    query_from:
      - Test-1-169_VPC_Sec
      - Test-1-169_SUB_App_1_MGMT
    bind_to:
      - Del_PytestExtra_SUB_Sec_2_DATA
      - PytestExtra_SUB_Sec_3_DATA
    cleanUP: True
PytestExtra_SUB_Sec_3_DATA(SUBNET):
  vpc-id: Test-1-169_VPC_Sec
  cidr-block: 20.0.23.0/24
  availability-zone: '{Test-1-169_SUB_App_1_MGMT}'
  action:
    query_from:
      - Test-1-169_VPC_Sec
      - Test-1-169_SUB_App_1_MGMT  
    bind_to:
      - Del_PytestExtra_SUB_Sec_3_DATA 
    cleanUP: True

PytestExtra_NWInterface_FTD1(NETWORK_INTERFACE):
  subnet-id: Test-1-169_SUB_Sec_DATA
  description: pytest Data Network for ASA
  groups: Test-1-169_SG_Sec_DATA
  private-ip-address: 20.0.1.122
  action:
    query_from:
        - Test-1-169_SUB_Sec_DATA
        - Test-1-169_SG_Sec_DATA
    bind_to:
        - Del_PytestExtra_NWInterface_FTD1
    cleanUP: True
PytestExtra_NWInterface_FTD2(NETWORK_INTERFACE):
  subnet-id: PytestExtra_SUB_Sec_2_DATA
  description: Test-1-169 Data Network2 for ASA
  groups: Test-1-169_SG_Sec_DATA
  private-ip-address: 20.0.22.102
  action:
    query_from:
        - Test-1-169_SG_Sec_DATA
    bind_to:
        - PytestExtra_SUB_Sec_2_DATA
        - Del_PytestExtra_NWInterface_FTD2
    cleanUP: True
PytestExtra_NWInterface_FTD3(NETWORK_INTERFACE):
  subnet-id: PytestExtra_SUB_Sec_3_DATA
  description: Test-1-169 Data Network3 for ASA
  groups: Test-1-169_SG_Sec_DATA
  private-ip-address: 20.0.23.102
  action:
    query_from:
        - Test-1-169_SG_Sec_DATA
    bind_to:
        - PytestExtra_SUB_Sec_3_DATA
        - Del_PytestExtra_NWInterface_FTD3
    cleanUP: True

PytestExtra_NWInterface_FTD_1_Bind(BIND):
  network-interface-id: PytestExtra_NWInterface_FTD1
  instance-id: PytestExtra-EC2-FTD
  device-index: 1
  action:
    bind_to:
      - PytestExtra_NWInterface_FTD1
      - PytestExtra-EC2-FTD
      - PytestExtra_NWInterface_FTD_3_Bind
    cleanUP: True
PytestExtra_NWInterface_FTD_2_Bind(BIND):
  network-interface-id: PytestExtra_NWInterface_FTD2
  instance-id: PytestExtra-EC2-FTD
  device-index: 2
  action:
    bind_to:
      - PytestExtra_NWInterface_FTD2
      - PytestExtra-EC2-FTD
      - PytestExtra_NWInterface_FTD_1_Bind
    cleanUP: True
PytestExtra_NWInterface_FTD_3_Bind(BIND):
  network-interface-id: PytestExtra_NWInterface_FTD3
  instance-id: PytestExtra-EC2-FTD
  device-index: 3
  action:
    bind_to:
      - PytestExtra_NWInterface_FTD3
      - PytestExtra-EC2-FTD
    cleanUP: True
'''
    obj = aws(record=False, debug=True)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

# @pytest.mark.runman
# def test_runman():
#     aws.runman("aws_cli_runman")
#
# @pytest.mark.runmanterm
# def test_runman_term():
#     aws.runman("aws_runman_2021-05-17_07-14-18", "termination")

@pytest.mark.yijun_xfail
@pytest.mark.xfail(raises=ZeroDivisionError)
def test_f():
    3/2

@pytest.mark.timer
def test_f():
    print("start timer")
    timer("start")
    print("~~~~~~~1~~~~~~~")
    test_gg()
    print("~~~~~~~2~~~~~~~")
    time.sleep(10)

    timer("stop")

@pytest.mark.atexit
@pytest.mark.gg
def test_gg():
    print("ggggg")
    assert 2 == 2

@pytest.mark.atexit
@pytest.mark.xfail(raises=KeyError)
def test_atexit():
    print("\nqqqqq")
    atexit.register(test_gg)
    raise KeyError
    # atexit.register(test_gg)


@pytest.mark.yijun_skip
def test_function1():
    print("hello 1")
    # pytest.skip("我不干了")
    # pytest.skip("我不干了", allow_module_level=True)  和上面一样，估计进入 test后，就module skip不了了
    print("hello 2")

@pytest.mark.yijun_skip
def test_function2():
    print("hello 3")

@pytest.mark.func_yijun
def test_func1():
    print("\nfunc1")

@pytest.mark.func_yijun
def test_func2():
    test_func1()
    print("\nfunc2")

#....
def test_auto_config_CleanUp():
    obj = aws()