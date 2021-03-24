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

@pytest.mark.deploy
def test_deploy():
    obj = aws(setting)
    atexit.register(obj.close)

    obj.load_deployment("aws_cli.config")
    obj.start_deployment()

    obj.res_record()
    obj.close()

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

#....
def test_auto_config_CleanUp():
    obj = aws()