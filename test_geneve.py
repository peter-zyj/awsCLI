import os, sys
import re, hashlib,time
import atexit

import pytest

from awsAPIv2 import aws
from lib_yijun import *

def load_asa_config(asa_address):
    import pexpect

    # asa_address = "ssh -i 'testDog.pem' admin@3.142.241.180"

    conn = pexpect.spawn(asa_address)
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("en")
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("copy http://20.0.250.10/geneve.smp disk0:/.")
    conn, result, cont = Geneve_reply(conn, timeout=120)

    conn.sendline("conf term")
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("boot system disk0:/geneve.smp")
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("reload")
    conn, result, cont = Geneve_reply(conn)

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

@pytest.fixture(scope="module", autouse=True)
def setup(request):
    global setting, aws_obj
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

    aws_obj = aws(setting,debug=False)
    atexit.register(aws_obj.close)

    aws_obj.load_deployment(fileName="aws_tb_pytest_west_1.config")
    aws_obj.start_deployment()

    asa_ip = aws_obj.fetch_address("Test-EC2-ASA")
    asa_address = f"ssh -i 'testDog.pem' admin@{asa_ip}"

    load_asa_config(asa_address)

    def teardown():

        aws_obj.close()

        with open("/Users/yijunzhu/.aws/config", "r") as f:
            bytes_str = f.read().encode()
            md5_default_config_v = hashlib.md5(bytes_str).digest()
        with open("/Users/yijunzhu/.aws/credentials", "r") as f:
            bytes_str = f.read().encode()
            md5_default_credentials_v = hashlib.md5(bytes_str).digest()

        assert md5_default_config == md5_default_config_v
        assert md5_default_credentials == md5_default_credentials_v

    request.addfinalizer(teardown)

@pytest.mark.basic
def test_Basic_PingGoogle():
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    jb_ip = aws_obj.fetch_address("Test-EC2-App-JB")

    ssh.connect(jb_ip, username='ubuntu', password='', key_filename="testDog.pem")

    while True:
        _, stdout, _ = ssh.exec_command("ssh -i 'testDog.pem' -o StrictHostKeyChecking=no "
                                        "-o UserKnownHostsFile=/dev/null ubuntu@10.0.1.101 'ping 8.8.8.8 -c 1'")
        stdout.channel.recv_exit_status()
        resp1 = "".join(stdout.readlines())
        if not resp1:
            continue
        else:
            break

    assert "0% packet loss" in resp1
    ssh.close()


@pytest.mark.install
def test_apt_install():
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    jb_ip = aws_obj.fetch_address("Test-EC2-App-JB")

    ssh.connect(jb_ip, username='ubuntu', password='', key_filename="testDog.pem")

    while True:
        _, stdout, _ = ssh.exec_command("ssh -i 'testDog.pem' -o StrictHostKeyChecking=no "
                                        "-o UserKnownHostsFile=/dev/null ubuntu@10.0.1.101 'sudo apt install net-tools'")
        stdout.channel.recv_exit_status()
        resp1 = "".join(stdout.readlines())
        if not resp1:
            continue
        else:
            break


    while True:
        _, stdout2, _ = ssh.exec_command("ssh -i 'testDog.pem' -o StrictHostKeyChecking=no "
                                         "-o UserKnownHostsFile=/dev/null ubuntu@10.0.1.101 'ifconfig'")
        stdout2.channel.recv_exit_status()
        resp2 = "".join(stdout2.readlines())
        if not resp2:
            continue
        else:
            break

    assert "10.0.1.101" in resp2

    ssh.close()