import os, sys
import re, hashlib, time
import atexit
from scapy.all import *

import pytest

from awsAPIv3 import aws
from lib_yijun import *


def load_asa_config(asa_address, asa_jb_ip="20.0.250.10", debug=False):
    import pexpect

    conn = pexpect.spawn(asa_address)
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("en")
    conn, result, cont = Geneve_reply(conn)

    conn.sendline(f"copy http://{asa_jb_ip}/geneve.smp disk0:/")
    # conn.sendline(f"copy http://{asa_jb_ip}/geneve.smp disk0:/.") #the crap syntax is changing all the time
    conn, result, cont = Geneve_reply(conn, timeout=120, debug=debug)

    conn.sendline("conf term")
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("boot system disk0:/geneve.smp")
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("reload")
    conn, result, cont = Geneve_reply(conn, debug=debug)

    print('WAITED', wait(600))
    conn.close();
    del conn

    conn = pexpect.spawn(asa_address)
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("en")
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("conf term")
    conn, result, cont = Geneve_reply(conn)

    Geneve_load(conn, "pytest_day999.txt")

    conn.sendline("show run")
    conn, result, cont = Geneve_reply(conn)
    assert "20.0.1.101" in cont

def asa_config(asa_address, lines, debug=False) -> tuple:
    import pexpect

    conn = None
    while not conn:
        conn = pexpect.spawn(asa_address)
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("en")
    conn, result, cont = Geneve_reply(conn)

    conn.sendline("conf term")
    conn, result, cont = Geneve_reply(conn)

    conn.sendline(lines)
    conn, result, cont = Geneve_reply(conn, debug=debug)

    conn.close()
    del conn
    return result, cont

def ftd_hack(ftd_address, debug=False):
    import pexpect

    conn = None
    while not conn:
        conn = pexpect.spawn(ftd_address)
    conn, result, cont = Ocean_reply(conn, debug=debug)

    go2fxos(conn, debug=debug)
    conn.sendline("configure manager delete")
    conn, result, cont = Ocean_reply(conn, debug=debug)
    time.sleep(5)
    conn.sendline("configure manager add 20.0.250.13 cisco")
    conn, result, cont = Ocean_reply(conn, debug=debug)

    go2ftd(conn, debug=debug)

    conn.sendline("en")
    conn, result, cont = Ocean_reply(conn, debug=debug)

    conn.sendline("show version")
    conn, result, cont = Ocean_reply(conn, debug=debug)
    p = "Serial Number: (.*)"
    sn = re.compile(p).findall(cont)[0].strip()
    if debug: print(sn)

    go2expert(conn, debug=debug)

    cli = f"sudo echo -n '1111222233334444{sn}' | md5sum>/mnt/disk0/enable_configure"
    conn.sendline(cli)
    conn, result, cont = Ocean_reply(conn, debug=debug)

    if debug:
        cli = "cat /mnt/disk0/enable_configure"
        conn.sendline(cli)
        conn, result, cont = Ocean_reply(conn, debug=debug)
        print (cont)

    go2ftd(conn, debug=debug)

    conn.sendline("en")
    conn, result, cont = Ocean_reply(conn, debug=debug)
    conn.sendline("")
    Ocean_reply(conn, debug=debug)

    conn.sendline(f"debug menu file-system 7")
    conn, result, cont = Ocean_reply(conn, debug=debug)
    conn.sendline("")
    Ocean_reply(conn, debug=debug)

    conn.sendline(f"conf term")
    conn, result, cont = Ocean_reply(conn, debug=debug)
    conn.sendline("")
    conn, result, cont = Ocean_reply(conn, debug=debug)


    if "firepower(config)#" not in cont:
        print("[Error][ftd_hack] failed to hack")
        return

    conn.sendline(f"end")
    Ocean_reply(conn, debug=debug)

def ftd_config(ftd_address, lines, debug=False) -> tuple:
    import pexpect

    conn = None
    while not conn:
        conn = pexpect.spawn(ftd_address)
    conn, result, cont = Ocean_reply(conn, debug=debug)

    conn.sendline("system support diagnostic-cli")
    conn, result, cont = Ocean_reply(conn, debug=debug)

    conn.sendline("end")
    conn, result, cont = Ocean_reply(conn, debug=debug)

    conn.sendline("en")
    conn, result, cont = Ocean_reply(conn, debug=debug)

    conn.sendline("conf term")
    conn, result, cont = Ocean_reply(conn, debug=debug)

    for line in lines.splitlines():
        if line:
            conn.sendline(line)
            conn, result, cont = Ocean_reply(conn, debug=debug)

    conn.sendline("end")
    Ocean_reply(conn, debug=debug)

    conn.close()
    del conn
    return result, cont

def load_ftd_config(ftd_address, debug=False):
    import pexpect
    conn = pexpect.spawn(ftd_address)
    conn, result, cont = Ocean_reply(conn,debug=debug)

    go2ftd(conn, debug=debug)

    conn.sendline("en")
    conn, result, cont = Ocean_reply(conn,debug=debug)

    conn.sendline("conf term")
    conn, result, cont = Ocean_reply(conn,debug=debug)

    Ocean_load(conn, "pytest_day999FTD.txt",debug=debug)

    conn.sendline("show run")
    conn, result, cont = Ocean_reply(conn,debug=debug)
    assert "20.0.1.102" in cont

@pytest.fixture(scope="module", autouse=True)
def setup(request):
    skip_updown = request.config.option.skip_updown
    if skip_updown:
        print("\nsetup/teardown: skipped")
        return

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

    debug = request.config.option.trs
    aws_obj = aws(setting, debug=debug)
    atexit.register(aws_obj.close)

    aws_obj.load_deployment(fileName="aws_tb_pytest_west_1.config")
    aws_obj.start_deployment()

    Basic_miss_config()

    asa_ip = aws_obj.fetch_address("template-Hybrid-EC2-ASA")
    asa_address = f"ssh -i 'template-Key' admin@{asa_ip}"

    load_asa_config(asa_address, debug)

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


def Basic_miss_config():
    print("####Basic_miss_config test####")

    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run()

    cmd1 = "sudo ifconfig eth1 down"
    cmd2 = "sudo ifconfig eth1 10.0.1.10/24"
    cmd3 = "sudo ifconfig eth1 up"

    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh2 = paramiko.SSHClient()
    ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(app_jb_ip, username='ubuntu', password='', key_filename="template-Key")
    ssh2.connect(asa_jb_ip, username='ubuntu', password='', key_filename="template-Key")

    _, stdout, _ = ssh.exec_command(f"{cmd1};{cmd2};{cmd3}")
    stdout.channel.recv_exit_status()

    _, stdout, _ = ssh2.exec_command(f"{cmd1};{cmd2};{cmd3}")
    stdout.channel.recv_exit_status()

    ssh.close()
    ssh2.close()

    #~~~~~~~~~~

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # jb_ip = aws_obj.fetch_address("template-Hybrid-EC2-App-JB")

    ssh.connect(app_jb_ip, username='ubuntu', password='', key_filename="template-Key")

    while True:
        _, stdout, _ = ssh.exec_command("ssh -i 'template-Key' -o StrictHostKeyChecking=no "
                                        "-o UserKnownHostsFile=/dev/null ubuntu@10.0.1.101 'ping 8.8.8.8 -c 1'")
        stdout.channel.recv_exit_status()
        resp1 = "".join(stdout.readlines())
        if not resp1:
            continue
        else:
            break

    assert "100% packet loss" in resp1
    ssh.close()

@pytest.mark.config_ASAv
def test_config_ASA(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, _, _ = local_run

    asa_address = f"ssh -i 'template-Key' admin@{asa_ip}"

    load_asa_config(asa_address, debug=False)


@pytest.mark.config_FTDv
def test_config_FTD(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run

    ftd_address = f"ssh -i 'template-Key' admin@{ftd_ip}"

    ftd_hack(ftd_address)
    cmd = "conf term"
    res, cont = ftd_config(ftd_address, cmd)
    assert "firepower(config)#" in cont
    load_ftd_config(ftd_address, debug=False)

@pytest.mark.geneveASA
@pytest.mark.basic1to2
def test_Basic_PingGoogle(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, _, _ = local_run
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(app_jb_ip, username='ubuntu', password='', key_filename="template-Key")

    while True:
        _, stdout, _ = ssh.exec_command("ssh -i 'template-Key' -o StrictHostKeyChecking=no "
                                        "-o UserKnownHostsFile=/dev/null ubuntu@10.0.1.101 'ping 8.8.8.8 -c 1'")
        stdout.channel.recv_exit_status()
        resp1 = "".join(stdout.readlines())
        if not resp1:
            continue
        else:
            break

    assert "0% packet loss" in resp1
    ssh.close()

@pytest.mark.geneveASA
@pytest.mark.basic2to1
def test_Basic_PingApp(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, _, _ = local_run
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    asa_address = f"ssh -i 'template-Key' admin@{asa_ip}"

    access_list = f"access-list geneve extended permit icmp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, access_list)

    ssh.connect(app_jb_ip, username='ubuntu', password='', key_filename="template-Key")

    while True:
        _, stdout, _ = ssh.exec_command(f"ping {app_ip} -c 1")
        stdout.channel.recv_exit_status()
        resp1 = "".join(stdout.readlines())
        if not resp1:
            continue
        else:
            break

    assert "0% packet loss" in resp1

    no_access_list = f"no access-list geneve extended permit icmp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, no_access_list)
    ssh.close()

@pytest.mark.geneveASA
@pytest.mark.install1to2
def test_apt_install_from_outside(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, _, _ = local_run
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(app_jb_ip, username='ubuntu', password='', key_filename="template-Key")

    while True:
        _, stdout, _ = ssh.exec_command("ssh -i 'template-Key' -o StrictHostKeyChecking=no "
                                        "-o UserKnownHostsFile=/dev/null ubuntu@10.0.1.101 'sudo apt install net-tools'")
        stdout.channel.recv_exit_status()
        resp1 = "".join(stdout.readlines())
        if not resp1:
            continue
        else:
            break

    while True:
        _, stdout2, _ = ssh.exec_command("ssh -i 'template-Key' -o StrictHostKeyChecking=no "
                                         "-o UserKnownHostsFile=/dev/null ubuntu@10.0.1.101 'ifconfig'")
        stdout2.channel.recv_exit_status()
        resp2 = "".join(stdout2.readlines())
        if not resp2:
            continue
        else:
            break

    assert "10.0.1.101" in resp2

    ssh.close()

@pytest.mark.geneveASA
@pytest.mark.install2to1
def test_apt_install_from_inside(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, _, _ = local_run
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    asa_address = f"ssh -i 'template-Key' admin@{asa_ip}"

    access_list = f"access-list geneve extended permit tcp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, access_list)

    ssh.connect(app_jb_ip, username='ubuntu', password='', key_filename="template-Key")

    while True:
        _, stdout, _ = ssh.exec_command("ssh -i 'testDog.pem' -o StrictHostKeyChecking=no "
                                        "-o UserKnownHostsFile=/dev/null ubuntu@10.0.1.101 'sudo apt update'")
        stdout.channel.recv_exit_status()
        resp1 = "".join(stdout.readlines())
        if not resp1:
            continue
        else:
            break

    while True:
        _, stdout, _ = ssh.exec_command("ssh -i 'template-Key' -o StrictHostKeyChecking=no "
                                        "-o UserKnownHostsFile=/dev/null ubuntu@10.0.1.101 'sudo apt install apache2 -y'")
        stdout.channel.recv_exit_status()
        resp1 = "".join(stdout.readlines())
        if not resp1:
            continue
        else:
            break

    while True:
        _, stdout2, _ = ssh.exec_command(f"wget http://{app_ip}/index.html; ls index.html")

        stdout2.channel.recv_exit_status()
        resp2 = "".join(stdout2.readlines())
        if not resp2:
            continue
        else:
            break

    assert "No such file or directory" not in resp2

    no_access_list = f"no access-list geneve extended permit tcp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, no_access_list)
    ssh.close()


@pytest.mark.pyserver
def test_PYSERVER(skip_updown):
    print("skip_updown:", skip_updown)

    # 1. transfer server file
    cmd1 = "scp -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@13.57.178.96:/home/ubuntu/."
    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@13.57.178.96 'scp -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@13.52.150.43:/home/ubuntu/.'"
    os.popen(cmd2).read()

    cmd3 = "scp -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@13.57.48.179:/home/ubuntu/."
    os.popen(cmd3).read()

@pytest.mark.geneveASA
@pytest.mark.tcp
@pytest.mark.tcp1to2
def test_TCP23_from_outside(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, _, _ = local_run

    asa_address = f"ssh -i 'template-Key' admin@{asa_ip}"
    acl_config = f"access-list geneve extended permit tcp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, acl_config)

    # 1. transfer server file
    cmd1 = "scp -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"Pytest_server.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'scp -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@10.0.1.101:/home/ubuntu/.'"
    os.popen(cmd2).read()

    # 2. run server file
    cmd_k = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
            f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
            "ubuntu@10.0.1.101 \'sudo pkill python3\''"

    os.popen(cmd_k).read()

    cmd3 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo screen -d -m sudo python3 Pytest_server.py\''"

    os.popen(cmd3).read()

    # 3. test
    test = f"""
import socket
s=socket.socket()
s.connect(("{app_ip}",23))
s.send("Yijun is coming".encode())
msg = s.recv(1024)
print(msg)
    """
    with open("test.py", "w+") as f:
        f.write(test)

    cmd4 = "scp -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"test.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd4).read()

    cmd5 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill python3;python3 test.py'"
    resp = os.popen(cmd5).read()

    assert "[Pytest]TCP:23 is back!" in resp

    # # terminate server
    cmd6 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo rm -rf test.py'"
    os.popen(cmd6).read()

    cmd7 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo pkill python3\''"

    os.popen(cmd7).read()

    no_acl_config = f"no access-list geneve extended permit tcp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, no_acl_config)

@pytest.mark.geneveASA
@pytest.mark.tcp
@pytest.mark.tcp2to1
def test_TCP23_from_inside(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, _, _ = local_run

    # 1. transfer server file
    cmd1 = "scp -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"Pytest_server.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'scp -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@10.0.1.101:/home/ubuntu/.'"
    os.popen(cmd2).read()

    # 2. run server file
    cmd3 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill python3;sudo screen -d -m sudo python3 Pytest_server.py'"

    os.popen(cmd3).read()

    # 3. test
    test = f"""
import socket
s=socket.socket()
s.connect(("{app_jb_ip}",23))
s.send("Yijun is coming".encode())
msg = s.recv(1024)
print(msg)
    """
    with open("test.py", "w+") as f:
        f.write(test)

    cmd4 = "scp -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"test.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd4).read()

    cmd4_2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             f"ubuntu@{app_jb_ip} 'scp -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             "test.py ubuntu@10.0.1.101:/home/ubuntu/.'"

    os.popen(cmd4_2).read()

    cmd5 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo pkill python3;python3 test.py\''"
    resp = os.popen(cmd5).read()

    assert "[Pytest]TCP:23 is back!" in resp

    # # terminate server
    cmd6 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo rm -rf test.py'"
    os.popen(cmd6).read()

    cmd6_2 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             "ubuntu@10.0.1.101 \'sudo rm -rf test.py\''"
    os.popen(cmd6_2).read()

    cmd7 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill python3'"

    os.popen(cmd7).read()

@pytest.fixture()
def local_run(show=False):

    if "aws_obj" not in globals():
        aws_obj = aws(record=False)

    app_jb = aws_obj.blind("template-Hybrid-EC2-App-JB", "EC2INSTANCE", show=show)
    asa_jb = aws_obj.blind("template-Hybrid-EC2-HBD-JB", "EC2INSTANCE", show=show)
    asa = aws_obj.blind("template-Hybrid-EC2-ASA", "EC2INSTANCE", show=show)
    app = aws_obj.blind("template-Hybrid-EC2-App", "EC2INSTANCE", show=show)
    ftd = aws_obj.blind("template-Hybrid-EC2-FTD", "EC2INSTANCE", show=show)
    fmc = aws_obj.blind("template-Hybrid-EC2-FMC", "EC2INSTANCE", show=show)


    app_jb_ip = app_jb["public_ip"]
    asa_jb_ip = asa_jb["public_ip"]
    asa_ip = asa["public_ip"]
    app_ip = app["public_ip"]
    ftd_ip = ftd["public_ip"]
    fmc_ip = fmc["public_ip"]


    yield app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip
    aws_obj.close()


@pytest.fixture()
def acl_config(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, _, _ = local_run

    asa_address = f"ssh -i 'template-Key' admin@{asa_ip}"
    acl_config = f"access-list geneve extended permit udp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, acl_config)

    yield

    no_acl_config = f"no access-list geneve extended permit udp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, no_acl_config)

@pytest.mark.geneveASA
@pytest.mark.udpYijun
def test_UDP666(local_run, acl_config):

    app_jb_ip, asa_jb_ip, asa_ip, app_ip, _, _ = local_run

    # asa_address = f"ssh -i 'template-Key' admin@{asa_ip}"
    # acl_config = f"access-list geneve extended permit udp host {app_jb_ip} host 10.0.1.101"
    # asa_config(asa_address, acl_config)

    # 1. transfer server file
    cmd1 = "scp -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"Pytest_server.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'scp -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@10.0.1.101:/home/ubuntu/.'"
    os.popen(cmd2).read()

    # 2. run server file
    cmd3 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo screen -d -m sudo python3 Pytest_server.py\''"

    os.popen(cmd3).read()

    # 3. test
    test = f"""
import socket
s=socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
s.sendto("Yijun is coming".encode(), ("{app_ip}", 666))
msg = s.recvfrom(1024)
print(msg[0])
    """
    with open("test.py", "w+") as f:
        f.write(test)

    cmd4 = "scp -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"test.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd4).read()

    cmd5 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo python3 test.py'"
    resp = os.popen(cmd5).read()

    assert "[Pytest]UDP:666 is back!" in resp

    # # terminate server
    cmd6 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo rm -rf test.py'"
    os.popen(cmd6).read()

    cmd7 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo pkill python3\''"

    os.popen(cmd7).read()

    # no_acl_config = f"no access-list geneve extended permit udp host {app_jb_ip} host 10.0.1.101"
    # asa_config(asa_address, no_acl_config)

@pytest.mark.geneveASA
@pytest.mark.udp1to2
def test_UDP_from_inside(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, _, _ = local_run

    asa_address = f"ssh -i 'template-Key' admin@{asa_ip}"
    acl_config = f"access-list geneve extended permit udp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, acl_config)

    # 1. transfer server file
    cmd1 = "scp -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"Pytest_server.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'scp -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@10.0.1.101:/home/ubuntu/.'"
    os.popen(cmd2).read()

    # 2. run server file
    cmd_k = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
            f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
            "ubuntu@10.0.1.101 \'sudo pkill python3\''"

    os.popen(cmd_k).read()
    cmd3 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo screen -d -m sudo python3 Pytest_server.py\''"

    os.popen(cmd3).read()

    # 3. test
    test = f"""
import socket
s=socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
s.sendto("Yijun is coming".encode(), ("{app_ip}", 666))
msg = s.recvfrom(1024)
print(msg[0])
    """
    with open("test.py", "w+") as f:
        f.write(test)

    cmd4 = "scp -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"test.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd4).read()

    cmd5 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill python3;python3 test.py'"
    resp = os.popen(cmd5).read()

    assert "[Pytest]UDP:666 is back!" in resp

    # # terminate server
    cmd6 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo rm -rf test.py'"
    os.popen(cmd6).read()

    cmd7 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo pkill python3\''"

    os.popen(cmd7).read()

    no_acl_config = f"no access-list geneve extended permit udp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, no_acl_config)

@pytest.mark.geneveASA
@pytest.mark.udp2to1
def test_UDP_from_outside(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, _, _ = local_run

    # 1. transfer server file
    cmd1 = "scp -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"Pytest_server.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'scp -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@10.0.1.101:/home/ubuntu/.'"
    os.popen(cmd2).read()

    # 2. run server file
    cmd3 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill python3;sudo screen -d -m sudo python3 Pytest_server.py'"

    os.popen(cmd3).read()

    # 3. test
    test = f"""
import socket,os
s=socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
s.sendto("Yijun is coming".encode(), ("{app_jb_ip}", 666))
msg = s.recvfrom(1024)
print(msg[0])
    """
    with open("test.py", "w+") as f:
        f.write(test)

    cmd4 = "scp -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"test.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd4).read()

    cmd4_2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             f"ubuntu@{app_jb_ip} 'scp -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             "test.py ubuntu@10.0.1.101:/home/ubuntu/.'"
    os.popen(cmd4_2).read()

    cmd5 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo python3 test.py; pkill python3\''"
    print(cmd5)
    resp = os.popen(cmd5).read()
    assert "[Pytest]UDP:666 is back!" in resp

    # # terminate server
    cmd6 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo rm -rf test.py'"
    os.popen(cmd6).read()

    cmd6_2 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             "ubuntu@10.0.1.101 \'sudo rm -rf test.py\''"
    os.popen(cmd6_2).read()

    cmd7 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill python3'"

    os.popen(cmd7).read()

@pytest.mark.geneveASA
@pytest.mark.iperfudp
def test_iperf_udp(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, _, _ = local_run

    asa_address = f"ssh -i 'template-Key' admin@{asa_ip}"
    acl_config = f"access-list geneve extended permit udp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, acl_config)

    cmd1 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo screen -d -m sudo iperf -s -u'"

    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@10.0.1.101 \'sudo iperf -c {app_jb_ip} -u\''"

    res = os.popen(cmd2).read()

    bd = re.compile(" ([\d.]+?) (?=MBytes)").findall(res)[0]
    assert float(bd) > 0

    cmd3 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill iperf'"

    os.popen(cmd3).read()

    no_acl_config = f"no access-list geneve extended permit udp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, no_acl_config)

@pytest.mark.geneveASA
@pytest.mark.iperfudpreverse
def test_iperf_udp_reverse(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, _, _ = local_run

    asa_address = f"ssh -i 'template-Key' admin@{asa_ip}"
    acl_config = f"access-list geneve extended permit udp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, acl_config)

    cmd1 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@10.0.1.101 \'sudo screen -d -m sudo iperf -s -u\''"

    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo iperf -c {app_ip} -u;'"

    res = os.popen(cmd2).read()
    print("Iperf result:\n", res)

    bd = re.compile(" ([\d.]+?) (?=MBytes)").findall(res)[0]
    assert float(bd) > 0
    cmd3 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@10.0.1.101 \'sudo pkill iperf\''"

    os.popen(cmd3).read()

    no_acl_config = f"no access-list geneve extended permit udp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, no_acl_config)

@pytest.mark.geneveASA
@pytest.mark.iperftcp
def test_iperf_tcp(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, _, _ = local_run

    asa_address = f"ssh -i 'template-Key' admin@{asa_ip}"
    acl_config = f"access-list geneve extended permit tcp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, acl_config)

    cmd1 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo screen -d -m sudo iperf -s'"

    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@10.0.1.101 \'sudo iperf -c {app_jb_ip}\''"

    res = os.popen(cmd2).read()

    try:
        bd = re.compile(" ([\d.]+?) (?=MBytes)").findall(res)[0]
    except:
        bd = re.compile(" ([\d.]+?) (?=GBytes)").findall(res)[0]

    assert float(bd) > 0

    cmd3 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill iperf'"

    os.popen(cmd3).read()

    no_acl_config = f"no access-list geneve extended permit tcp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, no_acl_config)

@pytest.mark.geneveASA
@pytest.mark.iperftcpreverse
def test_iperf_tcp_reverse(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, _, _ = local_run

    asa_address = f"ssh -i 'template-Key' admin@{asa_ip}"
    acl_config = f"access-list geneve extended permit tcp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, acl_config)

    cmd1 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@10.0.1.101 \'sudo screen -d -m sudo iperf -s\''"

    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo iperf -c {app_ip}'"

    res = os.popen(cmd2).read()

    print("Iperf result:\n", res)
    try:
        bd = re.compile(" ([\d.]+?) (?=MBytes)").findall(res)[0]
    except:
        bd = re.compile(" ([\d.]+?) (?=GBytes)").findall(res)[0]
    assert float(bd) > 0

    cmd3 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@10.0.1.101 \'sudo pkill iperf\''"

    os.popen(cmd3).read()

    no_acl_config = f"no access-list geneve extended permit tcp host {app_jb_ip} host 10.0.1.101"
    asa_config(asa_address, no_acl_config)

@pytest.mark.geneveASA
@pytest.mark.counter
def test_udp_counter(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, _, _ = local_run
    cmd1 = "clear asp drop"
    cmd2 = "show asp drop frame geneve-invalid-udp-checksum"

    asa_address = f"ssh -i 'template-Key' admin@{asa_ip}"
    asa_config(asa_address, cmd1)

    send(IP(dst="20.0.1.101") / UDP(sport=20001, dport=6081, chksum=0) / b'\x08\x00\x08')

    _, res = asa_config(asa_address, cmd2)
    assert "geneve-invalid-udp-checksum" in res

@pytest.mark.geneveASA
@pytest.mark.reset
def test_tcp_counter(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, _, _ = local_run

    cmd = f"ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
          f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
          f"ubuntu@10.0.1.101 \'sudo screen -d -m ssh root@{asa_jb_ip}\''"

    os.popen(cmd).read()

    cmd2 = "clear conn address 10.0.1.101"
    cmd3 = "show asp drop"
    cmd1 = "clear asp drop"

    asa_address = f"ssh -i 'template-Key' admin@{asa_ip}"
    asa_config(asa_address, cmd1)
    asa_config(asa_address, cmd2)

    cmd = f"ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
          f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
          f"ubuntu@10.0.1.101 \'sudo pkill screen\''"

    os.popen(cmd).read()

    _, res = asa_config(asa_address, cmd3)

    assert "tcp-not-syn" in res

@pytest.mark.geneveASA
@pytest.mark.logserver
def test_log_server(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, _, _ = local_run
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh2 = paramiko.SSHClient()
    ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(app_jb_ip, username='ubuntu', password='', key_filename="template-Key")
    ssh2.connect(asa_jb_ip, username='ubuntu', password='', key_filename="template-Key")

    while True:
        _, stdout, _ = ssh.exec_command("ssh -i 'template-Key' -o StrictHostKeyChecking=no "
                                        "-o UserKnownHostsFile=/dev/null ubuntu@10.0.1.101 'ping 8.8.8.8 -c 10'")
        stdout.channel.recv_exit_status()
        resp1 = "".join(stdout.readlines())
        if not resp1:
            continue
        else:
            break

    assert "0% packet loss" in resp1

    _, stdout, _ = ssh2.exec_command("sudo systemctl restart syslog")
    stdout.channel.recv_exit_status()
    while True:
        _, stdout, _ = ssh2.exec_command("tail -n 100 /var/log/syslog")
        stdout.channel.recv_exit_status()
        resp2 = "".join(stdout.readlines())
        if not resp2:
            continue
        else:
            break

    assert "8.8.8.8" in resp2

    ssh.close()
    ssh2.close()

@pytest.mark.geneveASA
@pytest.mark.genevedebug
def test_debug_geneve(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, _, _ = local_run
    cmd1 = "debug geneve encapsulation"
    cmd2 = "debug geneve encapsulation 4"
    cmd3 = "debug geneve decapsulation"
    cmd4 = "debug geneve decapsulation 4"
    cmd5 = "debug geneve all"
    cmd_clean = "unde all"
    cmd_show = "show debug"

    asa_address = f"ssh -i 'template-Key' admin@{asa_ip}"

    import pexpect

    conn = pexpect.spawn(asa_address)
    Geneve_reply(conn)

    conn.sendline("en")
    Geneve_reply(conn)

    conn.sendline(cmd_clean)
    Geneve_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Geneve_reply(conn)
    assert "debug geneve" not in res

    conn.sendline(cmd_clean)
    Geneve_reply(conn)
    conn.sendline(cmd1)
    Geneve_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Geneve_reply(conn)
    assert "debug geneve encapsulation enabled at level 1" in res

    conn.sendline(cmd_clean)
    Geneve_reply(conn)
    conn.sendline(cmd2)
    Geneve_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Geneve_reply(conn)
    assert "debug geneve encapsulation enabled at level 4" in res

    conn.sendline(cmd_clean)
    Geneve_reply(conn)
    conn.sendline(cmd3)
    Geneve_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Geneve_reply(conn)
    assert "debug geneve decapsulation enabled at level 1" in res

    conn.sendline(cmd_clean)
    Geneve_reply(conn)
    conn.sendline(cmd4)
    Geneve_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Geneve_reply(conn)
    assert "debug geneve decapsulation enabled at level 4" in res

    conn.sendline(cmd_clean)
    Geneve_reply(conn)
    conn.sendline(cmd5)
    Geneve_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Geneve_reply(conn)
    assert "debug geneve encapsulation enabled at level 1" in res
    assert "debug geneve decapsulation enabled at level 1" in res

    conn.sendline(cmd_clean)
    Geneve_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Geneve_reply(conn)
    assert "debug geneve" not in res

    conn.close()
    del conn

@pytest.mark.geneveASA
@pytest.mark.metaserver
def test_meta(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, _, _ = local_run
    cmd1 = "no aaa authentication listener http data-interface port www"
    cmd2 = "nat (data-interface,data-interface) source static gwlb interface destination static interface metadata service http80 http80"

    asa_address = f"ssh -i 'template-Key' admin@{asa_ip}"
    asa_config(asa_address, cmd1)
    asa_config(asa_address, cmd2)
    time.sleep(20)
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(app_jb_ip, username='ubuntu', password='', key_filename="template-Key")

    while True:
        _, stdout, _ = ssh.exec_command("ssh -i 'template-Key' -o StrictHostKeyChecking=no "
                                        "-o UserKnownHostsFile=/dev/null ubuntu@10.0.1.101 'ping 8.8.8.8 -c 1'")
        stdout.channel.recv_exit_status()
        resp1 = "".join(stdout.readlines())
        if not resp1:
            continue
        else:
            break

    assert "0% packet loss" in resp1
    ssh.close()

@pytest.mark.geneveASA
@pytest.mark.statistics
def test_stats(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, _, _ = local_run
    cmd1 = "show interface vni 1"
    cmd2 = "show nve 1"
    asa_address = f"ssh -i 'template-Key' admin@{asa_ip}"

    _, cont1_1 = asa_config(asa_address, cmd1)
    _, cont2_1 = asa_config(asa_address, cmd2)
    p1 = "(.*) packets input"
    p2 = "(.*) packets output"

    output_cmd1_1 = int(re.compile(p1).findall(cont1_1)[0])
    output_cmd2_1 = int(re.compile(p2).findall(cont2_1)[0])

    test_Basic_PingGoogle(local_run)

    _, cont1_2 = asa_config(asa_address, cmd1)
    _, cont2_2 = asa_config(asa_address, cmd2)

    output_cmd1_2 = int(re.compile(p1).findall(cont1_2)[0])
    output_cmd2_2 = int(re.compile(p2).findall(cont2_2)[0])

    assert output_cmd1_2 > output_cmd1_1
    assert output_cmd2_2 > output_cmd2_1

@pytest.mark.geneveASA
@pytest.mark.capture
def test_capture(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, _, _ = local_run
    cmd0 = "no capture g"
    cmd1 = "clear cap /all"
    cmd2 = "cap g int ge trace"
    cmd3 = "show capture g | in icmp: echo request"
    asa_address = f"ssh -i 'template-Key' admin@{asa_ip}"

    asa_config(asa_address, cmd0)
    asa_config(asa_address, cmd1)
    asa_config(asa_address, cmd2)
    test_Basic_PingGoogle(local_run)
    time.sleep(1)
    _, cont3 = asa_config(asa_address, cmd3)
    pNum = int(re.compile("\d+: ").findall(cont3)[0].strip().split(":")[0])
    cmd4 = f"show capture g trace packet-number {pNum}"
    cmd5 = "no capture g"
    _, cont4 = asa_config(asa_address, cmd4)
    assert "Action: allow" in cont4
    asa_config(asa_address, cmd5)

@pytest.mark.regASA
def test_reg_asa():
    cont="""
Del_template-Hybrid_TG_ASA(TERMINATION):
  target-group-arn: template-Hybrid-TG
  targets: Id=template-Hybrid_NWInterface_ASA
  type: REGISTER
  action:
    query_from:
      - template-Hybrid-TG
      - template-Hybrid_NWInterface_ASA     

Del_template-Hybrid_TG_FTD(TERMINATION):
  target-group-arn: template-Hybrid-TG
  targets: Id=Pytest_NWInterface_FTD1
  type: REGISTER
  action:
    query_from:
      - template-Hybrid-TG
      - Pytest_NWInterface_FTD1

template-Hybrid_TG_Instance(REGISTER):
  target-group-arn: template-Hybrid-TG
  targets: Id=template-Hybrid_NWInterface_ASA
  action:
    query_from:
      - template-Hybrid-TG
      - template-Hybrid_NWInterface_ASA        
    bind_to:
      - Del_template-Hybrid_TG_FTD
      - Del_template-Hybrid_TG_ASA
    cleanUP: True
"""
    obj = aws(debug=True)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

@pytest.mark.regFTD
def test_reg_ftd():
    cont = """
Del_template-Hybrid_TG_ASA(TERMINATION):
  target-group-arn: template-Hybrid-TG
  targets: Id=template-Hybrid_NWInterface_ASA
  type: REGISTER
  action:
    query_from:
      - template-Hybrid-TG
      - template-Hybrid_NWInterface_ASA     

Del_template-Hybrid_TG_FTD(TERMINATION):
  target-group-arn: template-Hybrid-TG
  targets: Id=Pytest_NWInterface_FTD1
  type: REGISTER
  action:
    query_from:
      - template-Hybrid-TG
      - Pytest_NWInterface_FTD1

template-Hybrid_TG_Instance(REGISTER):
  target-group-arn: template-Hybrid-TG
  targets: Id=Pytest_NWInterface_FTD1
  action:
    query_from:
      - template-Hybrid-TG
      - Pytest_NWInterface_FTD1        
    bind_to:
      - Del_template-Hybrid_TG_FTD
      - Del_template-Hybrid_TG_ASA
    cleanUP: True
    """
    obj = aws(debug=True)
    atexit.register(obj.close)

    obj.load_deployment(content=cont)
    obj.start_deployment()

@pytest.mark.hackFTD
def test_ftd_backdoor(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run
    ftd_address = f"ssh -i 'template-Key' admin@{ftd_ip}"
    ftd_hack(ftd_address)
    cmd = "conf term"
    res, cont = ftd_config(ftd_address, cmd)

    assert "firepower(config)#" in cont

@pytest.mark.FMCreg
def test_fmc_reg(local_run):
# def test_fmc_reg():
    from selenium import webdriver
    from selenium.webdriver.common.by import By

    timer = 5
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run
    # fmc_ip = "52.53.155.170"
    driver = webdriver.Chrome("/Users/yijunzhu/PycharmProjects/iTest/Geneve/chromedriver")

    try:
        driver.get(f"https://{fmc_ip}/ui/login")
        driver.find_element(By.ID, "details-button").click()
        driver.find_element(By.ID, "proceed-link").click()
    except:
        pass
    time.sleep(timer)# wait, otherwise can't find bd-2
    driver.get(f"https://{fmc_ip}/ui/login")
    driver.find_element(By.ID, "bd-2").send_keys("admin")
    driver.find_element(By.ID, "bd-5").send_keys("Cisco123!@#")
    driver.find_element(By.CSS_SELECTOR, ".atomic-btn").click()
    time.sleep(timer)
    try:
        driver.find_element(By.CSS_SELECTOR, ".atomic-btn:nth-child(2)").click()
    except:
        pass
    time.sleep(timer)


    driver.find_element(By.LINK_TEXT, "Devices").click()
    time.sleep(timer)
    driver.find_element(By.LINK_TEXT, "Device Management").click()
    time.sleep(timer)
    driver.find_element(By.CSS_SELECTOR, "#gwt-debug-device_management-add_dropdown-add .x-btn-text").click()
    driver.find_element(By.ID, "gwt-debug-device_management-device-add").click()
    time.sleep(timer)
    driver.find_element(By.ID, "gwt-debug-device_registration-host-text_field-input").send_keys("20.0.250.12")


    driver.find_element(By.ID, "gwt-debug-device_registration-display_name-text_field-input").click()
    driver.find_element(By.ID, "gwt-debug-device_registration-registration_key-text_field-input").send_keys("cisco")

    driver.find_element(By.ID, "gwt-debug-device_registration-access_control_policy-combobox-input").click()
    time.sleep(timer)
    driver.find_element(By.XPATH, '//div[text()="default_yijun"]').click()

    driver.find_element(By.ID, "gwt-debug-device_registration-license_tiers-combobox-input").click()
    time.sleep(timer)
    driver.find_element(By.XPATH, '//div[text()="FTDv20 - Tiered (Core 4 / 8 GB)"]').click()


    time.sleep(timer)
    check1 = driver.find_element(By.XPATH, '//fieldset[@class=" x-fieldset x-component"]//label[text()="Malware"]')
    check2 = driver.find_element(By.XPATH, '//fieldset[@class=" x-fieldset x-component"]//label[text()="Threat"]')
    check3 = driver.find_element(By.XPATH, '//fieldset[@class=" x-fieldset x-component"]//label[text()="URL Filtering"]')

    check1_id = str(check1.get_attribute("htmlfor"))
    check2_id = str(check2.get_attribute("htmlfor"))
    check3_id = str(check3.get_attribute("htmlfor"))

    driver.find_element(By.ID, check1_id).click()
    driver.find_element(By.ID, check2_id).click()
    driver.find_element(By.ID, check3_id).click()
    time.sleep(timer)
    driver.find_element(By.CSS_SELECTOR, "#gwt-debug-device_registration-register-button .x-btn-text").click()

    time.sleep(5)

@pytest.mark.FTDconfig
def test_ftd_config(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run
    ftd_address = f"ssh -i 'template-Key' admin@{ftd_ip}"
    load_ftd_config(ftd_address, debug=False)

@pytest.mark.geneveFTD
@pytest.mark.FTDmetaserver
@pytest.mark.FTDbasic1to2
def test_Basic_PingGoogle_FTD(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run
    # test_reg_ftd()
    # print('WAIT for FTD register', wait(90))
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(app_jb_ip, username='ubuntu', password='', key_filename="template-Key")

    while True:
        _, stdout, _ = ssh.exec_command("ssh -i 'template-Key' -o StrictHostKeyChecking=no "
                                        "-o UserKnownHostsFile=/dev/null ubuntu@10.0.1.101 'ping 8.8.8.8 -c 1'")
        stdout.channel.recv_exit_status()
        resp1 = "".join(stdout.readlines())
        if not resp1:
            continue
        else:
            break

    assert "0% packet loss" in resp1
    ssh.close()

@pytest.mark.geneveFTD
@pytest.mark.FTDbasic2to1
def test_Basic_PingApp_FTD(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(app_jb_ip, username='ubuntu', password='', key_filename="template-Key")

    while True:
        _, stdout, _ = ssh.exec_command(f"ping {app_ip} -c 1")
        stdout.channel.recv_exit_status()
        resp1 = "".join(stdout.readlines())
        if not resp1:
            continue
        else:
            break

    assert "0% packet loss" in resp1

    ssh.close()

@pytest.mark.geneveFTD
@pytest.mark.FTDinstall1to2
def test_apt_install_from_outside_FTD(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(app_jb_ip, username='ubuntu', password='', key_filename="template-Key")

    while True:
        _, stdout, _ = ssh.exec_command("ssh -i 'template-Key' -o StrictHostKeyChecking=no "
                                        "-o UserKnownHostsFile=/dev/null ubuntu@10.0.1.101 'sudo apt install net-tools'")
        stdout.channel.recv_exit_status()
        resp1 = "".join(stdout.readlines())
        if not resp1:
            continue
        else:
            break

    while True:
        _, stdout2, _ = ssh.exec_command("ssh -i 'template-Key' -o StrictHostKeyChecking=no "
                                         "-o UserKnownHostsFile=/dev/null ubuntu@10.0.1.101 'ifconfig'")
        stdout2.channel.recv_exit_status()
        resp2 = "".join(stdout2.readlines())
        if not resp2:
            continue
        else:
            break

    assert "10.0.1.101" in resp2

    ssh.close()

@pytest.mark.geneveFTD
@pytest.mark.FTDinstall2to1
def test_apt_install_from_inside_FTD(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(app_jb_ip, username='ubuntu', password='', key_filename="template-Key")

    while True:
        _, stdout, _ = ssh.exec_command("ssh -i 'template-Key' -o StrictHostKeyChecking=no "
                                        "-o UserKnownHostsFile=/dev/null ubuntu@10.0.1.101 'sudo apt install apache2 -y'")
        stdout.channel.recv_exit_status()
        resp1 = "".join(stdout.readlines())
        if not resp1:
            continue
        else:
            break

    while True:
        _, stdout2, _ = ssh.exec_command(f"wget http://{app_ip}/index.html; ls index.html")

        stdout2.channel.recv_exit_status()
        resp2 = "".join(stdout2.readlines())
        if not resp2:
            continue
        else:
            break

    assert "No such file or directory" not in resp2

    ssh.close()

@pytest.mark.geneveFTD
@pytest.mark.FTDtcp1to2
def test_TCP23_from_outside_FTD(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run

    # 1. transfer server file
    cmd1 = "scp -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"Pytest_server.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'scp -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@10.0.1.101:/home/ubuntu/.'"
    os.popen(cmd2).read()

    # 2. run server file
    cmd_k = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
            f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
            "ubuntu@10.0.1.101 \'sudo pkill python3\''"

    os.popen(cmd_k).read()

    cmd3 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo screen -d -m sudo python3 Pytest_server.py\''"

    os.popen(cmd3).read()

    # 3. test
    test = f"""
import socket
s=socket.socket()
s.connect(("{app_ip}",23))
s.send("Yijun is coming".encode())
msg = s.recv(1024)
print(msg)
    """
    with open("test.py", "w+") as f:
        f.write(test)

    cmd4 = "scp -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"test.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd4).read()

    cmd5 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill python3;python3 test.py'"
    resp = os.popen(cmd5).read()

    assert "[Pytest]TCP:23 is back!" in resp

    # # terminate server
    cmd6 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo rm -rf test.py'"
    os.popen(cmd6).read()

    cmd7 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo pkill python3\''"

    os.popen(cmd7).read()

@pytest.mark.geneveFTD
@pytest.mark.FTDtcp2to1
def test_TCP23_from_inside_FTD(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run

    # 1. transfer server file
    cmd1 = "scp -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"Pytest_server.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'scp -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@10.0.1.101:/home/ubuntu/.'"
    os.popen(cmd2).read()

    # 2. run server file
    cmd3 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill python3;sudo screen -d -m sudo python3 Pytest_server.py'"

    os.popen(cmd3).read()

    # 3. test
    test = f"""
import socket
s=socket.socket()
s.connect(("{app_jb_ip}",23))
s.send("Yijun is coming".encode())
msg = s.recv(1024)
print(msg)
    """
    with open("test.py", "w+") as f:
        f.write(test)

    cmd4 = "scp -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"test.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd4).read()

    cmd4_2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             f"ubuntu@{app_jb_ip} 'scp -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             "test.py ubuntu@10.0.1.101:/home/ubuntu/.'"

    os.popen(cmd4_2).read()

    cmd5 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo pkill python3;python3 test.py\''"
    resp = os.popen(cmd5).read()

    assert "[Pytest]TCP:23 is back!" in resp

    # # terminate server
    cmd6 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo rm -rf test.py'"
    os.popen(cmd6).read()

    cmd6_2 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             "ubuntu@10.0.1.101 \'sudo rm -rf test.py\''"
    os.popen(cmd6_2).read()

    cmd7 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill python3'"

    os.popen(cmd7).read()

@pytest.mark.geneveFTD
@pytest.mark.FTDudpYijun
def test_UDP666_FTD(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run

    # 1. transfer server file
    cmd1 = "scp -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"Pytest_server.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'scp -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@10.0.1.101:/home/ubuntu/.'"
    os.popen(cmd2).read()

    # 2. run server file
    cmd3 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo screen -d -m sudo python3 Pytest_server.py\''"

    os.popen(cmd3).read()

    # 3. test
    test = f"""
import socket
s=socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
s.sendto("Yijun is coming".encode(), ("{app_ip}", 666))
msg = s.recvfrom(1024)
print(msg[0])
    """
    with open("test.py", "w+") as f:
        f.write(test)

    cmd4 = "scp -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"test.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd4).read()

    cmd5 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo python3 test.py'"
    resp = os.popen(cmd5).read()

    assert "[Pytest]UDP:666 is back!" in resp

    # # terminate server
    cmd6 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo rm -rf test.py'"
    os.popen(cmd6).read()

    cmd7 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo pkill python3\''"

    os.popen(cmd7).read()

@pytest.mark.geneveFTD
@pytest.mark.FTDudp1to2
def test_UDP_from_inside_FTD(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run

    # 1. transfer server file
    cmd1 = "scp -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"Pytest_server.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'scp -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@10.0.1.101:/home/ubuntu/.'"
    os.popen(cmd2).read()

    # 2. run server file
    cmd_k = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
            f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
            "ubuntu@10.0.1.101 \'sudo pkill python3\''"

    os.popen(cmd_k).read()
    cmd3 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo screen -d -m sudo python3 Pytest_server.py\''"

    os.popen(cmd3).read()

    # 3. test
    test = f"""
import socket
s=socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
s.sendto("Yijun is coming".encode(), ("{app_ip}", 666))
msg = s.recvfrom(1024)
print(msg[0])
    """
    with open("test.py", "w+") as f:
        f.write(test)

    cmd4 = "scp -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"test.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd4).read()

    cmd5 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill python3;python3 test.py'"
    resp = os.popen(cmd5).read()

    assert "[Pytest]UDP:666 is back!" in resp

    # # terminate server
    cmd6 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo rm -rf test.py'"
    os.popen(cmd6).read()

    cmd7 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo pkill python3\''"

    os.popen(cmd7).read()

@pytest.mark.geneveFTD
@pytest.mark.FTDudp2to1
def test_UDP_from_outside_FTD(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run

    # 1. transfer server file
    cmd1 = "scp -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"Pytest_server.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'scp -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "Pytest_server.py ubuntu@10.0.1.101:/home/ubuntu/.'"
    os.popen(cmd2).read()

    # 2. run server file
    cmd3 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill python3;sudo screen -d -m sudo python3 Pytest_server.py'"

    os.popen(cmd3).read()

    # 3. test
    test = f"""
import socket
s=socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
s.sendto("Yijun is coming".encode(), ("{app_jb_ip}", 666))
msg = s.recvfrom(1024)
print(msg[0])
    """
    with open("test.py", "w+") as f:
        f.write(test)

    cmd4 = "scp -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"test.py ubuntu@{app_jb_ip}:/home/ubuntu/."
    os.popen(cmd4).read()

    cmd4_2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             f"ubuntu@{app_jb_ip} 'scp -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             "test.py ubuntu@10.0.1.101:/home/ubuntu/.'"
    os.popen(cmd4_2).read()

    cmd5 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           "ubuntu@10.0.1.101 \'sudo python3 test.py; pkill python3\''"
    resp = os.popen(cmd5).read()
    assert "[Pytest]UDP:666 is back!" in resp

    # # terminate server
    cmd6 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo rm -rf test.py'"
    os.popen(cmd6).read()

    cmd6_2 = "ssh -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
             "ubuntu@10.0.1.101 \'sudo rm -rf test.py\''"
    os.popen(cmd6_2).read()

    cmd7 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill python3'"

    os.popen(cmd7).read()

@pytest.mark.geneveFTD
@pytest.mark.FTDiperfudp
def test_iperf_udp_FTD(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run

    cmd1 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo screen -d -m sudo iperf -s -u'"

    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@10.0.1.101 \'sudo iperf -c {app_jb_ip} -u\''"

    res = os.popen(cmd2).read()

    bd = re.compile(" ([\d.]+?) (?=MBytes)").findall(res)[0]
    assert float(bd) > 0

    cmd3 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill iperf'"

    os.popen(cmd3).read()

@pytest.mark.geneveFTD
@pytest.mark.FTDiperfudpreverse
def test_iperf_udp_reverse_FTD(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run

    cmd1 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@10.0.1.101 \'sudo screen -d -m sudo iperf -s -u\''"

    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo iperf -c {app_ip} -u;'"

    res = os.popen(cmd2).read()
    print("Iperf result:\n", res)

    bd = re.compile(" ([\d.]+?) (?=MBytes)").findall(res)[0]
    assert float(bd) > 0
    cmd3 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@10.0.1.101 \'sudo pkill iperf\''"

    os.popen(cmd3).read()

@pytest.mark.geneveFTD
@pytest.mark.FTDiperftcp
def test_iperf_tcp_FTD(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run


    cmd1 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo screen -d -m sudo iperf -s'"

    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@10.0.1.101 \'sudo iperf -c {app_jb_ip}\''"

    res = os.popen(cmd2).read()
    print(res)
    try:
        bd = re.compile(" ([\d.]+?) (?=MBytes)").findall(res)[0]
    except:
        bd = re.compile(" ([\d.]+?) (?=GBytes)").findall(res)[0]

    assert float(bd) > 0

    cmd3 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo pkill iperf'"

    os.popen(cmd3).read()

@pytest.mark.geneveFTD
@pytest.mark.FTDiperftcpreverse
def test_iperf_tcp_reverse_FTD(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run

    cmd1 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@10.0.1.101 \'sudo screen -d -m sudo iperf -s\''"

    os.popen(cmd1).read()

    cmd2 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'sudo iperf -c {app_ip}'"

    res = os.popen(cmd2).read()

    print("Iperf result:\n", res)
    try:
        bd = re.compile(" ([\d.]+?) (?=MBytes)").findall(res)[0]
    except:
        bd = re.compile(" ([\d.]+?) (?=GBytes)").findall(res)[0]
    assert float(bd) > 0

    cmd3 = "ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
           f"ubuntu@10.0.1.101 \'sudo pkill iperf\''"

    os.popen(cmd3).read()

@pytest.mark.geneveFTD
@pytest.mark.FTDcounter
def test_udp_counter_FTD(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run
    cmd1 = "clear asp drop"
    cmd2 = "show asp drop frame geneve-invalid-udp-checksum"

    ftd_address = f"ssh -i 'template-Key' admin@{ftd_ip}"
    ftd_config(ftd_address, cmd1)

    send(IP(dst="20.0.1.101") / UDP(sport=20001, dport=6081, chksum=0) / b'\x08\x00\x08')

    _, res = ftd_config(ftd_address, cmd2)
    assert "geneve-invalid-udp-checksum" in res

@pytest.mark.geneveFTD
@pytest.mark.FTDreset
def test_tcp_counter_FTD(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run

    cmd = f"ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
          f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
          f"ubuntu@10.0.1.101 \'sudo screen -d -m ssh root@{asa_jb_ip}\''"

    os.popen(cmd).read()

    cmd2 = "clear conn address 10.0.1.101"
    cmd3 = "show asp drop"
    cmd1 = "clear asp drop"

    ftd_address = f"ssh -i 'template-Key' admin@{ftd_ip}"
    ftd_config(ftd_address, cmd1)
    ftd_config(ftd_address, cmd2)

    cmd = f"ssh  -i 'template-Key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
          f"ubuntu@{app_jb_ip} 'ssh -i \'template-Key\' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
          f"ubuntu@10.0.1.101 \'sudo pkill screen\''"

    os.popen(cmd).read()

    _, res = ftd_config(ftd_address, cmd3)

    assert "tcp-not-syn" in res

@pytest.mark.geneveFTD
@pytest.mark.FTDlogserver
def test_log_server_FTD(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run

    config = '''
logging enable
logging buffer-size 52428800
logging buffered debugging
logging trap debugging
logging host data-interface 20.0.1.10
logging message 302020
'''
    ftd_address = f"ssh -i 'template-Key' admin@{ftd_ip}"
    ftd_config(ftd_address, config)

    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh2 = paramiko.SSHClient()
    ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(app_jb_ip, username='ubuntu', password='', key_filename="template-Key")
    ssh2.connect(asa_jb_ip, username='ubuntu', password='', key_filename="template-Key")

    while True:
        _, stdout, _ = ssh.exec_command("ssh -i 'template-Key' -o StrictHostKeyChecking=no "
                                        "-o UserKnownHostsFile=/dev/null ubuntu@10.0.1.101 'ping 8.8.8.8 -c 10'")
        stdout.channel.recv_exit_status()
        resp1 = "".join(stdout.readlines())
        if not resp1:
            continue
        else:
            break

    assert "0% packet loss" in resp1

    _, stdout, _ = ssh2.exec_command("sudo systemctl restart syslog")
    stdout.channel.recv_exit_status()
    while True:
        _, stdout, _ = ssh2.exec_command("tail -n 100 /var/log/syslog")
        stdout.channel.recv_exit_status()
        resp2 = "".join(stdout.readlines())
        if not resp2:
            continue
        else:
            break

    assert "8.8.8.8" in resp2

    ssh.close()
    ssh2.close()

@pytest.mark.geneveFTD
@pytest.mark.FTDgenevedebug
def test_debug_geneve_FTD(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run
    cmd1 = "debug geneve encapsulation"
    cmd2 = "debug geneve encapsulation 4"
    cmd3 = "debug geneve decapsulation"
    cmd4 = "debug geneve decapsulation 4"
    cmd5 = "debug geneve all"
    cmd_clean = "unde all"
    cmd_show = "show debug"

    ftd_address = f"ssh -i 'template-Key' admin@{ftd_ip}"

    import pexpect

    conn = pexpect.spawn(ftd_address)
    Ocean_reply(conn)

    go2ftd(conn)

    conn.sendline("en")
    Ocean_reply(conn)

    conn.sendline(cmd_clean)
    Ocean_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Ocean_reply(conn)
    assert "debug geneve" not in res

    conn.sendline(cmd_clean)
    Ocean_reply(conn)
    conn.sendline(cmd1)
    Ocean_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Ocean_reply(conn)
    assert "debug geneve encapsulation enabled at level 1" in res

    conn.sendline(cmd_clean)
    Ocean_reply(conn)
    conn.sendline(cmd2)
    Ocean_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Ocean_reply(conn)
    assert "debug geneve encapsulation enabled at level 4" in res

    conn.sendline(cmd_clean)
    Ocean_reply(conn)
    conn.sendline(cmd3)
    Ocean_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Ocean_reply(conn)
    assert "debug geneve decapsulation enabled at level 1" in res

    conn.sendline(cmd_clean)
    Ocean_reply(conn)
    conn.sendline(cmd4)
    Ocean_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Ocean_reply(conn)
    assert "debug geneve decapsulation enabled at level 4" in res

    conn.sendline(cmd_clean)
    Ocean_reply(conn)
    conn.sendline(cmd5)
    Ocean_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Ocean_reply(conn)
    assert "debug geneve encapsulation enabled at level 1" in res
    assert "debug geneve decapsulation enabled at level 1" in res

    conn.sendline(cmd_clean)
    Ocean_reply(conn)
    conn.sendline(cmd_show)
    _, _, res = Ocean_reply(conn)
    assert "debug geneve" not in res

    conn.close()
    del conn

@pytest.mark.geneveFTD
@pytest.mark.FTDstatistics
def test_stats_FTD(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run
    cmd1 = "show interface vni 1"
    cmd2 = "show nve 1"
    ftd_address = f"ssh -i 'template-Key' admin@{ftd_ip}"

    _, cont1_1 = ftd_config(ftd_address, cmd1)
    _, cont2_1 = ftd_config(ftd_address, cmd2)
    p1 = "(.*) packets input"
    p2 = "(.*) packets output"

    output_cmd1_1 = int(re.compile(p1).findall(cont1_1)[0])
    output_cmd2_1 = int(re.compile(p2).findall(cont2_1)[0])

    test_Basic_PingGoogle_FTD(local_run)

    _, cont1_2 = ftd_config(ftd_address, cmd1)
    _, cont2_2 = ftd_config(ftd_address, cmd2)

    output_cmd1_2 = int(re.compile(p1).findall(cont1_2)[0])
    output_cmd2_2 = int(re.compile(p2).findall(cont2_2)[0])

    assert output_cmd1_2 > output_cmd1_1
    assert output_cmd2_2 > output_cmd2_1

@pytest.mark.geneveFTD
@pytest.mark.FTDcapture
def test_capture_FTD(local_run):
    app_jb_ip, asa_jb_ip, asa_ip, app_ip, ftd_ip, fmc_ip = local_run
    cmd0 = "no capture g"
    cmd1 = "clear cap /all"
    cmd2 = "cap g int ge trace"
    cmd3 = "show capture g | in icmp: echo request"
    ftd_address = f"ssh -i 'template-Key' admin@{ftd_ip}"

    ftd_config(ftd_address, cmd0)
    ftd_config(ftd_address, cmd1)
    ftd_config(ftd_address, cmd2)

    test_Basic_PingGoogle_FTD(local_run)
    time.sleep(1)
    _, cont3 = ftd_config(ftd_address, cmd3)

    pNum = int(re.compile("\d+: ").findall(cont3)[0].strip().split(":")[0])

    cmd4 = f"show capture g trace packet-number {pNum} | in Action:"
    cmd5 = "no capture g"
    _, cont4 = ftd_config(ftd_address, cmd4)
    assert "Action: allow" in cont4
    ftd_config(ftd_address, cmd5)

if __name__ == '__main__':
    pytest.main(["-q", "-s", "-ra", "test_geneve.py"])
