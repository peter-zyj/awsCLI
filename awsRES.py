import os, sys
import re, time, datetime
import shutil, atexit
import subprocess
import yaml

from awsAPI import aws

class resource(object):
    def __init__(self):
        self.dependency = None
        self.keepAlive = False
        self.creation = None
        self.termination = None

    def load_deployment(self, fileName):
        try:
            with open(fileName, "r") as f:
                cont = f.read()
        except FileNotFoundError as e:
            print(f"[ERROR][load_deplyment]:{e}")
            return
        self.res_deployment = yaml.load(cont, Loader=yaml.FullLoader)

    def get_dependency(self):
        return self.dependency

    def get_creation(self):
        return self.creation

    def get_termination(self):
        return self.termination

    def exec_creation(self):
        print("No definition of creation in object: ", self.__class__.__name__)

    def exec_termination(self):
        print("No definition of termination in object: ", self.__class__.__name__)

class EC2(resource):
    def __init__(self):
        super().__init__()

    def exec_creation(self):
        pass

    def exec_termination(self):
        pass

if __name__ == "__main__":
    res = EC2()
    res.exec_creation()