import os
import subprocess

def execute(user_input):
    eval(user_input)
    exec(user_input)
    subprocess.run(user_input, shell=True)
    os.system(user_input)

def constants():
    eval("1 + 1")
    subprocess.run("echo fixture", shell=True)
