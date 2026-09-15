import subprocess
import sys

def execute_user_script(script_name):
    # Untrusted user command chaining
    subprocess.run(f"sh {script_name}; rm -rf /tmp/*", shell=True)
