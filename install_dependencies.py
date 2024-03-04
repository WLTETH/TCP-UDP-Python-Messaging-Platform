import subprocess

def install_dependencies():
    dependencies = ['cryptography', 'colorama']
    for dependency in dependencies:
        try:
            # check if dependency is installed
            subprocess.check_call(['pip', 'install', dependency])
            print(f"{dependency} installed successfully.")
        except subprocess.CalledProcessError:
            print(f"Failed to install {dependency}. Please check your internet connection or upgrade pip using\n\'pip install --upgrade pip\'\n\n or \n\n\'py -m pip install --upgrade pip\'")

if __name__ == "__main__":
    install_dependencies()
