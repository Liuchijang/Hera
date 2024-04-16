# Hera
A Python tool development project to help detect and synthesize the behavior of malicious code, especially *fileless malware* during the CA process.

```cmd
 ██╗  ██╗███████╗██████╗  █████╗ 
 ██║  ██║██╔════╝██╔══██╗██╔══██╗
 ███████║█████╗  ██████╔╝███████║
 ██╔══██║██╔══╝  ██╔══██╗██╔══██║
 ██║  ██║███████╗██║  ██║██║  ██║
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
    by Information Assurance students at FPT University

usage: main.py [-h] [-cl] [-sf] [-v] [-f]

Hera is not thor

options:
  -h, --help      show this help message and exit
  -cl, --collect  Collect event log files
  -sf, --save     Save output to file
  -v, --verbose   Enable verbose
  -f, --fast      Do not scan files for quick analysis
  ```

## Downloads
Please download the latest stable version of Hera with compiled binaries or compile the source code from the [Release](https://github.com/Liuchijang/Hera/releases/) page
## Git Cloning
You can `git clone` the repository with the following command and run main.py file:
```
git clone https://github.com/Liuchijang/Hera.git
```
**Note**: With this option, you'll need to have Python 3 and the required dependencies installed on your system. Issue this command to download all dependencies:
```cmd
pip install -r requirements.txt
```
## Unleash the Power of Hera: Configure Your Event Logs for optimal performance
Event logs are essential for **Hera** to function effectively. The more relevant and detailed event logs you provide, the deeper insights **Hera** can deliver. While configuring event logs is not mandatory, doing so can significantly enhance the tool's performance and analytical capabilities.
### Recommendation

For the most comprehensive and valuable analysis, we strongly recommend using *Sysmon*, a free system monitor and event logging tool from *Microsoft*. *Sysmon* provides in-depth details about system activity, process creation, network connections, and more, which are invaluable for **Hera**'s operations.

## Requirements
- **Administrator Privileges:** **Hera** requires administrator privileges to function correctly. This is because certain functionalities, such as accessing system resources, necessitate elevated permissions.
- **Port 8001:** **Hera** utilizes port 8001 for communication. Please ensure that this port is open and not in use by any other applications on your system. If port 8001 is already occupied, you might need to:
	- Stop any conflicting applications: Identify and stop any applications currently using port 8001.
	- Or configure a different port by your own
