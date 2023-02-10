# RSMBI - Yes, another SMB related thing

RSMBI is a python tool that answers to the question: What are the writable shares in this big domain? 
RSMBI connect to each target and it mounts the available shares in the /tmp folder (but that can also be changed). Once the shares are successfully mounted the threads (or the 
solo one) would start (os.)walking recursively all the folders, trying get a file handle with writing rights. If the handle is obtained successfully the UNC path of that file
is saved within the database, this time also with a clickable version. Once a share is fully analyzed, the folder is unmounted (gracefully or lazily).
Results are saved in a sqlite database and also exported in a nice CSV.  

## Requirements

```bash
pip3 install -r requirements.txt
```
## Usage

For instance, from the project folder:

```bash
sudo python3 rsmbi.py -username $username -password $password -domain ciao.grande -dc-ip 127.0.0.1 -multithread -ldap -T 30 -smbcreds /path/to/smbcreds -csv -debug -share-black $SHAREBLACK
```
Accepted input targets are: 

* UNC patchs
* CIDR
* IP address(es)
* Computer Objects from LDAP, RSMBI retrieves that for you

The -username and -password passed via the command line are used by RSMBI to enumerate shares using pysmb and for retrieving the list of computer objects from Active Directory
via LDAP protocol. 
The content of the smbcreds file (needed for the mount) must be as following: 

```
username=ob
password=ciaogrande
domain=ciao.grande
```

# Credits 

* Everyone who is going to help out finding issues and improving with new features 
* [Retrospected](https://github.com/Retrospected): For helping out every Friday with debugging the code and brainstorming on new features
