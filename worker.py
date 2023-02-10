import logging
import threading
import string
import random
from os.path import expanduser
import os
from subprocess import *
import subprocess
from smb import *
from smb.SMBConnection import SMBConnection
from persistence import Database
import time
logger = logging.getLogger('rSMBi')


class rsmicore(object):

    def __init__(self, workername, options, db, targetobj, targetIPenum):
        super(rsmicore, self).__init__()
        self.options = options
        self.workername = workername
        self.db = db
        self.targetobj = targetobj
        self.targetIPenum = targetIPenum

    def checkWritingRights(self, filePath, sharePath):

        try:
            f = open(filePath, "a")
        except Exception:
            return
        logger.info(self.workername + " | " + " Writing permissions on: " +
                    filePath)
        # here there is a finding def insertFinding(self, filename, share, ip, tag):
        self.db.insertFinding(filePath, list(self.targetobj.values())[0],
                              list(self.targetobj.keys())[0], self.options.tag)
        f.close()

    def createFolder(self, options):
        localpath = options.local_path + "/" + \
            ''.join(random.choices(string.ascii_letters, k=7))
        try:
            os.mkdir(expanduser(localpath))
            logger.debug("Created folder: " + localpath +
                         " | " + self.workername)
        except Exception as e:
            logger.error(self.workername + " |" + " Error while creating folder: " +
                         localpath + " with exception: " + str(e))

        return localpath

    def deleteFolder(self, path):
        logger.debug(self.workername + " |" + " Removing folder: " +
                     path)
        try:
            os.rmdir(path)
        except Exception as e:
            logger.error(self.workername + " |" + " Error removing " + path + " with exception " + str(e) +
                         ", keep in mind you might need to cleanup yourself")

    def listShares(self, serverName, options):
        connection = SMBConnection(options.username, options.password, options.fake_hostname,
                                   'netbios-server-name', options.domain, use_ntlm_v2=True, is_direct_tcp=True)
        try:
            connection.connect(serverName, 445)
        except Exception as e:
            logger.info(self.workername + " | " + "Error connecting to: " + serverName +
                        ", with exception: " + str(e))
        try:
            shares = connection.listShares()
        except Exception as e:
            logger.info(self.workername + " | " + "Error while listing shares from: " +
                        serverName + ", with exception: " + str(e))
            shares = []
        connection.close()
        return shares

    def mountShare(self, localPath, remoteShare, pathCredFile):
        logger.debug(self.workername + " | " + "Mounting share: " + remoteShare +
                     " in: " + localPath)
        try:
            check_call(['mount', '-t', 'cifs', remoteShare, '-o', 'credentials=' + pathCredFile,
                        expanduser(localPath)], stderr=subprocess.DEVNULL)
            return True
        except Exception as e:
            logger.error(self.workername + " | " + "Exception while trying to mount " +
                         remoteShare + " with exception: " + str(e))
            return False

    def umountShare(self, localPath):
        logger.debug(self.workername + " | " + "Unmounting share: " +
                     localPath)
        try:
            check_call(['umount', '-f', '-l', localPath],
                       stderr=subprocess.DEVNULL)
        except Exception as e:
            logger.error(self.workername + " | " + "Exception while trying to unmount " +
                         localPath + " with exception: " + str(e))

    def walkFolders(self, path):

        logger.debug(self.workername + " | " + "Walking folder in: " + path)

        try:
            for root, dirs, files in os.walk(path):
                for file in files:
                    self.checkWritingRights(root + "/" + file, path)

        except Exception as e:
            logger.error(self.workername + " | " + "Error while walking folders of path: " +
                         path + "with exception: " + str(e))
            self.umountShare(path)

    def analyzeTarget(self):
        logger.info("I'm " + self.workername +
                    " working on: " + str(self.targetobj))
        localpath = ""
        localpath = self.createFolder(self.options)
        if localpath != "":
            try:

                if self.mountShare(localpath, "//" + list(self.targetobj.keys()
                                                          )[0] + "/" + list(self.targetobj.values())[0], self.options.smbcreds):
                    self.walkFolders(localpath)
                    self.umountShare(localpath)
                self.deleteFolder(localpath)

            except Exception as e:
                logger.error(self.workername + " | " + "Error while working on: //" + list(self.targetobj.keys())
                             [0] + "/" + list(self.targetobj.values())[0])

    def enumTargets(self):
        logger.info("I'm " + self.workername +
                    " enumerating targets")
        tempShares = []
        # need to check here if i get empty shares
        logger.debug(self.workername + " | " +
                     "Listing shares for: " + self.targetIPenum)
        for share in self.listShares(self.targetIPenum, self.options):
            if not share.isSpecial and share.name not in ['NETLOGON', 'IPC$'] and (share.name).lower() not in list(map(lambda x: x.lower(), self.options.share_black.split(','))):
                logger.debug(self.workername + " | " + "Found share: " + share.name +
                             " on host:" + self.targetIPenum)
                tempShares.append(share.name)

        return self.targetIPenum, tempShares


class rsmbiworker (threading.Thread):
    def __init__(self, workername, options, targetdict, db, lock, scope, targetsIPs):
        threading.Thread.__init__(self)
        self.workername = workername
        self.options = options
        self.targetdict = targetdict
        self.db = db
        self.lock = lock
        self.scope = scope
        self.targetsIPs = targetsIPs

    def run(self):
        logger.info("Starting " + self.workername)
        if self.scope == "Action":

            while True:
                self.lock.acquire()
                if (len(list(self.targetdict.keys())) == 0):
                    logger.debug(self.workername + " | " +
                                 "No Targets left to analyze, Ciao Grande")
                    self.lock.release()
                    break
                key = list(self.targetdict.keys())[0]
                logger.info(self.workername + " | " + "Targets left to analyze: " +
                            str(len(list(self.targetdict.keys()))))
                try:
                    targetobj = {}
                    if len((self.targetdict[key])) > 0:
                        logger.debug(self.workername + " | " + "Shares to analyze left for: " +
                                     key + " are: " + str(len((self.targetdict[key]))))
                        targetobj[key] = (self.targetdict[key]).pop(0)
                    else:
                        logger.debug(self.workername + " | " + "No shares left for: " + key +
                                     ", I'm going to pop it out")
                        self.targetdict.pop(key)
                finally:
                    self.lock.release()
                    if bool(targetobj):
                        rsmbi = rsmicore(
                            self.workername, self.options, self.db, targetobj, None)
                        rsmbi.analyzeTarget()
                        # self.targetdict[]
        else:
            logger.info("My duty is to Enum")
            # workername, options, db, targetobj, targetIPenum
            while len(self.targetsIPs) > 0:
                ipToEnum = self.targetsIPs.pop(0)
                rsmbi = rsmicore(
                    self.workername, self.options, self.db, None, ipToEnum)
                toDict = rsmbi.enumTargets()
                self.targetdict[toDict[0]] = toDict[1]
        logger.info("Exiting " + self.workername)
