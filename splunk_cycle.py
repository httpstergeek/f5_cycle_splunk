__author__ = 'httpstergeek@httpstergeek.com'
# !/usr/bin/env python
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the (LGPL) GNU Lesser General Public License as
# published by the Free Software Foundation; either version 3 of the 
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Library Lesser General Public License for more details at
# ( http://www.gnu.org/licenses/lgpl.html ).
# written by: Bernardo Macias ( httpstergeek@httpstergeek.com )

# Currently require a splunk_lint.cfg file to run
#
#

import bigsuds
import os
import logging
import logging.handlers
import smtplib
import socket
import splunklib.client as client
from ConfigParser import ConfigParser
from time import sleep


def setup_logger(level):
    """
        @param level: Logging level
        @type level: logger object
        @rtype: logger object
    """
    logger = logging.getLogger('splunk_cycle')
    logger.propagate = False # Prevent the log messages from being duplicated in the python.log file
    logger.setLevel(level)
    file_handler = logging.handlers.RotatingFileHandler(os.path.join('splunk_cycle.log'), maxBytes=5000000,backupCount=5)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    consolehandler = logging.StreamHandler()
    consolehandler.setFormatter(formatter)
    logger.addHandler(consolehandler)
    return logger

logger = setup_logger(logging.INFO)

def splunkrestart(host='localhost', port=8089, user='admin', passwd='changeme'):
    """
        Restarts Splunk Services
        @param host: IP or FQDN.  default 'localhost'
        @type host: str
        @param port: splunkd service port. default 8089
        @type signed_low: int
        @param user: Splunk user with admin permission. default admin
        @type user: str
        @param passwd: Splunk user password.  default 'changeme'
        @type passwd: str
        @rtype = dict
    """
    service = client.Service(host=host,
                             port=port,
                             username=user,
                             password=passwd)
    try:
        service.login()
        response = service.restart()
        service.logout()
    except Exception as e:
        return e
    return response


def convert_64bit(signed_high, signed_low):
    """
        Converts two 32 bit signed integers to a 64-bit unsigned integer
        @param signed_high: signed 32bit integer.
        @type signed_high: int
        @param signed_low: signed 32bit integer.
        @type signed_low: int
        @rtype: int
    """
    # x << n operation x shifted left by n bits
    if signed_high < 0:
        signed_high += (1 << 32)
    if signed_low < 0:
        signed_low += (1 << 32)
    unsigned_value = long((signed_high << 32) | signed_low)
    assert (unsigned_value >= 0)
    return unsigned_value

def sendmail(toaddr, fromaddr, subject, msg, relay='localhost', port=25):
    """
        Send email message
        @param toaddr: email to
        @type toaddr: list
        @param fromaddr: email from
        @type fromaddr: str
        @param subject: email subject
        @type subject: str
        @param msg: message body
        @type msg: str
        @param relay: smtprelay host
        @type relay: str
        @param port: smtp port
        @type port: int
        @rtype: None
    """
    msg = ("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s"
           % (fromaddr, ", ".join(toaddr), subject, msg))
    mailserver = smtplib.SMTP(relay, port)
    mailserver.set_debuglevel(1)
    mailserver.sendmail(fromaddr, toaddr, msg)
    mailserver.quit()


def getconfig(objfile, stanza):
    """
        Gets custom config file
        @param objfile: absolute path of config file
        @type objfile: str
        @param stanza: config option
        @type str: str
    """
    config = ConfigParser()
    settings = dict()
    try:
        config.read(objfile)
        options = config.options(stanza)
        for option in options:
            settings[option] = config.get(stanza, option)
    except Exception, e:
        return dict(message=e)
    return settings

class f5cycle():
    """
        Used to manipulate F5 pools and pool members
    """
    def __init__(self, user, passwd, host):
        self.f5 = bigsuds.BIGIP(
            hostname=host,
            username=user,
            password=passwd
        )
        self.mstatus = None

    def setpartition(self, partition):
        """
            Set active partition for methods.
            @param partition: F5 partition name.
            @type partition: str
            @rtype: str
        """
        activeparition = self.f5.Management.Partition.get_active_partition()
        if partition != activeparition:
            self.f5.Management.Partition.set_active_partition(partition)
        return self.f5.Management.Partition.get_active_partition()

    def poolstatus(self, poolname):
        """
            Return pool status
            @param poolname: F5 pool name.
            @type poolname: str
            @rtype: dict
        """
        return self.f5.LocalLB.Pool.get_object_status([poolname])[0]


    def memberstatus(self, poolname):
        """
            Return pool member status
            @param poolname: F5 pool name.
            @type poolname: str
            @rtype: list
        """
        mstatus = self.f5.LocalLB.PoolMember.get_object_status([poolname])[0]
        return mstatus

    def setstatus(self, pool, member, state='enabled'):
        """
            Set pool member status to disabled or enabled
            @param pool: F5 pool name.
            @type pool: str
            @param member: F5 IPPortDefinition object.
            @type member: IPPortDefinition
            @rtype: None
        """
        membersessionstate = {'member': member}
        membersessionstate['session_state'] = 'STATE_ENABLED'
        if state == 'disable':
            membersessionstate['session_state'] = 'STATE_DISABLED'
        self.f5.LocalLB.PoolMember.set_session_enabled_state([pool], [[membersessionstate]])

    def getconnections(self, pool, member):
        """
            Returns number of active connections for a pool member
            @param pool: F5 pool name.
            @type pool: str
            @param member: F5 IPPortDefinition object.
            @type member: IPPortDefinition
            @rtype: None
        """
        statistics = self.f5.LocalLB.PoolMember.get_statistics([pool], [[member]])[0]['statistics'][0]['statistics']
        unsigned_value = None
        for statistic in statistics:
            if statistic['type'] == 'STATISTIC_SERVER_SIDE_CURRENT_CONNECTIONS':
                unsigned_value = convert_64bit(statistic['value']['high'], statistic['value']['low'])
        return unsigned_value

    def verifymembers(self, poolname=None):
        """
            Returns list of down or unavailable members
            @param poolname: F5 pool name.
            @type pool: str
            @rtype: list
        """

        members = self.memberstatus(poolname)
        downmembers = []
        for memberobject in members:
            status = memberobject['object_status']
            if status['availability_status'] != 'AVAILABILITY_STATUS_GREEN' \
                    or status['enabled_status'] != 'ENABLED_STATUS_ENABLED':
                downmembers.append(memberobject['member'])
        return dict(downmembers=downmembers, members=members)

    def verifypool(self, poolname=None):
        poolstatus = self.poolstatus(poolname)
        if poolstatus['availability_status'] != 'AVAILABILITY_STATUS_GREEN' \
                or poolstatus['enabled_status'] != 'ENABLED_STATUS_ENABLED':
            return False
        return True


    def nodename(self, nodeaddress):
        partition = self.f5.Management.Partition.get_active_partition()
        self.setpartition('Common')
        nodename = self.f5.LocalLB.NodeAddress.get_screen_name([nodeaddress])[0].rstrip('-lb')
        self.setpartition(partition)
        return nodename



if __name__ == '__main__':
    # finds execution path and builds config location
    executepath = os.path.dirname(__file__)
    configfile = os.path.join(executepath, 'splunk_cycle.cfg')

    # try to log configs
    if not os.path.isfile(configfile):
        logger.info('% not found.' % configfile)
        exit(0)
    try:
        logger.info('Loading config: %s', configfile)
        f5config = getconfig(configfile, 'f5')
        poolname = f5config['pool']
        splunkconfig = getconfig(configfile, 'splunk')
        retries = int(splunkconfig['retries'])
        email = getconfig(configfile, 'email')
        runinfo = getconfig(configfile, 'runinfo')
        sleeptime = int(runinfo['sleep'])
        breaks = int(runinfo['breaks'])
    except Exception as e:
        logger.info('failed to load configs: %s' % e)
        exit(1)

    # settings up f5 connection
    splunkf5 = f5cycle(f5config['user'],
                       f5config['password'],
                       f5config['host'])

    # sets correct working partition
    partition = splunkf5.setpartition(f5config['partition'])
    logger.info('active partition set: %s' % partition)

    # verifes F5 pool
    if not splunkf5.verifypool(poolname):
        msg = '%s did not pass verification: % %' % (poolname,
                                                     poolstatus['availability_status'],
                                                     poolstatus['enabled_status'])
        logger.info(msg)
        sendmail([email['recipients']], email['from'], email['subject'], msg, relay=email['smtprelay'])
        exit(0)

    # verifies all members
    memberstatus = splunkf5.verifymembers(poolname)
    if len(memberstatus['downmembers']) > 0:
        msg = 'down members: %s' % memberstatus['downmembers']
        logger.info(msg)
        sendmail([email['recipients']], email['from'], email['subject'], msg ,relay=email['smtprelay'])
        logger.info('mail sent')
        exit(0)
    logger.info('Pool verified')

    # starts managing pool members0
    for memberobject in memberstatus['members']:
        member = memberobject['member']
        current_conn = splunkf5.getconnections(poolname, member)
        logger.info('disabling %s in %s' % (member, poolname))
        splunkf5.setstatus(poolname, member, 'disable')
        cnt = 0
        while current_conn > 0:
            logger.info('%s active_connections=%s' % (member, current_conn))
            current_conn = splunkf5.getconnections(poolname, member)
            cnt += 1
            sleep(sleeptime)
            if cnt >= 12:
                break
        logger.info('%s splunk restarting' % member)
        cnt = 0

        # restarts splunk server
        while retries >= cnt:
            node = splunkf5.nodename(member['address'])
            routableip = socket.gethostbyname(node)
            # Real restart code
            # response = splunkrestart(host='routableip', user=splunkconfig['user'], passwd=splunkconfig['password'])
            response = splunkrestart(host='localhost', user='admin', passwd='hello')
            cnt += 1
            sleep(sleeptime)
            print response, retries, cnt
            if response['status'] != 200 and retries >= cnt:
                msg = '%s did not restart.  status %s returned' % (member, response['status'])
                logger.info(msg)
                sendmail([email['recipients']], email['from'], email['subject'], msg, relay=email['smtprelay'])
            elif response['status'] == 200:
                msg = '%s splunk restarted.  status %s returned' % (member, response['status'])
                logger.info(msg)
                break

        # waiting for member status to return to AVAILABILITY_STATUS_GREEN and ENABLED_STATUS_ENABLED
        memberdown = True
        while memberdown == True:
            curstatus = splunkf5.memberstatus(poolname)
            for memberobject in curstatus:
                if member == memberobject['member']:
                    status = memberobject['object_status']
                    logger.info('%s status: %s, %s' % (member, status['availability_status'], status['enabled_status']))
                    if status['availability_status'] == 'AVAILABILITY_STATUS_GREEN':
                        memberdown = False
                        break
            sleep(sleeptime)
            cnt += 1
            if cnt >= 14:
                msg = '%s down for more than 7 minutes. May require intervention' % member
                logger.info(msg)
                sendmail([email['recipients']], email['from'], email['subject'], msg, relay=email['smtprelay'])
                exit(0)

        logger.info('Enabling member: %s' % member)
        splunkf5.setstatus(poolname, member, 'enable')
    logger.info('%s members cycled ending run' % poolname)
    exit(0)
