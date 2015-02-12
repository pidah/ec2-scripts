import boto.ec2
import paramiko
from paramiko.ssh_exception import AuthenticationException
import base64
import socket
from blessings import Terminal

t = Terminal()

class BaseAWSChecker(object):
    """
    Uses boto.ec2 and provides some methods for checking some things in AWS
    we want checked.
    """
    def __init__(self, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
        self.AWS_ID = AWS_ACCESS_KEY_ID
        self.AWS_KEY = AWS_SECRET_ACCESS_KEY
        self.conn = boto.ec2.connect_to_region('eu-west-1',
                                   aws_access_key_id=AWS_ACCESS_KEY_ID,
                                   aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

    def instance_name(self, instance):
        """
        Nicely formatted instance name, wit some other info like the public
        DNS etc.  Should be enough to workout what and where the instance is.
        """

        if 'Name' in instance.tags:
            return "%s (%s, %s) [%s]" % (instance.tags['Name'], instance.id,
                                         instance.public_dns_name,
                                         instance.state)
        else:
            return "%s (%s) [%s]" % (instance.id, instance.public_dns_name,
                                 instance.state)

    def instances(self, running=True):
        """
        A list of instances for a given account.  This is needed because AWS
        lists 'reservations' rather than instances.  This method just pulls
        instances out of reserved slots and puts them in a single list.
        """

        instance_list = []
        filters = {}
        if running:
            filters['instance-state-name'] = 'running'

        reservations = self.conn.get_all_instances(
            filters=filters)

        for r in reservations:
            instance_list.extend(r.instances)

        return instance_list

    def ssh_to_instance(self, instance, key_path, username='ubuntu',
                        close=True):
        """
        Use paramiko to attempt to SSH to an instance.  Does no exception
        handeling, so look for socket timeouts, and paramiko's
        AuthenticationException, etc.

        Requires a boto instance object and a path to a private key

        """

        instance_dns = instance.public_dns_name
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(instance_dns,
                       username=username,
                       key_filename=key_path,
                       timeout=2)
        if close:
            client.close()
        return client


class KeysAWSChecker(BaseAWSChecker):
    def attempt_bad_ssh(self, keys, usernames):
            """
            Takes a list of key paths and usernames and tries to SSH to all
            instances in self.conn (i.e., the creds provided.)

            Returns a list of instances that *allow* SSH to them, i.e.,
            normally ones with the provisioning key still in place.
            the pro
            """
            bad_list = []
            for instance in self.instances():
                name = self.instance_name(instance)

                for key_str in keys:
                    for username in usernames:
                        try:
                            print t.yellow('\n>>> attempting to ssh into %s\n') % name
                            self.ssh_to_instance(instance, key_str, username)
                            bad_list.append([instance, key_str, username])
                        except (AuthenticationException, socket.timeout, socket.error):
                            pass
            return bad_list


if __name__ == "__main__":
    from data import CREDS, USERNAMES, KEYS
    for name, k, v in CREDS:
        print t.yellow("\n## %s\n") % name
        checker = KeysAWSChecker(k,v)
        bad_list = checker.attempt_bad_ssh(KEYS, USERNAMES)
        if bad_list:
            print t.red("The following are BAD!\n")
        else:
            print t.green("Can't see anything wrong here :)\n")
        for bad in bad_list:
            print t.red("* %s with the key %s and the username %s") % (
                checker.instance_name(bad[0]), bad[1].split('/')[-1], bad[2])
