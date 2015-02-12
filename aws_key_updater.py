import sys
import socket
import subprocess
from paramiko.ssh_exception import AuthenticationException
from aws_checker import BaseAWSChecker
from data import CREDS, USERNAMES, KEYS, NEW_PUBLIC_KEY, NEW_PRIVATE_KEY
from blessings import Terminal

t = Terminal()


class UpdateAWS(BaseAWSChecker):

    def _write_key(
            self,
            instance,
            ssh_key,
            ssh_username,
            new_public_key,
            append=True):
        client = self.ssh_to_instance(
            instance,
            ssh_key,
            username=ssh_username,
            close=False)
        client.exec_command(
            'echo "%s" %s ~/.ssh/authorized_keys' %
            (new_public_key, '>>' if append else '>'))
        client.close()

    def update_instances(self, keys, usernames):
        """
        This checks for the old default key on running ec2 instances,
        adds a new default key, deletes the old key.
        """

        with open(NEW_PUBLIC_KEY, "r") as f:
            new_public_key = f.read()

        bad_list = []
        for instance in self.instances():
            name = self.instance_name(instance)
            for key_str in keys:
                for username in usernames:
                    try:
                        print t.yellow('\n\n>>> checking %s') % name
                        self._write_key(
                            instance,
                            key_str,
                            username,
                            new_public_key,
                            append=True)
                        bad_list.append(name)
                    except AuthenticationException as e:
                        # can't ssh with old key => good for now
                        continue

                    try:
                        self._write_key(
                            instance,
                            NEW_PRIVATE_KEY,
                            username,
                            new_public_key,
                            append=False)

                    except (AuthenticationException, socket.timeout, socket.error):
                        print t.red('>>> could not ssh into %s with new key') % name

        return new_public_key, bad_list

    def update_account(self, new_pub_key, old_priv_key):
        """
        This checks for ssh key fingerprint matches, deleting any
        matches found within the AWS account. It also updates the `default` key
        within the AWS account.
        """
        key = old_priv_key[0] if old_priv_key else sys.exit(
            'old_private_key not found')
        cmd = "openssl rsa -in %s -inform PEM -pubout -outform DER | openssl md5 -c" % key
        fingerprint = subprocess.check_output(
            cmd,
            shell=True,
            stderr=subprocess.PIPE)

        try:
            conn = self.conn

            for k in conn.get_all_key_pairs():

                if fingerprint.strip('\n') == k.fingerprint:
                    print t.red('fingerprint matched! deleting the %s key pair.') % k.name

                    try:
                        conn.delete_key_pair(k.name)
                        conn.import_key_pair(k.name, new_pub_key)

                    except Exception as err:
                        sys.stderr.write('ERROR: %s\n' % str(err))
                        sys.exit(2)
                else:
                    print t.green('no fingerprint match found for %s') % k.fingerprint

        except Exception as err:
            sys.stderr.write('ERROR: %s\n' % str(err))
            sys.exit(2)


if __name__ == "__main__":
    for name, k, v in CREDS:
        print t.yellow("\n## %s\n") % name
        aws = UpdateAWS(k, v)
        update_key, bad_list = aws.update_instances(KEYS, USERNAMES)
        update_aws_account = aws.update_account(update_key, KEYS)
        print t.red("fixed the following vulnerable instances:\n" + "\n".join(bad_list))
