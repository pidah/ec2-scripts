# ec2-scripts

ec2 audit scripts that check for:
- old ssh keys on running instances and replaces them with new keys.
- checks for ssh fingerprint matches between old ssh keys and fingerprints within an AWS account,deleting any matching keys.
