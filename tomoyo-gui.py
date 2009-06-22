#!/usr/bin/python
"""Parses tomoyo"""

class TomoyoPolicy:
    def __init__(self):
        """Initializes the policy class"""

    def parse(self):
        """Loads the policy"""
        self.policy = []
        self.policy_dict = {}
        with open("/sys/kernel/security/tomoyo/domain_policy") as fd:
            data = fd.readlines()
        for line in data:
            line = line.strip()
            if not line:
                continue
            if line.find('<kernel>') == 0:
                # a domain
                domain = line
                self.policy.append(domain)
                if domain not in self.policy_dict:
                    self.policy_dict[domain] = []
            else:
                # an ACL
                command, params = line.split(" ", 1)
                self.policy_dict[domain].append((command, params))
        for a in self.policy:
            print a


if __name__ == "__main__":
    policy = TomoyoPolicy()
    policy.parse()
