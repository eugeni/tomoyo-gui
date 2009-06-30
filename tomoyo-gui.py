#!/usr/bin/python
"""Parses tomoyo"""

import gobject
import gtk

class TomoyoPolicy:
    def __init__(self):
        """Initializes the policy class"""

    def parse(self):
        """Loads the policy"""
        self.policy = []
        self.policy_dict = {}
        self.tree = {}
        self.tree_depth = {}
        with open("/sys/kernel/security/tomoyo/domain_policy") as fd:
            data = fd.readlines()
        for line in data:
            line = line.strip()
            if not line:
                continue
            # parse policy
            if line.find('<kernel>') == 0:
                # it is a security domain
                domain = line
                self.policy.append(domain)
                if domain not in self.policy_dict:
                    self.policy_dict[domain] = []
                # update policy tree
                items = line.split(" ")
                num_items = len(items)
                for pos in range(1, num_items):
                    if pos not in self.tree_depth:
                        self.tree_depth[pos] = []
                    # current item
                    cur_item = " ".join(items[:pos])
                    if cur_item not in self.tree:
                        self.tree[cur_item] = []
                        self.tree_depth[pos].append(cur_item)
                    # parent item
                    last_item = " ".join(items[:pos-1])
                    if last_item:
                        if cur_item not in self.tree[last_item]:
                            self.tree[last_item].append(cur_item)
            else:
                # an ACL
                command, params = line.split(" ", 1)
                self.policy_dict[domain].append((command, params))
        # have a look on the policy
        for k in self.tree_depth.keys():
            print "Level %d: %d keys" % (k, len(self.tree_depth[k]))
        print self.tree[self.tree_depth[1][0]]




if __name__ == "__main__":
    policy = TomoyoPolicy()
    policy.parse()
