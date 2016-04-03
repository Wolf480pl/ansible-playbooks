#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2015, Wolf480pl <wolf480@interia.pl>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: openssl_req
author:
    - "Wolf480pl (@Wolf480pl)"
description:
    - Generate certificate requests using the openssl tool
short_description: Generate certificate requests using openssl
options:
    
node:
  - This module requires I(openssl) utility to be installed on the remote host.
'''

import re
import os
from os import R_OK

class OpenSSLError(Exception):
    pass

subject_regex = re.compile("^subject=(.*)$", flags=re.M)

def req_is_already_generated(openssl_func, req_file, key_file, subj):
    opts = ['req', '-in', req_file, '-key', key_file, '-noout', '-verify', '-subject']
    
    (rc, out, err) = openssl_func(opts)
    if rc != 0:
        return False

    if not "verify OK" in err:
        return False
    
    subj_match = subject_regex.search(out)
    return subj_match and subj_match.group(1) == subj 

def req_generate(openssl_func, req_file, key_file, subj, config=None):
    opts = ['req', '-new', '-key', key_file, '-out', req_file, '-subj', subj, '-batch']
    
    if config:
        opts.append('-config')
        opts.append(config)
    
    (rc, out, err) = openssl_func(opts)
    if rc != 0:
        raise OpenSSLError(err or out)

def main():
    module = AnsibleModule(
        argument_spec={
            'dest': {'required': True},
            'key': {'required': True},
            'subject': {'required': True},
            'config': {}, 
        },
        supports_check_mode=True
    )
    
    # Create type object as namespace for module params
    p = type('Params', (), module.params)

    if not os.access(p.key, R_OK):
        module.fail_json(msg="key %s doesn't exist or not readable" % (p.key))

    if p.config and not os.access(p.config, R_OK):
        module.fail_json(msg="config %s doesn't exist or not readable" % (p.config))

    openssl_bin = module.get_bin_path('openssl')
    if openssl_bin is None:
        module.fail_json(msg="openssl command not found")
    openssl_func = lambda opts: module.run_command("%s %s" % (openssl_bin, ' '.join(opts)))

    changed = False
    if not req_is_already_generated(openssl_func, p.dest, p.key, p.subject):
        out_file = module.check_mode and '/dev/null' or p.dest
        try:
            req_generate(openssl_func, out_file, p.key, p.subject, p.config)
            changed = True
        except OpenSSLError, e:
            module.fail_json(msg=str(e))

    module.exit_json(changed=changed)

# import module snippets
from ansible.module_utils.basic import *
main()
