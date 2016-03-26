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
module: openssl_keygen
author:
    - "Wolf480pl (@Wolf480pl)"
description:
    - Generate various keys using the openssl tool
short_description: Generate keys using openssl
options:
    
node:
  - This module requires I(openssl) utility to be installed on the remote host.
'''

import re
import os
from os import W_OK

class OpenSSLError(Exception):
    pass

modulus_regex = re.compile("^(?:Modulus|Public Key)=([0-9a-fA-F]*)$", flags=re.M) 

def key_is_already_generated(openssl_func, key_type, key_file, size): 
    opts = [key_type, '-in', key_file, '-noout', '-modulus']
    
    (rc, out, err) = openssl_func(opts)
    # `openssl dsa` for some reason always returns 1 if -noout is used
    if rc != 0 and key_type != 'dsa':
        return False
    
    match = modulus_regex.search(out)
    
    return match and len(match.group(1)) * 4 == size

dhsize_regex = re.compile("^\s*DH Parameters: \(([0-9]+) bit\)$", flags=re.M)

dhcheck_regex = re.compile("DH parameters appear to be ok")

def dhparam_is_already_generated(openssl_func, param_file, size):
    opts = ['dhparam', '-in', param_file, '-check', '-noout', '-text']
    
    (rc, out, err) = openssl_func(opts)
    if rc != 0:
        return False
    
    if not dhcheck_regex.search(out):
        return False
    
    match = dhsize_regex.search(out)
    return match and int(match.group(1)) == size

def generate_opts(key_type, out_file, size):
    if key_type == 'dsa':
        opts = ['dsaparam', '-genkey']
    elif key_type == 'rsa':
        opts = ['genrsa' ]
    else:
        opts = ["dhparam" ]
    
    opts.append('-out')
    opts.append(out_file)
    opts.append(str(size))
    return opts

def generate(openssl_func, opts):
    (rc, _, _) = openssl_func(opts)
    if rc != 0:
        msg = err or out
        raise OpenSSLError(msg)    

def main():
    module = AnsibleModule(
        argument_spec={
            'dest': {'required': True},
            'type': {'default': 'rsa', 'choices': ['rsa', 'dsa', 'dhparam']},
            'size': {'default': 2048, 'type': 'int'}
        },
        supports_check_mode=True
    )
    
    # Create type object as namespace for module params
    p = type('Params', (), module.params)
    
    #if not os.access(p.dest, W_OK):
    #    module.fail_json(msg="dest %s doesn't exist or not writable" % (p.dest))
    
    openssl_bin = module.get_bin_path('openssl')
    if openssl_bin is None:
        module.fail_json(msg="openssl command not found")
    openssl_func = lambda opts: module.run_command("%s %s" % (openssl_bin, ' '.join(opts)))
    
    if p.type == 'dhparam':
        check_func = lambda: dhparam_is_already_generated(openssl_func, p.dest, p.size)
    else:
        check_func = lambda: key_is_already_generated(openssl_func, p.type, p.dest, p.size)
    
    gen_func = lambda dest: generate(openssl_func, generate_opts(p.type, dest, p.size))
    
    changed = False
    if not check_func():
        try:
            # Generating key to /dev/null will consume randomness, and possibly modify ~/.rnd
            # TODO: Are we sure we want thsi for check mode?
            gen_func(module.check_mode and "/dev/null" or p.dest)
            changed = True
        except OpenSSLError, e:
            module.fail_json(msg=str(e))
    
    module.exit_json(changed=changed)
    
# import module snippets
from ansible.module_utils.basic import *
main()
