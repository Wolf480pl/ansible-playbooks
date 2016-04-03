#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2012, Luis Alberto Perez Lazaro <luisperlazaro@gmail.com> (original patch module)
# (c) 2015, Jakub Jirutka <jakub@jirutka.cz> (original patch module)
# (c) 2016, Wolf480pl <wolf480@interia.pl>
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
module: make
author:
    - "Wolf480pl"
description:
    - Run a Makefile using GNU Make tool
short_description: Run a Makefile using GNU Make tool.
options:
  basedir:
    description:
      - Path of a base directory in which the Makefile will be ran.
    required: true
  target:
    description:
      - The make target to invoke
    required: false
note:
  - This module requires GNU I(make) utility to be installed on the remote host.
'''

import os
from os import path, R_OK, W_OK


class MakeError(Exception):
    pass

def is_already_built(make_func, target=None):
    opts = ['-q']
    if target:
        opts.append(target)

    (rc, _, _) = make_func(opts)
    return rc == 0


def do_build(make_func, target=None):
    opts = []
    if target:
        opts.append(target)

    (rc, out, err) = make_func(opts)
    if rc != 0:
        msg = err or out
        raise MakeError(msg)


def main():
    module = AnsibleModule(
        argument_spec={
            'basedir': {'required': True, 'aliases': ['chdir']},
            'target': {},
        },
        supports_check_mode=True
    )

    # Create type object as namespace for module params
    p = type('Params', (), module.params)

    p.basedir = os.path.abspath(os.path.expanduser(p.basedir))

    if not path.exists(p.basedir):
        module.fail_json(msg="basedir %s doesn't exist" % (p.basedir))

    os.chdir(p.basedir)

    make_bin = module.get_bin_path('make')
    if make_bin is None:
        module.fail_json(msg="make command not found")
    make_func = lambda opts: module.run_command("%s %s" % (make_bin, ' '.join(opts)))

    changed = False
    if not is_already_built(make_func, p.target):
        try:
            do_build( make_func, p.target )
            changed = True
        except PatchError, e:
            module.fail_json(msg=str(e))

    module.exit_json(changed=changed)

# import module snippets
from ansible.module_utils.basic import *
main()
