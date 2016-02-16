# Copyright (c) 2016, Wolf480pl <wolf480@interia.pl>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import

import hashlib
from random import SystemRandom

randbase = "abcdefghijklmnopqrstuvwxyz" \
           "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
		   "0123456789!?.,:;/*-+_()"

def znc_random(size=20):
    r = SystemRandom()
    return ''.join([r.choice(randbase) for _ in range(size)])

def znc_hash_password(password, salt, hashtype='sha256'):
    try:
        h = hashlib.new(hashtype)
    except:
        return None
    
    h.update(salt + password)
    return h.hexdigest()

class FilterModule(object):
    ''' Ansible ZNC jinja2 filters '''

    def filters(self):
        return {
            # exponents and logarithms
            'znc_random': znc_random,
            'znc_hash_password': znc_hash_password
        }
