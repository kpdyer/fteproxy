# This file is part of FTE.
#
# FTE is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# FTE is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with FTE.  If not, see <http://www.gnu.org/licenses/>.

#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import glob


def main():
    TO_REMOVE = [
        './languages/cfgs/*.py',
        './languages/cfgs/*.c',
        './languages/cfgs/*.h',
        './languages/cfgs/*.o',
        './languages/cfgs/*.tokens',
        './languages/regexs/*.fst',
        './fte/cCfg.cc',
        './fte/*.o',
        './fte/*.so',
        './*.log',
        './*.pyc',
        './*/*.pyc',
        './*/*/*.pyc',
        'doc/*',
        'bin/re2dfa',
        'fte_relay.spec',
    ]
    for path in TO_REMOVE:
        for file in glob.glob(path):
            print file
            os.remove(file)
    os.system('rm -rf build')
    os.system('rm -rf dist')
    os.system('cd ../third-party/openfst-1.3.3 && make clean')
    os.system('cd ../third-party/gmp-5.1.1 && make clean')
    os.system('cd ../third-party/re2-20130115 && make clean')

if __name__ == '__main__':
    main()