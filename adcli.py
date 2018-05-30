#!/usr/bin/env python

import socket
import pexpect
import optparse
import settings
import subprocess
from os import mkdir
from sys import stdout
from sssd import SSSD
from realm import Realm
from utils import create_exec_id
from shutil import copy2
from os.path import exists, join

_debug = settings.DEBUG
_bkp_dir = join(settings.TMP_DIR, '_adcli_{}'.format(create_exec_id()))
_klist_cmd = settings.KLIST_CMD
_ktutil_cmd = settings.KTUTIL_CMD
_keytab_content = settings.KEYTAB_CONTENT


def _parse_options():

    def _required():
        pass

    parser = optparse.OptionParser()
    parser.add_option('-k', '--keytab-file', help='Keytab file',
                      default=settings.DEFAULT_KEYTAB_FILE, dest='keytab_file')
    parser.add_option('-u', '--user', help='Join User',
                      default=None, dest='join_user')
    parser.add_option('-d', '--domain', help='Join Domain',
                      default=None, dest='join_domain')
    parser.add_option('-P', '--password', help='Join Password',
                      default=None, dest='join_password')
    parser.add_option('-s', '--manage-sssd', help='Defines wether sssd.conf will be managed.',
                      action='store_true', default=False, dest='manage_sssd')
    parser.add_option('-w', '--domain-with-only-sid', help='Defines wether sssd.conf needs special params for idmap range.',
                      action='store_true', default=False, dest='domain_with_only_sid')

    opts, _ = parser.parse_args()
    return opts


def _check_keytab_file():
    def _create_keytab_file():
        _o = open(options.keytab_file, 'wb')
        _o.write(_keytab_content)
        _o.close()
    def is_keytab_format():
        _o = open(options.keytab_file, 'rb')
        _buffer = _o.read(2)
        _o.close()
        if _buffer == _keytab_content:
            return True
        return False

    if not exists(options.keytab_file) or is_keytab_format() == False:
        _create_keytab_file()


def _check_keytab_entry(principal):
    _cmd_line = [_klist_cmd, '-k', options.keytab_file]
    _list = subprocess.Popen(_cmd_line,
                             stdout=subprocess.PIPE,
                             shell=False)
    while True:
        line = _list.stdout.readline().decode('utf-8')
        if line.rstrip() != '':
            if principal.lower() in line.rstrip().lower():
                return True
        else:
            break
    return False


def create_bkp():
    if not exists(_bkp_dir):
        mkdir(_bkp_dir)
    copy2(options.keytab_file, join(_bkp_dir, 'krb5.keytab'))


def rollback():
    copy2(join(_bkp_dir, 'krb5.keytab'), options.keytab_file)


def _inserting_domain_auth(principal):
    """
        Some parts of the code were reused from https://github.com/Tagar/stuff/blob/master/keytab.py
    """
    encrypts = [
        'aes128-cts-hmac-sha1-96',
        'aes256-cts-hmac-sha1-96',
        'RC4-HMAC'
    ]

    default_prompt = 'ktutil: '
    ktutil = pexpect.spawn(_ktutil_cmd)

    def wait (prompt=default_prompt):
        ''' Wait for ktutil's prompt
            Returns true if ktutil's cli command  produced output (error message) or unexpected prompt
        '''

        # always wait for default prompt too in case of error, so no timeout exception
        i = ktutil.expect([prompt, default_prompt], timeout=3)

        lines = ktutil.before.strip().split('\n'.encode())
        problem = (      len(lines) > 1   # if there is an error message
                    or  (i == 1)       # or ktutil gives default prompt when another prompt expected
                  )
        if problem:
            print('ktutil error: ' + lines[1])
        return problem

    wait()

    if _debug:
        ktutil.logfile = stdout.buffer

    for enc in encrypts:
        ktutil.sendline('addent -password -p {} -k 1 -e {}'.format(principal, enc))
        if wait('Password for ' + principal):
            exit('Unexpected ktutil error while waiting for password prompt')

        ktutil.sendline(options.join_password)
        if wait():
            exit('Unexpected ktutil error after addent command')
    ktutil.sendline('wkt {}'.format(options.keytab_file))
    ktutil.sendline('quit')
    ktutil.close()


def main():
    _principal = '{}@{}'.format(options.join_user, options.join_domain.upper())
    _check_keytab_file()
    # Checking if the user authentication is already created. If don't, do it.
    create_bkp()
    try:
        if not _check_keytab_entry(_principal):
            _inserting_domain_auth(_principal)
        if not _check_keytab_entry('{}@{}'.format(socket.gethostname(), options.join_domain)):
            realm = Realm(options.join_domain, options.join_user, options.join_password)
            realm.join()
        if options.manage_sssd:
            sssd_data = {
                'domain': options.join_domain,
                'auth_id': _principal,
                'keytab_file': options.keytab_file,
                'domain_with_only_sid': options.domain_with_only_sid
            }
            sssd = SSSD(**sssd_data)
            sssd.write_sssd_section()
    except Exception as e:
        rollback()
        print(str(e))


if __name__ == "__main__":
    options = _parse_options()
    main()
