import settings
import subprocess
from os import mkdir
from utils import create_exec_id
from shutil import copy2
from os.path import join, exists
from configparser import ConfigParser

class SSSD():

    temp_dir = settings.TMP_DIR
    sssd_orig_file = settings.DEFAULT_SSSD_CONFIG_FILE

    def __init__(self, **kwargs):
        self.config = self.parse_sssd_conf()
        self.domain = kwargs.get('domain', 'NODOMAIN.IO')
        self.auth_id = kwargs.get('auth_id', 'user@NODOMAIN.IO')
        self.keytab_file = kwargs.get('keytab_file', '/etc/krb5.keytab')
        self.domain_with_only_sid = kwargs.get('domain_with_only_sid', False)
        self.exec_id = create_exec_id()
        self.bkp_dir = join(self.temp_dir, '_sssd_{}'.format(self.exec_id))
        self.domain_section = 'domain/{}'.format(self.domain.lower())


    def parse_sssd_conf(self):
        config = ConfigParser()
        config.read(self.sssd_orig_file)
        return config


    def create_bkp(self):
        if not exists(self.bkp_dir):
            mkdir(self.bkp_dir)
        if not exists(self.sssd_orig_file):
            raise Exception('{} file not found.'.format(self.sssd_orig_file))
        copy2(self.sssd_orig_file, join(self.bkp_dir, 'sssd.conf'))


    def has_section(self):
        if self.domain_section in self.config.sections():
            return True
        return False


    def get_domains(self):
        _domains = self.config.get('sssd', 'domains')
        return [x.strip(' ') for x in _domains.split(',')]


    def insert_domain_into_domain_list(self):
        if self.domain.lower() not in self.get_domains():
            _a = self.get_domains()
            _a.append(self.domain.lower())
            self.config.set('sssd', 'domains', ', '.join(_a))


    def restart_sssd(self):
        subprocess.run(['/sbin/service', 'sssd', 'restart'])


    def commit_configfile(self):
            configfile = open(self.sssd_orig_file, 'w')
            self.config.write(configfile)
            configfile.close()


    def write_sssd_section(self):
        if not self.has_section():
            self.create_bkp()

            self.config.add_section(self.domain_section)
            self.config.set(self.domain_section, 'ad_domain', self.domain.lower())
            self.config.set(self.domain_section, 'enumerate', 'True')
            self.config.set(self.domain_section, 'krb5_validate', 'False')
            self.config.set(self.domain_section, 'ldap_sasl_authid', self.auth_id)
            self.config.set(self.domain_section, 'ldap_krb5_keytab', self.keytab_file)
            self.config.set(self.domain_section, 'ad_enable_gc', 'False')
            self.config.set(self.domain_section, 'auth_provider', 'ad')
            self.config.set(self.domain_section, 'cache_credentials', 'True')
            self.config.set(self.domain_section, 'account_cache_expiration', '1')
            self.config.set(self.domain_section, 'default_shell', '/bin/bash')
            self.config.set(self.domain_section, 'fallback_homedir', '/home/.%d/%u')
            self.config.set(self.domain_section, 'id_provider', 'ad')
            self.config.set(self.domain_section, 'krb5_realm', self.domain.upper())
            self.config.set(self.domain_section, 'krb5_store_password_if_offline', 'True')
            self.config.set(self.domain_section, 'ldap_id_mapping', 'True')
            self.config.set(self.domain_section, 'ldap_user_principal', 'nosuchattribute')
            self.config.set(self.domain_section, 'realmd_tags', 'manages-system joined-with-adcli')
            self.config.set(self.domain_section, 'use_fully_qualified_names', 'False')
            self.config.set(self.domain_section, 'ldap_user_ssh_public_key', 'sshPublicKeys')
            if self.domain_with_only_sid:
                self.config.set(self.domain_section, 'ldap_idmap_range_min', str(200000))
                self.config.set(self.domain_section, 'ldap_idmap_range_max', str(2000200000))
                self.config.set(self.domain_section, 'ldap_idmap_range_size', str(100000000))

            self.insert_domain_into_domain_list()
            self.commit_configfile()
        self.restart_sssd()


