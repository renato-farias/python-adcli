import pexpect
import settings
from os import mkdir
from utils import create_exec_id
from shutil import copy2
from string import Template
from os.path import join, dirname, exists

class Realm():

    net_cmd = 'net ads join'
    temp_dir = settings.TMP_DIR
    template_dir = '{}/templates'.format(dirname(__file__))
    smb_orig_file = settings.DEFAULT_SMB_CONFIG_FILE
    krb_orig_file = settings.DEFAULT_KRB_CONFIG_FILE

    def __init__(self, realm, user, password):
        self.user = user
        self.realm = realm
        self.password = password
        self.exec_id = create_exec_id()
        self.bkp_dir = join(self.temp_dir, '_realm_{}'.format(self.exec_id))


    def get_bkp_dir(self):
        return self.bkp_dir


    def krb_tmpl(self):
        return self.load_template('krb')


    def smb_tmpl(self):
        return self.load_template('smb')


    def load_template(self, name):
        _tmpl = self.open_tmpl_file('{}.tmpl'.format(name))
        data = {
            'domain_u': self.realm.upper(),
            'domain_l': self.realm.lower(),
            'workgroup_u': self.realm.split('.')[0].upper(),
            'workgroup_l': self.realm.split('.')[0].lower()
        }
        return _tmpl.substitute(data)


    def open_tmpl_file(self, file_name):
        _f = open(join(self.template_dir, file_name))
        return Template(_f.read())


    def create_bkp(self):
        if not exists(self.bkp_dir):
            mkdir(self.bkp_dir)
        if not exists(self.smb_orig_file):
            raise Exception('{} file not found.'.format(self.smb_orig_file))
        if not exists(self.krb_orig_file):
            raise Exception('{} file not found.'.format(self.krb_orig_file))

        copy2(self.smb_orig_file, join(self.bkp_dir, 'smb.conf'))
        copy2(self.krb_orig_file, join(self.bkp_dir, 'krb5.conf'))



    def restore_bkp(self):
        copy2(join(self.bkp_dir, 'smb.conf'), self.smb_orig_file)
        copy2(join(self.bkp_dir, 'krb5.conf'), self.krb_orig_file)


    def writing_temp_file(self, pth, cnt):
        _f = open(pth, 'w')
        _f.write(cnt)
        _f.close()


    def write_files(self):
       self.writing_temp_file(self.smb_orig_file, self.smb_tmpl())
       self.writing_temp_file(self.krb_orig_file, self.krb_tmpl())


    def join_domain(self):
        principal = '{}@{}'.format(self.user, self.realm.upper())
        try:
            net_join = pexpect.spawn('{} -U {}'.format(self.net_cmd, principal))
            net_join.expect('{}\'s password:'.format(principal), timeout=30)
            net_join.sendline('{}\n'.format(self.password))
            net_join.expect('Joined', timeout=30)
            net_join.close()
        except Exception as e:
            exit('Error: {}'.format(str(e)))


    def join(self):
        self.create_bkp()
        self.write_files()
        self.join_domain()
        self.restore_bkp()
