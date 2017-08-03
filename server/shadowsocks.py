#encoding=utf-8
import commands
import errno
import pwd
import os
from common.log import logger
from config import config
from iptables import Iptables

class Shadowsocks(object):
    
    working_dir = config['ss_working_dir']
    run_user_str = config['ss_run_user']
    run_user = pwd.getpwnam(run_user_str)

    @classmethod
    def addService(cls, port, traffic_qouta, ss_config):
        add_rule_ret = Iptables.addRule(port, traffic_qouta)
        if not add_rule_ret:
            return False

        config_dir = os.path.join(cls.working_dir, 'config')
        pid_dir = os.path.join(cls.working_dir, 'pid')
        if not os.path.exists(config_dir):
            os.mkdir(config_dir)
            os.chown(config_dir, cls.run_user.pw_uid, cls.run_user.pw_gid)
        if not os.path.exists(pid_dir):
            os.mkdir(pid_dir)
            os.chown(pid_dir, cls.run_user.pw_uid, cls.run_user.pw_gid)
        
        config_file_path = os.path.join(config_dir, '%s.conf' % port)
        pid_file_path = os.path.join(pid_dir, '%s.pid' % port)

        kill_ret = cls.killExistedService(pid_file_path)
        if not kill_ret:
            return False

        with open(config_file_path, 'w') as f:
            f.write(ss_config)

        os.chown(config_file_path, cls.run_user.pw_uid, cls.run_user.pw_gid)

        cmd = 'su - %s -c \'nohup ss-server -c %s -f %s\' &> /dev/null' % (
            cls.run_user_str, config_file_path, pid_file_path
        )

        ret_val, output = commands.getstatusoutput(cmd)
        if ret_val != 0:
            logger.error('execute cmd[%s] failed. output[%s]', cmd, output)
            return False
        
        return True

    @classmethod
    def deleteService(cls, port):
        del_rule_ret = Iptables.deleteRule(port)
        if not del_rule_ret:
            return False

        pid_file_path = os.path.join(cls.working_dir, 'pid', '%s.pid' % port)
        kill_ret = cls.killExistedService(pid_file_path)
        if not kill_ret:
            return False

        return True

    @classmethod
    def killExistedService(cls, pid_file_path):
        pid = cls.getPidInFile(pid_file_path)
        if not pid:
            return True

        if cls.checkPid(pid):
            try:
                os.kill(pid, 9)
            except OSError:
                logger.exception('kill pid[%s] failed' % pid)
                return False
        
        return True

    @classmethod
    def getPidInFile(cls, pid_file_path):
        try:
            with open(pid_file_path, 'r') as f:
                pid = int(f.read())
                return pid
        except IOError:
            return None
            
    @classmethod
    def checkPid(cls, pid):
        try:
            os.kill(pid, 0)
        except OSError, e:
            if e.errno == errno.ESRCH:
                # ESRCH == No such process
                return False
            elif e.errno == errno.EPERM:
                # EPERM clearly means there's a process to deny access to
                return True
            else:
                logger.exception('invalid error')
                raise
        else:
            return True


