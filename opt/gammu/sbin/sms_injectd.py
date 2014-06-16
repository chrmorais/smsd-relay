#!/usr/bin/env python
#
# Web server listening for requests to inject SMS into the Gammu SMSD spool
#

from BaseHTTPServer import HTTPServer
from BaseHTTPServer import BaseHTTPRequestHandler
import sys, os, time, atexit, signal, logging, json
import resource, urlparse, cgi
import subprocess as sub
import pwd, grp

DEFAULT_ADDRESS = '127.0.0.1'
DEFAULT_PORT = 9045
SMS_SEND_PATH = '/deliver/sms/simple/text'
UNICODE_SMS_SEND_PATH = '/deliver/sms/simple/unicode'
JSON_SMS_SEND_PATH = '/deliver/sms/packed/text'
JSON_UNICODE_SMS_SEND_PATH = '/deliver/sms/packed/unicode'
PHONE_NUMBER_PARAM = 'phone'
MESSAGE_TEXT_PARAM = 'text'
CHECKCODE_TEXT_PARAM = 'pass'
DEFAULT_HOME_DIR = '/tmp'
DEAFULT_INJECT_NAME = 'gammu-smsd-inject'
DEFAULT_INJECT_OUTPUT_START = 'Written message with ID'

params = None

class Parameters():
    def __init__(self):
        self.params = self.parse_params()

        log_path = self.get_log_path()
        log_level = logging.WARNING
        if self.get_log_info():
            log_level = logging.INFO
        if log_path:
            logging.basicConfig(filename=log_path, level=log_level, format='%(levelname)s [%(asctime)s] %(message)s')
        else:
            logging.basicConfig(level=log_level, format='%(levelname)s [%(asctime)s] %(message)s')

        if not self.params['config_path']:
            logging.error('config path not provided')
            sys.exit(1)
        if not os.path.exists(self.params['config_path']):
            logging.error('config path not found: ' + str(self.params['config_path']))
            sys.exit(1)
        if not os.path.isfile(self.params['config_path']):
            logging.error('config path not file: ' + str(self.params['config_path']))
            sys.exit(1)

        self.allowed_addresses = []
        self.setup_restrictions()

        self.inject_result_matches = []
        self.setup_inject_matching()

        test_inject = self.get_inject_command()
        if not test_inject:
            logging.error('sms inject path not provided, nor found')
            sys.exit(1)
        if not os.path.exists(test_inject):
            logging.error('sms inject path not found: ' + str(test_inject))
            sys.exit(1)
        if not os.path.isfile(test_inject):
            logging.error('sms inject path not file: ' + str(test_inject))
            sys.exit(1)

        if self.params['user_id'] is not None:
            if self.params['user_id'].isdigit():
                self.params['user_id'] = int(self.params['user_id'])
            else:
                try:
                    requested_user_name = self.params['user_id']
                    user_info = pwd.getpwnam(requested_user_name)
                    self.params['user_id'] = int(user_info.pw_uid)
                except:
                    logging.error('can not find the specified user: ' + str(requested_user_name))
                    sys.exit(1)

        if self.params['group_id'] is not None:
            if self.params['group_id'].isdigit():
                self.params['group_id'] = int(self.params['group_id'])
            else:
                try:
                    requested_group_name = self.params['group_id']
                    group_info = grp.getgrnam(requested_group_name)
                    self.params['group_id'] = int(group_info.gr_gid)
                except:
                    logging.error('can not find the specified group: ' + str(requested_group_name))
                    sys.exit(1)

    def setup_secrets(self):
        if not self.params['sms_secret_path']:
            return
        self.params['sms_secret'] = []

        try:
            fh = open(self.params['sms_secret_path'])
            while True:
                one_line = fh.readline()
                if not one_line:
                    break
                one_line = one_line.strip()
                if not one_line:
                    continue
                if one_line.startswith('#'):
                    continue
                self.params['sms_secret'].append(one_line)
            fh.close()
        except:
            pass

    def setup_restrictions(self):
        self.allowed_addresses = []

        if not self.params['restrict_path']:
            return

        if not os.path.exists(self.params['restrict_path']):
            logging.error('restrictions path not found: ' + str(self.params['restrict_path']))
            sys.exit(1)
        if not os.path.isfile(self.params['restrict_path']):
            logging.error('restrictions path not file: ' + str(self.params['restrict_path']))
            sys.exit(1)

        try:
            fh = open(self.params['restrict_path'])
            while True:
                one_line = fh.readline()
                if not one_line:
                    break
                one_line = one_line.strip()
                if (not one_line) or one_line.startswith('#'):
                    continue
                self.allowed_addresses += [one_line]
            fh.close()
        except Exception:
            logging.error('restrictions file not readable: ' + str(self.params['restrict_path']))
            sys.exit(1)

    def setup_inject_matching(self):
        self.inject_result_matches = []
        if not self.params['inject_match_path']:
            self.inject_result_matches = [DEFAULT_INJECT_OUTPUT_START]
            return

        if not os.path.exists(self.params['inject_match_path']):
            logging.error('inject match path not found: ' + str(self.params['inject_match_path']))
            sys.exit(1)
        if not os.path.isfile(self.params['inject_match_path']):
            logging.error('inject match path not file: ' + str(self.params['inject_match_path']))
            sys.exit(1)

        try:
            fh = open(self.params['inject_match_path'])
            while True:
                one_line = fh.readline()
                if not one_line:
                    break
                one_line = one_line.strip()
                if (not one_line) or one_line.startswith('#'):
                    continue
                self.inject_result_matches += [one_line]
            fh.close()
        except Exception:
            logging.error('inject match file not readable: ' + str(self.params['inject_match_path']))
            sys.exit(1)

        if not self.inject_result_matches:
            self.inject_result_matches = [DEFAULT_INJECT_OUTPUT_START]

    def parse_params(self):
        keys1 = {
            '-f': 'log_info',
            '-d': 'daemonize',
        }
        keys2 = {
            '-s': 'sms_inject_path',
            '-e': 'sms_secret_path',
            '-l': 'log_path',
            '-c': 'config_path',
            '-a': 'address',
            '-p': 'port',
            '-h': 'home_dir',
            '-u': 'user_id',
            '-g': 'group_id',
            '-r': 'restrict_path',
            '-i': 'pid_path',
            '-m': 'inject_match_path',
        }

        pars = {
            'sms_inject_path': None,
            'sms_secret_path': None,
            'sms_secret': None,
            'log_info': False,
            'log_path': None,
            'config_path': None,
            'address': None,
            'port': None,
            'daemonize': False,
            'home_dir': None,
            'user_id': None,
            'group_id': None,
            'restrict_path': None,
            'pid_path': None,
            'inject_match_path': None,
        }

        current_option = None
        for one_arg in sys.argv:
            if one_arg in keys1:
                pars[keys1[one_arg]] = True;
                current_option = None
                continue
            if one_arg in keys2:
                current_option = keys2[one_arg]
                continue
            if current_option is not None:
                pars[current_option] = one_arg

        return pars

    def get_inject_command(self):
        inject_command = self.params['sms_inject_path']
        if inject_command and os.path.isdir(inject_command):
            inject_command = os.path.join(inject_command, DEAFULT_INJECT_NAME)
        if not inject_command:
            sys_path = os.environ.get('PATH')
            if not sys_path:
                sys_path = []
            for one_path_dir in sys_path.split(os.pathsep):
                inject_path_test = os.path.join(one_path_dir, DEAFULT_INJECT_NAME)
                if os.path.exists(inject_path_test) and os.path.isfile(inject_path_test):
                    inject_command = inject_path_test
                    break
        return inject_command

    def get_sms_secret(self):
        return self.params['sms_secret']

    def get_log_info(self):
        return self.params['log_info']

    def get_log_path(self):
        return self.params['log_path']

    def get_gammu_config_path(self):
        return self.params['config_path']

    def get_daemonize(self):
        return self.params['daemonize']

    def get_address(self):
        if self.params['address']:
            return self.params['address']
        return DEFAULT_ADDRESS

    def get_port(self):
        if self.params['port'] and self.params['port'].isdigit():
            port = int(self.params['port'])
            if port:
                return port
        return DEFAULT_PORT

    def get_user_id(self):
        return self.params['user_id']

    def get_group_id(self):
        return self.params['group_id']

    def get_home_dir(self):
        if self.params['home_dir']:
            return self.params['home_dir']
        return DEFAULT_HOME_DIR

    def get_pid_path(self):
        return self.params['pid_path']

    def is_inject_correct(self, output):
        if not output:
            return False

        for one_line in output.split('\n'):
            one_line = one_line.lstrip()
            for one_match in self.inject_result_matches:
                if one_line.startswith(one_match):
                    return True

        return False

    def is_ip_allowed(self, address):
        if not self.allowed_addresses:
            return True
        if address in self.allowed_addresses:
            return True
        return False

class RequestHandler(BaseHTTPRequestHandler):
    spec_phone = 'phone'
    spec_text = 'text'

    def _read_form(self):
        parsed_path = urlparse.urlparse(self.path)

        content_type = ''
        if self.headers and ('Content-Type' in self.headers):
            content_type = self.headers['Content-Type']
        environment = {'REQUEST_METHOD':'POST', 'CONTENT_TYPE':content_type}
        form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ=environment)

        return form

    def _read_json(self):
        parsed_path = urlparse.urlparse(self.path)

        content_length = 0
        if self.headers and ('Content-Length' in self.headers):
            try:
                content_length = int(self.headers.getheader('Content-Length'))
            except:
                content_length = 0

        content_type = ''
        if self.headers and ('Content-Type' in self.headers):
            content_type = self.headers.getheader('Content-Type')

        content_type_value, content_type_params = cgi.parse_header(content_type)
        try:
            req_post_data = self.rfile.read(content_length)
        except:
            req_post_data = None

        try:
            data = json.loads(req_post_data)
        except:
            data = None

        return data

    def log_message(self, format, *args):
        message = "%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), format%args)
        logging.info(message.strip())

    def send_sms(self, multipart, use_unicode, message_info):
        inject_command_path = params.get_inject_command()
        command_args = [inject_command_path] + ['-L']
        command_args += ['-c'] + [params.get_gammu_config_path()]
        command_args += ['TEXT'] + [message_info[self.spec_phone]]
        if multipart:
            command_args += ['-len'] + [str(len(message_info[self.spec_text]))]
        if use_unicode:
            command_args += ['-unicode'] + ['-textutf8']
        else:
            command_args += ['-text']
        command_args += [message_info[self.spec_text]]

        p = sub.Popen(command_args, stdout=sub.PIPE, stderr=sub.PIPE)
        output, errors = p.communicate()

        success = params.is_inject_correct(output)
        if not success:
            return {'status': False, 'message': errors}

        log_info = 'sent ' + ('long' if multipart else 'short') + ' '
        log_info += ('UNICODE' if use_unicode else 'TEXT')+ ' sms to '
        log_info += str(message_info[self.spec_phone])
        logging.info(log_info)

        return {'status': True}

    def process_sms_packed(self, system_set, data):
        set_secret = system_set['secret']

        if not data:
            return {'status':'400', 'message':'no (json) data provided'}
        if type(data) is not dict:
            return {'status':'400', 'message':'data provided in wrong format'}

        if set_secret is not None:
            if 'secret' not in data:
                return {'status':'401', 'message':'secret not provided'}
            if data['secret'] not in set_secret:
                return {'status':'401', 'message':'wrong secret provided'}

        if ('message' not in data) or (not data['message']):
            return {'status':'400', 'message':'message not provided'}
        send_message = data['message']

        use_phone_numbers = []
        if ('recipients' not in data) or (not data['recipients']) or (type(data['recipients']) not in (list, tuple)):
            return {'status':'400', 'message':'recipients not provided'}
        for one_recipient in data['recipients']:
            if type(one_recipient) is not dict:
                continue
            if ('type' not in one_recipient) or (one_recipient['type'] != 'address'):
                continue
            if ('value' not in one_recipient) or (not one_recipient['value']):
                continue
            use_phone_numbers.append(one_recipient['value'])
        if not use_phone_numbers:
            return {'status':'400', 'message':'no recipient address provided'}

        delivered = []
        err_notices = []

        use_unicode = system_set['use_unicode']
        max_len = system_set['max_len']
        multipart = False
        if len(send_message) > max_len:
            multipart = True

        for one_phone_number in use_phone_numbers:
            try:
                one_phone_number = str(one_phone_number)
            except:
                err_notices.append('a wrong phone number')
                continue

            try:
                message_info = {
                    self.spec_phone: one_phone_number,
                    self.spec_text: send_message,
                }
                res = self.send_sms(multipart, use_unicode, message_info)
                if res and ('status' in res) and res['status']:
                    delivered.append(one_phone_number)
                else:
                    err_notices.append('can not deliver to ' + one_phone_number)
            except Exception as exc:
                notice = 'an error during SMS sending to ' + one_phone_number
                if hasattr(exc, 'message') and exc.message:
                    notice += ': ' + str(exc.message)
                err_notices.append(notice)

        ret_data = {}
        if delivered:
            ret_data['status'] = '200'
        else:
            ret_data['status'] = '400'
        if err_notices:
            ret_data['message'] = '\r\n'.join(err_notices)
        else:
            ret_data['message'] = 'no failure detected'
        ret_data['delivered'] = delivered

        return ret_data

    def process_sms_simple(self, system_set, data):
        set_secret = system_set['secret']

        if set_secret is not None:
            got_secret = None
            if CHECKCODE_TEXT_PARAM in form.keys():
                got_secret_info = form[CHECKCODE_TEXT_PARAM]
                if got_secret_info.filename:
                    got_secret = got_secret_info.file.read()
                else:
                    got_secret = got_secret_info.value
            if not got_secret:
                return {'status':'400', 'message':'missing "' + CHECKCODE_TEXT_PARAM + '" part'}
            if got_secret not in set_secret:
                return {'status':'400', 'message':'incorect checkcode parameter'}

        use_keys = {PHONE_NUMBER_PARAM: self.spec_phone, MESSAGE_TEXT_PARAM: self.spec_text}
        message_info = {self.spec_phone:None, self.spec_text:None}
        phone_number = None
        message_text = ''

        for field in form.keys():
            if field not in use_keys:
                continue

            field_key = use_keys[field]
            field_item = form[field]
            if field_item.filename:
                message_info[field_key] = field_item.file.read()
            else:
                message_info[field_key] = field_item.value

        for part in [self.spec_phone, self.spec_text]:
            if not message_info[part]:
                logging.warning('can not use sms: missing ' + part + ' part')
                return {'status':'400', 'message':'missing ' + part + ' part'}

        use_unicode = system_set['use_unicode']
        max_len = system_set['max_len']
        multipart = False
        if len(message_info[self.spec_text]) > max_len:
            multipart = True

        is_correct = True
        notice = ''
        res = None
        try:
            res = self.send_sms(multipart, use_unicode, message_info)
        except Exception as exc:
            is_correct = False
            notice = 'An error during SMS sending'
            if hasattr(exc, 'message') and exc.message:
                notice += ': ' + str(exc.message)

        if is_correct:
            if (not res) or (not 'status' in res) or (not res['status']):
                is_correct = False

            notice = 'Could not send SMS'
            if res and ('message' in res) and res['message']:
                notice += ': ' + res['message']

        if not is_correct:
            warning_msg = notice + '\t' + str(message_info[self.spec_phone]) + ':'
            if use_unicode:
                warning_msg += 'UNICODE'
            else:
                warning_msg += 'TEXT'
            warning_msg += ':' + str(message_info[self.spec_text])
            logging.warning(warning_msg)

            return {'status':'400', 'message':notice}

        return {'status':'200', 'message':'sms sent'}

    def do_GET(self):
        if not params.is_ip_allowed(str(self.client_address[0])):
            self.send_error(403)
            return

        parsed_path = urlparse.urlparse(self.path)
        parsed_params = urlparse.parse_qs(parsed_path.query)

        if '/' != parsed_path.path:
            self.send_error(404)
            return

        self.send_response(200)
        self.end_headers()

        self.wfile.write('use ' + SMS_SEND_PATH + ' for ascii sms sending\r\n')
        self.wfile.write('use ' + UNICODE_SMS_SEND_PATH + ' for unicode sms sending\r\n')
        self.wfile.write('use ' + JSON_SMS_SEND_PATH + ' for ascii sms sending in packed way\r\n')
        self.wfile.write('use ' + JSON_UNICODE_SMS_SEND_PATH + ' for unicode sms sending in packed way\r\n')

        return

    def do_POST(self):
        global params

        if not params.is_ip_allowed(str(self.client_address[0])):
            self.send_error(403)
            return

        set_secret = None
        if params:
            set_secret = params.get_sms_secret()

        use_unicode = False
        bit_len = 7
        max_len = 160 # 7-bit encoding
        if parsed_path.path.startswith(UNICODE_SMS_SEND_PATH) or parsed_path.path.startswith(JSON_UNICODE_SMS_SEND_PATH):
            use_unicode = True
            bit_len = 16
            max_len = 70 # 16-bit unicode

        system_set = {'bits':bit_len, 'max_len':max_len, 'use_unicode':use_unicode, 'secret':set_secret}

        use_simple = False
        use_packed = False
        if parsed_path.path.startswith(UNICODE_SMS_SEND_PATH):
            use_simple = True
        if parsed_path.path.startswith(SMS_SEND_PATH):
            use_simple = True
        if parsed_path.path.startswith(JSON_UNICODE_SMS_SEND_PATH):
            use_packed = True
        if parsed_path.path.startswith(JSON_SMS_SEND_PATH):
            use_packed = True

        ret = None
        if use_simple:
            form_data = self._read_form()
            ret = self.process_sms_simple(system_set, form_data)
        if use_packed:
            json_data = self._read_json()
            ret = self.process_sms_packed(system_set, json_data)

        if (not ret) or (type(ret) is not dict) or (not 'status' in ret) or (not ret['status']):
            self.send_error(404)
            return

        self.send_response(int(ret['status']))
        self.end_headers()

        if use_packed:
            if 'delivered' in ret:
                to_ret = json.dumps({'message': ret['message'], 'delivered': ret['delivered']})
            else:
                to_ret = ret['message']
            self.wfile.write(to_ret)
            self.wfile.write('\r\n')

        else:
            if 'message' in ret:
                self.wfile.write(ret['message'])
                self.wfile.write('\r\n')

        return

def daemonize(work_dir, pid_path):
    UMASK = 022

    if (hasattr(os, 'devnull')):
       REDIRECT_TO = os.devnull
    else:
       REDIRECT_TO = '/dev/null'

    try:
        pid = os.fork()
    except OSError, e:
        logging.error('can not daemonize: %s [%d]' % (e.strerror, e.errno))
        sys.exit(1)

    if (pid != 0):
        os._exit(0)

    os.setsid()
    signal.signal(signal.SIGHUP, signal.SIG_IGN)

    try:
        pid = os.fork()
    except OSError, e:
        logging.error('can not daemonize: %s [%d]' % (e.strerror, e.errno))
        sys.exit(1)

    if (pid != 0):
        os._exit(0)

    try:
        os.chdir(work_dir)
        os.umask(UMASK)
    except OSError, e:
        logging.error('can not daemonize: %s [%d]' % (e.strerror, e.errno))
        sys.exit(1)

    try:
        sys.stdout.flush()
        sys.stderr.flush()
        si = file(REDIRECT_TO, 'r')
        so = file(REDIRECT_TO, 'a+')
        se = file(REDIRECT_TO, 'a+', 0)
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())
    except OSError, e:
        logging.error('can not daemonize: %s [%d]' % (e.strerror, e.errno))
        sys.exit(1)

    if pid_path is None:
        logging.warning('no pid file path provided')
    else:
        try:
            fh = open(pid_path, 'w')
            fh.write(str(os.getpid()) + '\n')
            fh.close()
        except Exception:
            logging.error('can not create pid file: ' + str(pid_path))
            sys.exit(1)

def set_user(user_id, group_id, pid_path):
    if (user_id is not None) and (str(user_id) != '0'):
        if (pid_path is not None) and os.path.exists(pid_path):
            try:
                os.chown(pid_path, user_id, -1)
            except OSError, e:
                logging.warning('can not set pid file owner: %s [%d]' % (e.strerror, e.errno))

    if group_id is not None:
        try:
            os.setgid(group_id)
        except Exception as e:
            logging.error('can not set group id: %s [%d]' % (e.strerror, e.errno))
            sys.exit(1)

    if user_id is not None:
        try:
            os.setuid(user_id)
        except Exception as e:
            logging.error('can not set user id: %s [%d]' % (e.strerror, e.errno))
            sys.exit(1)

def cleanup():
    logging.info('stopping the SMS web server')

    pid_path = params.get_pid_path()
    if pid_path is not None:
        try:
            fh = open(pid_path, 'w')
            fh.write('')
            fh.close()
        except Exception:
            logging.warning('can not clean pid file: ' + str(pid_path))

        if os.path.isfile(pid_path):
            try:
                os.unlink(pid_path)
            except Exception:
                pass

    logging.shutdown()
    os._exit(0)

def exit_handler(signum, frame):
    cleanup()

def run_server(ip_address, port):
    logging.info('starting the SMS web server')

    server_address = (ip_address, port)
    httpd = HTTPServer(server_address, RequestHandler)
    httpd.serve_forever()

if __name__ == "__main__":
    params = Parameters()
    atexit.register(cleanup)

    signal.signal(signal.SIGTERM, exit_handler)
    signal.signal(signal.SIGINT, exit_handler)

    if params.get_daemonize():
        daemonize(params.get_home_dir(), params.get_pid_path())

    set_user(params.get_user_id(), params.get_group_id(), params.get_pid_path())

    try:
        run_server(params.get_address(), params.get_port())
    except Exception as exc:
        logging.error('can not start the SMS web server: ' + str(exc))
        sys.exit(1)

