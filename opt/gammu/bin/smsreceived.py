#!/usr/bin/env python
#
# ./smsreceived -d db_sms_path -c db_config_path
#

import os, sys, time, copy, logging, atexit
import urllib, urllib2
import sqlite3 as dbs

def cleanup():
    logging.shutdown()

def get_log_path():
    log_path = None
    index = 0
    for one_arg in sys.argv:
        index += 1
        if one_arg == '-l':
            break
    if index < len(sys.argv):
        log_path = sys.argv[index]
    return log_path

def get_db_path(part='sms'):
    param = None
    if 'sms' == part:
        param = '-d'
    if 'config' == part:
        param = '-c'

    if not param:
        logging.error('Unknown db specifier: ' + str(part))
        sys.exit(1)

    db_path = None
    index = 0
    for one_arg in sys.argv:
        index += 1
        if one_arg == param:
            break
    if index < len(sys.argv):
        db_path = sys.argv[index]

    if db_path is None:
        logging.error('DB param was not given: ' + str(param))
        sys.exit(1)

    if not os.path.exists(db_path):
        logging.error('db path not found: ' + str(db_path))
        sys.exit(1)
    if not os.path.isfile(db_path):
        logging.error('db path not file: ' + str(db_path))
        sys.exit(1)
    return db_path

def get_db_conn(db_path):
    try:
        dbc = dbs.connect(db_path)
    except:
        logging.error('can not open db path: ' + str(db_path))
        sys.exit(1)
    if not dbc:
        logging.error('db path could not be open: ' + str(db_path))
        sys.exit(1)
    try:
        dbc.row_factory = dbs.Row
    except:
        logging.error('can not set db row factory: ' + str(db_path))
        sys.exit(1)
    return dbc

def get_url_paths():
    db_path = get_db_path('config')
    dbc = get_db_conn(db_path)

    url_paths = []
    try:
        cur = dbc.cursor()
        cur.execute('SELECT name, keyword, method, url FROM feeds ORDER BY id')
        while True:
            one_feed = cur.fetchone()
            if not one_feed:
                break
            url_paths.append({'feed': one_feed['name'], 'key': one_feed['keyword'], 'method': one_feed['method'], 'url': one_feed['url']})
    except:
        logging.error('Can not read URL paths: ' + str(db_path))
        sys.exit(1)

    return url_paths

def get_messages():
    db_path = get_db_path()
    dbc = get_db_conn(db_path)

    messages = []
    try:
        cur = dbc.cursor()
        # not sorting by UDH, since operators can send same UDHs for several sequences
        cur.execute('SELECT ID, SenderNumber as phone_number, Coding as sms_coding, TextDecoded as sms_text, ReceivingDateTime as received_datetime, UDH FROM inbox WHERE Processed = "false" ORDER BY ID')
        current_sms = None
        empty_sms = {'text': '', 'ids': [], 'phone': None, 'received': None, 'sequence': None}
        while True:
            one_sms = cur.fetchone()
            if not one_sms:
                break

            if not current_sms:
                current_sms = copy.deepcopy(empty_sms)

            sms_id = one_sms['ID']
            phone_number = one_sms['phone_number'].replace('+', '00')
            sms_coding = one_sms['sms_coding'] # not used now
            sms_text = one_sms['sms_text']
            received_datetime = one_sms['received_datetime']
            sms_udh = one_sms['UDH']
            if sms_udh:
                sms_udh = sms_udh.lower()
            sms_sequence = None
            sms_count = None
            sms_rank = None

            if sms_udh:
                if (12 == len(sms_udh)) and sms_udh.startswith('050003'):
                    sms_sequence = sms_udh[6:8]
                    sms_count = sms_udh[8:10]
                    sms_rank = sms_udh[10:12]
                if (14 == len(sms_udh)) and sms_udh.startswith('060804'):
                    sms_sequence = sms_udh[6:10]
                    sms_count = sms_udh[10:12]
                    sms_rank = sms_udh[12:14]

            if current_sms['sequence']:
                if (not sms_sequence) or (sms_sequence != current_sms['sequence']):
                    messages.append(current_sms)
                    current_sms = copy.deepcopy(empty_sms)
                else:
                    current_sms['text'] = current_sms['text'] + sms_text
                    current_sms['ids'] = current_sms['ids'] + [sms_id]
                    if sms_count <= sms_rank:
                        messages.append(current_sms)
                        current_sms = copy.deepcopy(empty_sms)
                    continue

            current_sms['text'] = sms_text
            current_sms['ids'] = [sms_id]
            current_sms['phone'] = phone_number
            current_sms['received'] = received_datetime
            current_sms['sequence'] = sms_sequence

            if not sms_sequence:
                messages.append(current_sms)
                current_sms = copy.deepcopy(empty_sms)

    except:
        logging.error('can not read messages from db: ' + str(db_path))
        sys.exit(1)

    return messages

def send_message(method, url, params):
    if 'GET' == method:
        try:
            resp = urllib2.urlopen(url)
            resp.read()
        except:
            logging.warning('Can not (GET) relay message: ' + str(url))
            return False
        return True

    else:
        try:
            post_data = urllib.urlencode(params)
            req = urllib2.Request(url, post_data)
            response = urllib2.urlopen(req)
            response.read()
        except:
            logging.warning('Can not (POST) relay message: ' + str(url) + '\t' + str(params))
            return False
        return True

def confirm_message(ids):
    db_path = get_db_path()
    dbc = get_db_conn(db_path)

    try:
        cur = dbc.cursor()
        for one_id in ids:
            cur.execute('UPDATE inbox SET Processed = "true" WHERE ID = ?', (one_id,))
            dbc.commit()
    except:
        logging.error('can not update messages: ' + str(db_path))
        sys.exit(1)

def process_messages():

    for message in get_messages():
        if not message['text']:
            pass
        if not message['phone']:
            pass

        received = message['received']
        if not received:
            received = time.strftime('%Y-%m-%d %H:%M:%S.000', time.gmtime())
        if '.' not in received:
            received = received + '.000'

        text = message['text']
        phone = message['phone']
        orig_params = {'text': text, 'phone': phone, 'time': received, 'feed': ''}

        replacement = {}
        replacement['text'] = urllib.quote_plus(text)
        replacement['phone'] = urllib.quote_plus(phone)
        replacement['time'] = urllib.quote_plus(received)

        chosen_feed = None
        chosen_key = None
        chosen_method = None
        chosen_url = None
        all_paths = get_url_paths()
        for one_path in all_paths:
            if text.lower().startswith(one_path['key'].lower()):
                if (chosen_key is None) or (len(chosen_key) < len(one_path['key'])):
                    chosen_feed = one_path['feed']
                    chosen_key = one_path['key']
                    chosen_method = one_path['method']
                    chosen_url = one_path['url']

        if chosen_feed is None:
            log_issue('No feed for SMS: ' + str(orig_params['text']))
            pass

        orig_params['feed'] = chosen_feed
        replacement['feed'] = urllib.quote_plus(chosen_feed)

        url_path = ''
        part_index = 1
        for url_part in chosen_url.split('%%'):
            part_index = 1 - part_index
            if 1 == part_index:
                if url_part in replacement:
                    url_part = replacement[url_part]
                else:
                    url_part = '%%' + url_part + '%%'
            url_path += url_part

        res = send_message(chosen_method, url_path, orig_params)
        if res:
            confirm_message(message['ids'])

if __name__ == '__main__':
    atexit.register(cleanup)
    log_path = get_log_path()
    if log_path:
        logging.basicConfig(filename=log_path, level=logging.WARNING, format='%(levelname)s [%(asctime)s] %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(levelname)s [%(asctime)s] %(message)s')
    process_messages()
