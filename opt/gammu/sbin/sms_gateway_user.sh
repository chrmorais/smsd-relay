#!/bin/sh

HOMEDIR=/opt/gammu/var/lib/gammu
mkdir -p $HOMEDIR

adduser --system --home $HOMEDIR --no-create-home --ingroup dialout --disabled-login sms-gateway

chown sms-gateway $HOMEDIR
chown sms-gateway $HOMEDIR/*

