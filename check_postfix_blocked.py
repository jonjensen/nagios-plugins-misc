#!/usr/bin/env python

# check_postfix_blocked.py
# by Jon Jensen <jon@endpoint.com>
# 2018-03-12 initial version
# 2018-04-06 allow specifying log file path
#
# This is a Nagios plugin that scans Postfix logs (in syslog format) to
# count outbound messages blocked or greylisted as spam and alert based
# on supplied thresholds.

import optparse
import re
import sys

# Nagios status codes
OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3

class PostfixBounces:
    def __init__(self, filehandle, warn, crit, debug=False):
        self.fh = filehandle
        self.warn = warn
        self.crit = crit
        self.debug = debug
        self.processed = False
        self.blocked = dict()
        self.worrisome = dict()
        self.exit_code = None
        self.exit_note = None

    def process(self):
        bounced_re = re.compile(r" postfix/smtp\[\d+\]: ([0-9A-Za-z]+): .*, status=(?:bounced|deferred) ")

        site_rejection_regexes = (
            # postfix/smtp[9978]: E491D4296: to=<MASKED@mail.ru>, relay=mxs.mail.ru[94.100.180.31]:25, delay=5, delays=0.01/0/1.5/3.5, dsn=5.0.0, status=bounced (host mxs.mail.ru[94.100.180.31] said: 550 spam message rejected. Please visit http://help.mail.ru/notspam-support/id?c=fhtDsnELae77cN6t9-j6dIPfAZm8McBDFOVns8DZ9Q1n62fvJQEllQsAAAAOxQEA6zMdHg~~ or  report details to abuse@corp.mail.ru. Error code: B2431B7EEE690B71ADDE70FB74FAE8F79901DF8343C031BCB367E5140DF5D9C0EF67EB6795250125. ID: 0000000B0001C50E1E1D33EB. (in reply to end of DATA command))
            r" said: 550 .*spam",
            # postfix/smtp[22442]: C3F1FD6E: to=<MASKED@EARTHLINK.NET>, relay=mx1.EARTHLINK.NET[209.86.93.226]:25, delay=0.55, delays=0.01/0.02/0.48/0.04, dsn=5.0.0, status=bounced (host mx1.EARTHLINK.NET[209.86.93.226] said: 550 IP 45.79.0.243 is blocked by EarthLink. Go to earthlink.net/block for details. (in reply to MAIL FROM command))
            r" said: 550 .*blocked",
            # postfix/smtp[25122]: B60EA42D4: host hotmail-com.olc.protection.outlook.com[104.47.41.33] said: 451 4.7.500 Server busy. Please try again later from [174.136.107.245]. (AS843) (in reply to RCPT TO command)
            # postfix/smtp[25122]: B60EA42D4: to=<MASKED@hotmail.com>, relay=hotmail-com.olc.protection.outlook.com[104.47.42.33]:25, delay=0.77, delays=0.06/0/0.61/0.09, dsn=4.7.500, status=deferred (host hotmail-com.olc.protection.outlook.com[104.47.42.33] said: 451 4.7.500 Server busy. Please try again later from [174.136.107.245]. (AS843) (in reply to RCPT TO command))
            r" said: 451 .*busy",
        )
        site_rejection_re = re.compile('|'.join(site_rejection_regexes), re.IGNORECASE)

        for line in self.fh:
            m = re.search(bounced_re, line)
            if not m: continue
            queue_id = m.group(1)
            self.blocked[queue_id] = True
            if self.debug: sys.stderr.write("blocked: " + line)
            if not re.search(site_rejection_re, line): continue
            self.worrisome[queue_id] = True
            if self.debug: sys.stderr.write("worrisome: " + line)

        self.processed = True

    def report(self):
        status_string = {
            OK:       'OK',
            WARNING:  'WARN',
            CRITICAL: 'CRITICAL',
            UNKNOWN:  'UNKNOWN',
        }

        blocked_count   = len(self.blocked.keys())
        worrisome_count = len(self.worrisome.keys())
        if not self.processed:
            self.exit_code = UNKNOWN
            self.exit_note = "%s No mail log analysis to report on" % status_string[self.exit_code]
            return
        elif worrisome_count >= self.crit:
            self.exit_code = CRITICAL
        elif worrisome_count >= self.warn:
            self.exit_code = WARNING
        else:
            self.exit_code = OK

        self.exit_note = "%(status)s %(worrisome)d worrisome | blocked=%(blocked)d worrisome=%(worrisome)d" % \
            dict(
                status=status_string[self.exit_code],
                blocked=blocked_count,
                worrisome=worrisome_count,
            )

def main():
    parser = optparse.OptionParser()
    parser.add_option('-w', '--warn', type='int', help='warning threshold')
    parser.add_option('-c', '--crit', type='int', help='critical threshold')
    parser.add_option('-f', '--file', type='str', default='/var/log/maillog', help='verbosity level')
    parser.add_option('-v', '--verbose', action='count', default=0, help='verbosity level')
    options, _ = parser.parse_args()

    if not options.warn and not options.crit:
        parser.print_help()
        return UNKNOWN

    debug = options.verbose > 2

    with open(options.file) as fh:
        pb = PostfixBounces(filehandle=fh, warn=options.warn, crit=options.crit, debug=debug)
        pb.process()
        pb.report()
        print(pb.exit_note)
        return pb.exit_code

if __name__ == '__main__':
    sys.exit(main())

# vim: set et ts=4 sw=4 sts=4 shiftround:
