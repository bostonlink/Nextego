#!/usr/bin/env python

import os.path
from common.pyNexpose import nexlogin, nexlogout, checkdir
from common.reportparser import nexposePortTests, nexposeVulns, reportChecker
from canari.framework import configure
from canari.config import config
from common.entities import Port, NexposeVulnerability
from canari.maltego.message import MaltegoException, Label

__author__ = 'David Bressler (@bostonlink), GuidePoint Security LLC'
__copyright__ = 'Copyright 2013, Nextego Project'
__credits__ = []

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'David Bressler (@bostonlink), GuidePoint Security LLC'
__email__ = 'david.bressler@guidepointsecurity.com'
__status__ = 'Development'

__all__ = ['dotransform']

@configure(
	label='To Vulnerability',
	description='Outputs Identified Vulnerabilities',
	uuids=[ 'nextego.v2.NexposePorttoVuln' ],
	inputs=[ ( 'Nexpose', Port ) ],
	debug=True
)
def dotransform(request, response):
	checkdir(config['nexpose/reportdir'])
	# Nexpose API session login
	session = nexlogin()
	# Nexpose Adhoc report generation and save to file
	siteid = request.fields['siteid']
	report = '%s.xml' % siteid
	reportstatus = reportChecker(session, siteid, report)
	if reportstatus == True:
		f = open(os.path.join(config['nexpose/reportdir'], report))
		reporto = f.read()
		f.close
	else:
		raise MaltegoException('Something went wrong with the report checks')
	
	for dic in nexposePortTests(reporto):
		for key, val in dic.iteritems():
			if request.value == key:
				for key1, val1 in val.iteritems():
					test = key1
					for dic in nexposeVulns(reporto):
						for key2, val2 in dic.iteritems():
							if test == key2:
								e = NexposeVulnerability(val2[0],
                    				siteid=siteid,
                    				scanid=request.fields['scanid'],
                    				vulnid=key2)

								e += Label('cvss Score', val2[2])
								e += Label('Severity', val2[1])
								response += e
			else:
				pass

	return response
	nexlogout(session)