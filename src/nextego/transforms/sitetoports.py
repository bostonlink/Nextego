#!/usr/bin/env python

import os.path
from common.pyNexpose import nexlogin, nexlogout, checkdir
from common.reportparser import nexposePort, reportChecker
from canari.framework import configure
from canari.config import config
from common.entities import Port, NexposeSite
from canari.maltego.message import MaltegoException

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
	label='To Ports',
	description='Outputs Open Ports',
	uuids=[ 'nextego.v2.NexposeSitetoPorts' ],
	inputs=[ ( 'Nexpose', NexposeSite ) ],
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
	
	for dic in nexposePort(reporto):
		for key, val in dic.iteritems():
			response += Port(key,
                    	siteid=siteid,
                    	scanid=request.fields['scanid'],
                    	protocol=val[0],
                    	status=val[1])

	return response
	nexlogout(session)