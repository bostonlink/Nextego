#!/usr/bin/env python

import os.path
from common.pyNexpose import nexlogin, nexlogout, checkdir
from common.reportparser import nexposeServiceVer, reportChecker
from canari.framework import configure
from canari.config import config
from common.entities import Service, ServiceVersion
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
	label='To Service Version',
	description='Outputs identified Service Versions',
	uuids=[ 'nextego.v2.NexposeServicetoServiceVersion' ],
	inputs=[ ( 'Nexpose', Service ) ],
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
	
	# have to add logic to pass on certain values that was not fingerprinted
	for dic in nexposeServiceVer(reporto):
		for key, val in dic.iteritems():
			if key == request.value:
				response += ServiceVersion(val[0] + '-' + val[1],
                    	siteid=siteid,
                    	scanid=request.fields['scanid'],
                    	port=request.fields['port'],
                    	service=request.value,
                    	certainty=val[2])

	return response
	nexlogout(session)