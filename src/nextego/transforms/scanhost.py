#!/usr/bin/env python

import elementtree.ElementTree as ET
from datetime import datetime
from time import sleep
from common.pyNexpose import nexlogin, nexlogout, host_site, sitesave, sitescan, scanstatus
from canari.maltego.entities import IPv4Address
from canari.maltego.utils import progress
from canari.framework import configure
from common.entities import NexposeSite

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
    label='Launch Vulnerability Scan',
    description='Creates a site in nexpose and launches a scan',
    uuids=[ 'nextego.v2.IPv4AddressToNexposeVulnScan' ],
    inputs=[ ( 'Nexpose', IPv4Address ) ],
    debug=True
)
def dotransform(request, response):
    # Nespose API session login
    session = nexlogin()
    # Nexpose site creation
    sitename = datetime.today().strftime("%Y%m%d-%H%M%S") + '-MaltegoSite'
    newsite = host_site(sitename, request.value)
    nexsite = sitesave(session, newsite)
    resxml = ET.fromstring(nexsite)
    siteid = resxml.attrib.get('site-id')
    progress(10)
    if resxml.attrib.get('success') == '1':
        # Nexpose Scan Site
        launchscan = sitescan(session, siteid)
        launchres = ET.fromstring(launchscan)
        progress(25)
        if launchres.attrib.get('success') == '1':
            for child in launchres:
                scanid = child.attrib.get('scan-id')
                status = scanstatus(session, scanid)
                statusxml = ET.fromstring(status)
                progress(50)
                while statusxml.attrib.get('status') == 'running':
                    sleep(5)
                    status = scanstatus(session, scanid)
                    statusxml = ET.fromstring(status)
                    continue
                progress(100)
                response += NexposeSite(
                    sitename,
                    siteid=siteid,
                    scanid=scanid,
                    targetip=request.value)

    return response
    nexlogout(session)