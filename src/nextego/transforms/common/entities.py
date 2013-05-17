#!/usr/bin/env python

from canari.maltego.message import Entity, EntityField, MatchingRule

__author__ = 'David Bressler (@bostonlink), GuidePoint Security LLC'
__copyright__ = 'Copyright 2013, Nextego Project'
__credits__ = []

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'David Bressler (@bostonlink), GuidePoint Security LLC'
__email__ = 'david.bressler@guidepointsecurity.com'
__status__ = 'Development'

__all__ = [
    'NextegoEntity',
    'NexposeSite',
    'NexposeVulnerability',
    'NexposeExploit',
    'NexposeMetasploitModule',
    'NexposeEDBExploit',
    'NexposeOS',
    'Port',
    'Service',
    'ServiceVersion'
]

@EntityField(name='siteid', propname='siteid', displayname='Nexpose Site ID')
@EntityField(name='scanid', propname='scanid', displayname='Nexpose Scan ID')
class NextegoEntity(Entity):
    namespace = 'nextego'

"""
You can specify as many entity fields as you want by just adding an extra @EntityField() decorator to your entities. The
@EntityField() decorator takes the following parameters:
    - name: the name of the field without spaces or special characters except for dots ('.') (required)
    - propname: the name of the object's property used to get and set the value of the field (required, if name contains dots)
    - displayname: the name of the entity as it appears in Maltego (optional)
    - type: the data type of the field (optional, default: EntityFieldType.String)
    - required: whether or not the field's value must be set before sending back the message (optional, default: False)
    - choices: a list of acceptable field values for this field (optional)
    - matchingrule: whether or not the field should be loosely or strictly matched (optional, default: MatchingRule.Strict)
    - decorator: a function that is invoked each and everytime the field's value is set or changed.
TODO: define as many custom fields and entity types as you wish:)
"""    

@EntityField(name='targetip', propname='targetip', displayname='Target IP Address')
class NexposeSite(NextegoEntity):
    pass

@EntityField(name='vulnid', propname='vulnid', displayname='Vulnerability ID')
class NexposeVulnerability(NextegoEntity):
    pass

class NexposeExploit(NextegoEntity):
    pass

@EntityField(name='exploittype', propname='exploittype', displayname='Type')
class NexposeMetasploitModule(NextegoEntity):
    pass

@EntityField(name='exploittype', propname='exploittype', displayname='Type')
class NexposeEDBExploit(NextegoEntity):
    pass

class NexposeOS(NextegoEntity):
    pass

@EntityField(name='protocol', propname='protocol', displayname='Protocol')
@EntityField(name='status', propname='status', displayname='Status')
class Port(NextegoEntity):
    pass


@EntityField(name='port', propname='port', displayname='Port')
class Service(NextegoEntity):
    pass

@EntityField(name='port', propname='port', displayname='Port')
@EntityField(name='service', propname='service', displayname='Service')
@EntityField(name='certainty', propname='certainty', displayname='Certainty Score')
class ServiceVersion(NextegoEntity):
    pass