# Copyright (c) 2013 Cortney T. Buffington, N0MJS n0mjs@me.com
#
# This work is licensed under the Creative Commons Attribution-ShareAlike
# 3.0 Unported License.To view a copy of this license, visit
# http://creativecommons.org/licenses/by-sa/3.0/ or send a letter to
# Creative Commons, 444 Castro Street, Suite 900, Mountain View,
# California, 94041, USA.

# Logging system configuration

from logging.config import dictConfig
import logging

dictConfig({
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
    },
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s'
        },
        'timed': {
            'format': '%(levelname)s %(asctime)s %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple'
        },
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'formatter': 'simple',
            'filename': '/tmp/ipsc.log',
        },
        'console-timed': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'timed'
        },
        'file-timed': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'formatter': 'timed',
            'filename': '/tmp/ipsc.log',
        },
    },
    'loggers': {
        'ipsc': {
#            'handlers': ['file-timed', 'console-timed'],
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        }
    }
})
logger = logging.getLogger('ipsc')
