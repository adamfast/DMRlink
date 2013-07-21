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
