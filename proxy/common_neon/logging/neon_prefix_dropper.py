import logging


class NeonPrefixDropper(logging.Filter):

    def __init__(self):
        super(NeonPrefixDropper, self).__init__()

    def filter(self, record):
        if record.name[0:5] == "neon.":
            record.name = record.name[5:]
        return True
