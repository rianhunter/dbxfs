# don't abuse this file!

# for the 99.9% of you for which the preceding comment is unclear:

# keep this file small, if there is a theme of utility functions then
# put group them into a separate file

import datetime

def utctimestamp(dt):
    assert dt.tzinfo is None
    return dt.replace(tzinfo=datetime.timezone.utc).timestamp()
