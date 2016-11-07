"""
Here is the SSPI authentication for NTLM.

Compartmentalised here to permit testing ctypes/pywin32 versions.
"""

import base64
import logging

try:
    from sspi import ClientAuth
    raise ImportError # comment-out this line to use pywin32 if available
except ImportError:
    from ctypes_sspi import ClientAuth
  
def sspi_ntlm_auth(scheme='NTLM'):
    handle = ClientAuth(scheme)
    def generate_answer(challenge=None):
        logging.debug("challenge: "+challenge)
        if challenge is not None:
            assert challenge.startswith(scheme) # or, could be a series of challenge options?
            challenge = base64.b64decode(challenge[len(scheme):])
        status, token_buffer = handle.authorize(challenge)
        token = scheme + ' ' + base64.b64encode(token_buffer[0].Buffer)
        return token
    return generate_answer
    
