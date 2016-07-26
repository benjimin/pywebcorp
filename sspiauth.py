"""
Here is the SSPI authentication.

Compartmentalised here to permit testing ctypes/pywin32 versions.
"""

import base64

try:
    import sspi
except ImportError:
    raise ImportError # TODO: ctypes! (nb. should do that in a try block too)
  
def sspiauth(scheme='NTLM'):
    handle = sspi.ClientAuth(scheme)
    def generate_answer(challenge=None):
        if challenge is not None:
            assert challenge.startswith(scheme) # or, could be a series of challenge options?
            challenge = base64.b64decode(challenge[len(scheme):])
        status, token_buffer = handle.authorize(challenge)
        token = scheme + ' ' + base64.b64encode(token_buffer[0].Buffer)
        return token
    return generate_answer

if __name__ == '__main__': import demo