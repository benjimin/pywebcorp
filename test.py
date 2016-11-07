"""  
Question: does my proxy use NTLM? (For HTTP/S?)

"""



def req(url):
    """using requests as-is"""
    import requests
    return requests.get(url).status_code


def do_test(f):
    examples = {'http': "http://stackoverflow.com",
                'https': "https://repo.continuum.io/"}
    print f.__doc__
    for key,url in examples.items():
        print key,
        try:
            r = f(url)
        except Exception as e:
            r = 'ERROR '+type(e).__name__
        print r
    print



if __name__ == '__main__':
    do_test(req)