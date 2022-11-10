from flask import make_response


def make_acao_response(response_object, status=None, cache=None, origin=None, allow_credentials=False):
    """
        We're handling CORS directly for clarity
        Create a response with the correct CORS headers
    """
    resp = make_response(response_object, status)

    # Purely to cater for the MPEG-DASH demo we are allowing specific origin and credentials.
    # For content resources requested simply (e.g., as `src` attributes), we should not
    # have specific origins or credentialed requests.
    resp.headers['Access-Control-Allow-Origin'] = origin or '*'
    if allow_credentials:
        resp.headers['Access-Control-Allow-Credentials'] = "true"
    if cache is None:
        resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    else:
        resp.headers['Cache-Control'] = 'public, max-age=120'
    return resp


def preflight():
    """Handle a CORS preflight request"""
    resp = make_acao_response('', 200)
    resp.headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS, HEAD'
    resp.headers['Access-Control-Allow-Headers'] = 'Authorization'
    return resp
