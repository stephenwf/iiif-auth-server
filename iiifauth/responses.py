from flask import make_response


def make_acao_response(response_object, status=None, cache=None, origin=None):
    """We're handling CORS directly for clarity"""
    resp = make_response(response_object, status)
    resp.headers['Access-Control-Allow-Origin'] = origin or '*'
    # only for MPEG-DASH:
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
