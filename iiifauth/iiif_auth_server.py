"""
    Experimental Implementation of evolving IIIF Auth 2.0 specification
"""

import os
import re
import json
from datetime import timedelta

from flask import (
    Flask, make_response, request, session, url_for,
    render_template, redirect, send_file, jsonify
)
import iiif2

import iiifauth
from iiifauth.media_helpers import get_media_path, get_media_summaries, get_all_files, make_manifest, get_single_file, \
    get_pattern_name, assert_auth_services, get_actual_dimensions, transform_info_json
from iiifauth.responses import make_acao_response, preflight
from iiifauth.session_db import get_session_tokens, end_session_for_service, get_session_id, establish_session, \
    get_db_token_for_session, kill_db_sessions, get_db_token, close_db

app = Flask(__name__)
app.permanent_session_lifetime = timedelta(minutes=10)
app.secret_key = 'Set a sensible secret key here'
app.database_file = os.path.join(app.root_path, 'iiifauth.db')
app.config.update(dict(
    SERVER_NAME=os.environ.get('IIIFAUTH_SERVER_NAME', None),
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True,
    JSON_SORT_KEYS=False
))


@app.before_request
def func():
    """Make our Flask sessions last longer than the browser window lifetime"""
    session.permanent = True
    session.modified = True


@app.teardown_appcontext
def teardown(error):
    close_db(error)


@app.route('/')
def index():
    """Home page: list all the authed resources we have, and where available, manifests that refer to them"""
    manifest_ids = [file["file"] for file in get_all_files() if file["provideManifest"]]
    return render_template('index.html', media=get_media_summaries(), manifests=manifest_ids)


@app.route('/index.json')
def index_json():
    """JSON version of media list, to help clients"""
    return make_acao_response(jsonify(get_media_summaries()), 200, True)


@app.route('/manifest/<identifier>')
def manifest(identifier):
    """ IIIF Presentation 3.0 Manifest to carry the resource """
    new_manifest = make_manifest(identifier)
    return make_acao_response(jsonify(new_manifest), 200, True)


@app.route('/img/<identifier>')
def image_id(identifier):
    """ Redirect a plain image id to its info.json"""
    resp = redirect(url_for('image_info', identifier=identifier), code=303)
    return make_acao_response(resp)


@app.route('/img/<identifier>/info.json', methods=['GET', 'OPTIONS', 'HEAD'])
def image_info(identifier):
    """
        Return the info.json, with the correct HTTP status code,
        and decorated with the right auth services.
    """

    # Handle CORS explicitly for clarity.
    if request.method == 'OPTIONS':
        print('CORS preflight request for', identifier)
        return preflight()

    uri = url_for('image_id', identifier=identifier, _external=True)

    # Use the iiif2 library to generate the info.json
    # We'll prepend the Auth2 @context; the context has to allow
    iiif2_info = iiif2.web.info(uri, get_media_path(identifier))  # the info.json object
    info = transform_info_json(iiif2_info, version=2)
    assert_auth_services(info, identifier)

    if authorise_probe_request(identifier):
        del info["location"]
        return make_acao_response(jsonify(info), 200)

    # The user is not authorised, but can we provide a degraded version?
    degraded_version = get_single_file(identifier).get('degraded', None)
    if degraded_version:
        location = url_for('image_info', identifier=degraded_version, _external=True)
        # In IIIF Auth 1, we would do this:
        # return make_acao_response(redirect(location, code=302))
        # But in Auth 2, we just do this:
        info["location"] = location
    else:
        del info["location"]

    # Either way, _this_ resource is a 401 - but we don't redirect.
    # Its auth services belong to it... unlike the Auth 1 scenario, where the auth services
    # have to be declared on the degraded version.
    return make_acao_response(jsonify(info), 401)


@app.route('/img/<identifier>/<region>/<size>/<rotation>/<quality>.<fmt>')
def image_api_request(identifier, **kwargs):
    """
        A IIIF Image API request; use iiif2 to generate the tile and return the pixels.
        Also handles a (limited) implementation of maxWidth; enough to demo.
    """
    if authorise_resource_request(identifier):
        params = iiif2.web.Parse.params(identifier, **kwargs)
        config = get_single_file(identifier)
        max_width = config.get('maxWidth', None)
        if max_width is not None:
            full_w = config['width']
            full_h = config['height']
            req_w, req_h = get_actual_dimensions(
                params.get('region'),
                params.get('size'),
                full_w,
                full_h)
            if req_w > max_width or req_h > max_width:
                return make_response("Requested size too large, maxWidth is " + str(max_width))

        tile = iiif2.iiif.IIIF.render(get_media_path(identifier), **params)
        return send_file(tile, mimetype=tile.mime)

    return make_response("Not authorised", 401)


@app.route('/auth/access/<pattern>/<identifier>', methods=['GET', 'POST'])
def access_service(pattern, identifier):
    """
    Access service (might be a login interaction pattern. Doesn't have to be)
    """
    origin = request.args.get('origin')
    if origin is None:
        return make_response("Error - no origin supplied", 400)

    if pattern == 'login':
        return handle_interactive(pattern, identifier, origin, 'login.html')

    elif pattern == 'clickthrough':
        return handle_interactive(pattern, identifier, origin, 'clickthrough.html')

    elif pattern == 'kiosk':
        establish_session(get_access_service_id(pattern, identifier), origin)
        return redirect_to_self_closing_window()

    elif pattern == 'external':
        return make_response("Error - a client should not call an "
                             "external auth access service @id", 400)


def handle_interactive(pattern, identifier, origin, template):
    """
        This is for when the access service profile is interactive.
        This means the user has to do something at the rendered page.
        They might supply credentials (a typical login pattern),
        or might just press a button to acknowledge terms of use or
        a content-advisory notice (a clickthrough pattern).

        The spec does not dictate what happens here. In this demo implementation,
        This is handling GETs (to render that page) and POSTs (submission of the form).

        A real world implementation could do anything. It might bounce the user
        around a single sign on flow.

        This page is not part of a client, or shown in the client.
        The client opens the window (tab) and waits for it to close.
    """

    if authorise_resource_request(identifier):
        # the client opened the window, but we know the user is OK for this resource.
        # so just start or re-start a session and close the window immediately.
        establish_session(get_access_service_id(pattern, identifier), origin)
        return redirect_to_self_closing_window()

    error = None
    if identifier != 'shared':
        policy = get_single_file(identifier)
        if not policy:
            error = f"No access service for {identifier}"

    # In our demo, we're using a POST to indicate that the user has done whatever they need to do
    # in the opened window. This isn't required, but it will be common - e.g., submitting a login form.
    if not error and request.method == 'POST':
        if request.form.get("hidden_clickthrough", None) is not None:
            # The user submitted a clickthrough form.
            establish_session(get_access_service_id(pattern, identifier), origin)
            return redirect_to_self_closing_window()
        elif request.form.get("hidden_login", None) is not None:
            if request.form['username'] != 'username':
                error = 'Invalid username'
            elif request.form['password'] != 'password':
                error = 'Invalid password'
            else:
                establish_session(get_access_service_id(pattern, identifier), origin)
                return redirect_to_self_closing_window()
        else:
            error = 'Unknown interaction for access service'

    return render_template(template, error=error)


def redirect_to_self_closing_window():
    resp = redirect(url_for('self_closing_window'))
    return resp


@app.route('/external-access/<identifier>', methods=['GET', 'POST'])
def external(identifier):
    """This is a 'secret' login page"""
    return handle_interactive('external', identifier, None, 'external.html')


def get_access_service_id(pattern, identifier):
    """
        Simple format for session keys used to maintain sessions for different resources in the same demo.
    """
    return f"access/{pattern}/{identifier}"


@app.route('/auth/self_closing_window')
def self_closing_window():
    """render a window-closing page"""
    return render_template('self_closing_window.html')


@app.route('/auth/token/<pattern>/<identifier>')
def token_service(pattern, identifier):
    """Token service"""
    origin = request.args.get('origin')
    message_id = request.args.get('messageId')
    service_id = get_access_service_id(pattern, identifier)
    session_id = get_session_id()
    token_object = {
        "@context": iiifauth.terms.CONTEXT_AUTH_2,
        "type": "AuthToken2"  # if it's an error, this will change below.
    }
    db_token = None
    print(f"looking for token for session {session_id}, service {service_id}, pattern {pattern}")
    if session_id:
        db_token = get_db_token_for_session(session_id, service_id)
    if db_token:
        print(f"found token {db_token['token']}")
        session_origin = db_token['origin']
        if origin == session_origin or pattern == 'external':
            # don't enforce origin on external auth
            token_object["accessToken"] = db_token['token']
            token_object["expiresIn"] = 600
        else:
            print(f"session origin was {session_origin}")
            token_object["type"] = "AuthTokenError2"
            token_object["error"] = "invalidOrigin"
            token_object["description"] = {"en": ["Not the origin supplied at login"]}
    else:
        token_object["type"] = "AuthTokenError2"
        token_object["error"] = "missingCredentials"
        token_object["description"] = {"en": ["The aspect of the request considered by the token service didn't yield "
                                              "the right information"]}

    if message_id:
        # client is a browser
        token_object['messageId'] = message_id
        return render_template('token.html', token_object=json.dumps(token_object), origin=origin)

    # client isn't using postMessage
    return jsonify(token_object)


@app.route('/auth/logout/<pattern>/<identifier>')
def logout_service(pattern, identifier):
    """Log out service"""
    service_id = get_access_service_id(pattern, identifier)
    end_session_for_service(service_id)
    return "You are now logged out"


@app.route('/resources/<identifier>', methods=['GET', 'OPTIONS', 'HEAD'])
def resource_request(identifier):
    # This might be used as a probe
    # TODO - what happens when this is the MPEG-DASH manifest?
    print("METHOD:", request.method)
    if request.method == 'OPTIONS':
        print('CORS preflight request for', identifier)
        return preflight()

    if request.method == 'HEAD':
        if authorise_probe_request(identifier):
            return make_acao_response('', 200)
        return make_acao_response('', 401)

    policy = get_single_file(identifier)
    if authorise_resource_request(identifier):
        resp = send_file(get_media_path(identifier))
        required_session_origin = None
        if policy.get("format", None) == "application/dash+xml":
            session_id = get_session_id()
            db_token = None
            if session_id:
                db_token = get_db_token_for_session(session_id)
            if db_token:
                print(f"found token {db_token['token']}")
                required_session_origin = db_token['origin']
                # Here we are saying it's OK to echo back the origin we acquired during
                # the auth flow, from the client.
                # This ony happens here, not generally;
                # It happens because this server needs to support adaptive bit rate formats
                # The server could validate the origin, from the request (although not tamper-proof)
                # Or by other means, including whitelists
                # THIS IS ONLY FOR non-simple content requests, and lies outside the auth spec.
                #
                # See https://github.com/IIIF/api/issues/1290#issuecomment-417924635
                #
            else:
                # BUT... the client might be making a credentialled request for
                # something that is not authed?
                required_session_origin = request.headers.get('Origin', None)
        return make_acao_response(resp, origin=required_session_origin)  # for dash.js
    else:
        degraded_version = policy.get('degraded', None)
        if degraded_version:
            content_location = url_for('resource_request', identifier=degraded_version, _external=True)
            print('a degraded version is available at', content_location)
            return redirect(content_location, code=302)

    return make_response("Not authorised", 401)


@app.route('/resources/<manifest_identifier>/<fragment>', methods=['GET'])
def resource_request_fragment(manifest_identifier, fragment):
    id_parts = manifest_identifier.split(".token.")
    if len(id_parts) == 1:
        id_parts.append(None)
    identifier, token = tuple(id_parts)
    reconstructed_path = os.path.join(manifest_identifier, fragment)
    # TODO
    # if not access controlled, just serve the fragment:
    return make_acao_response(send_file(get_media_path(reconstructed_path)))
    # If token is not None, authorise on that. It should be a hash of the user's sesison token
    # (for demo purposes!)
    # Otherwise, look for cookies and use them.


@app.route('/probe/<identifier>', methods=['GET', 'OPTIONS', 'HEAD'])
def probe(identifier):
    if request.method == 'OPTIONS':
        return preflight()

    policy = get_single_file(identifier)
    probe_body = {
        "@context": iiifauth.terms.CONTEXT_AUTH_2,
        "id": url_for('probe', identifier=identifier, _external=True),
        "type": "AuthProbeService2"
    }
    http_status = 200

    if not authorise_probe_request(identifier):
        http_status = 401
        print('The user is not authed for the resource being probed via this service')
        degraded_version = policy.get('degraded', None)
        if degraded_version:
            probe_body["location"] = url_for('resource_request', identifier=degraded_version, _external=True)

    return make_acao_response(jsonify(probe_body), http_status)


def authorise_probe_request(identifier):
    """
        Authorise info.json or probe request based on token
        This should not be used to authorise DIRECT requests for content resources
    """
    policy = get_single_file(identifier)
    services = policy.get('auth_services', [])
    if len(services) == 0:
        print(f'{identifier} is open, no auth required')
        return True

    service_id = None
    match = re.search('Bearer (.*)', request.headers.get('Authorization', ''))
    if match:
        token = match.group(1)
        print(f'token {token} found')
        db_token = get_db_token(token)
        if db_token:
            service_id = db_token['service_id']
            print(f'service_id {service_id} found')
    else:
        print('no Authorization header found')

    if not service_id:
        print('requires access control and no service_id found')
        return False

    # Now make sure the token is for one of this image's services
    identifier_slug = 'shared' if policy.get('shared', False) else identifier
    for service in services:
        pattern = get_pattern_name(service)
        test_service_id = get_access_service_id(pattern, identifier_slug)
        if service_id == test_service_id:
            print('User has access to service', service_id, ' - request authorised')
            return True

    print('info request is NOT authorised')
    return False


def authorise_resource_request(identifier):
    """
        Authorise image API requests based on some aspect of the request - often Cookies
        This method should not accept a token as evidence of identity
    """
    policy = get_single_file(identifier)
    services = policy.get('auth_services', [])
    if len(services) == 0:
        return True  # absence of services in our config indicates "open"

    identifier_slug = 'shared' if policy.get('shared', False) else identifier
    # does the request have a cookie acquired from this image's access service(s)?
    for service in services:
        pattern = get_pattern_name(service)
        test_service_id = get_access_service_id(pattern, identifier_slug)
        if session.get(test_service_id, None):
            # we stored the user's access to this service in the session.
            # There will also be a row in the tokens table, but we don't need that
            # This is an example implementation, there are many ways to do this.
            return True

    # handle other possible authorisation mechanisms, such as IP
    return False


@app.route('/sessiontokens')
def view_session_tokens():
    """concession to admin dashboard"""
    session_tokens = get_session_tokens()
    return render_template('session_tokens.html',
                           session_tokens=session_tokens,
                           user_session=get_session_id())


@app.route('/killsessions')
def kill_sessions():
    """Clear up all my current session tokens"""
    session_id = get_session_id()
    if session_id:
        kill_db_sessions(session_id)

    return redirect(url_for('view_session_tokens'))


if __name__ == '__main__':
    # app.run(ssl_context=app.config.get("SSL_CONTEXT", None))
    app.run()
