import sqlite3
import uuid

from flask import session, g, current_app


def get_session_tokens():
    database = get_db()
    database.execute("delete from tokens where created < date('now','-1 day')")
    database.commit()
    session_tokens = query_db('select * from tokens order by created desc')
    return session_tokens


def end_session_for_service(service_id):
    session.pop('service_id')
    database = get_db()
    database.execute('delete from tokens where session_id=? and service_id=?',
                     [get_session_id(), service_id])
    database.commit()


def get_session_id():
    """Helper for session_id"""
    return session.get('session_id', None)


def make_session(service_id, origin):
    """
        Establish a session for this user and this resource.
        This is not a production application.
    """
    # Get or create a session ID to keep track of this user's permissions
    session_id = get_session_id()
    if session_id is None:
        session_id = uuid.uuid4().hex
        session['session_id'] = session_id
    print("This user's session is", session_id)

    if origin is None:
        origin = "[No origin supplied]"
    print('User authed for service ', service_id)
    print('origin is ', origin)
    # The token can be anything, but you shouldn't be able to
    # deduce the cookie value from the token value.
    # In this demo the client cookie is a Flask session cookie,
    # we're not setting an explicit IIIF auth cookie.

    # Store the fact that user can access this service in the session
    session[service_id] = True
    # Now store a token associated that represents the user's access to this service
    token = uuid.uuid4().hex
    print('minted token:', token)
    print('session id:', session_id)

    database = get_db()
    database.execute("delete from tokens where session_id=? and service_id=?",
                     [session_id, service_id])
    database.commit()
    database.execute("insert into tokens (session_id, service_id, token, origin, created) "
                     "values (?, ?, ?, ?, datetime('now'))",
                     [session_id, service_id, token, origin])
    database.commit()


def get_db_token_for_session(session_id, service_id=None):
    if service_id is None:
        db_token = query_db('select * from tokens where session_id=?', [session_id], one=True)
    else:
        db_token = query_db('select * from tokens where session_id=? and service_id=?',
                            [session_id, service_id], one=True)
    return db_token


def get_db_token(token):
    return query_db('select * from tokens where token=?', [token], one=True)


def kill_db_sessions(session_id):
    database = get_db()
    database.execute("delete from tokens where session_id=?", [session_id])
    database.commit()
    for key in list(session.keys()):
        if key != 'session_id':
            session.pop(key, None)


def get_db():
    """
    Opens a new database connection if there is none yet for the
    current application context, and ensures the token table exists in it.
    """
    if not hasattr(g, 'sqlite_db'):
        conn = sqlite3.connect(current_app.database_file)
        conn.row_factory = sqlite3.Row
        conn.cursor().executescript("create table if not exists tokens ( "
                                    "session_id text not null, "
                                    "service_id text not null, "
                                    "token text not null, "
                                    "origin text not null, "
                                    "created text not null"
                                    ");")
        g.sqlite_db = conn
    return g.sqlite_db


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def close_db(error):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()


