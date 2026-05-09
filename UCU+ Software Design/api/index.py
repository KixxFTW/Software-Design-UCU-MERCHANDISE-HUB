import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from run import app

def handler(event, context):
    from werkzeug.test import EnvironBuilder

    method = event.get('method', 'GET')
    path = event.get('path', '/')
    headers = event.get('headers', {})
    body = event.get('body', '')
    query_string = event.get('queryString', '')

    builder = EnvironBuilder(
        method=method,
        path=path,
        query_string=query_string,
        headers=headers,
        data=body
    )
    environ = builder.get_environ()
    environ['wsgi.url_scheme'] = headers.get('x-forwarded-proto', 'https')

    status_code = [200]
    response_headers = [[]]
    response_body = []

    def start_response(status, headers_list):
        status_code[0] = int(status.split()[1])
        response_headers[0] = headers_list

    result = app(environ, start_response)
    for chunk in result:
        if isinstance(chunk, bytes):
            response_body.append(chunk)
        else:
            response_body.append(chunk.encode('utf-8') if chunk else b'')

    return {
        'statusCode': status_code[0],
        'headers': dict(response_headers[0]),
        'body': b''.join(response_body).decode('utf-8')
    }
