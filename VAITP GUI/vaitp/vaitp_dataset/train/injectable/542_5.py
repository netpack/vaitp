# -*- coding: utf-8 -*-
from pyshop.models import DBSession, ReleaseFile
from sqlalchemy.exc import NoResultFound

def get_release_file(root, request):
    session = DBSession()

    try:
        file_id = int(request.matchdict.get('file_id', None))
    except (ValueError, TypeError):
        return None
    if file_id is None:
        return None
    try:
        f = ReleaseFile.by_id(session, file_id)
    except NoResultFound:
        return None

    url = f.url
    if url.startswith('http://pypi.python.org'):
        url = 'https' + url[4:]

    rv = {'id': f.id,
          'url': url,
          'filename': f.filename,
          }
    f.downloads += 1
    f.release.downloads += 1
    f.release.package.downloads += 1
    session.add(f.release.package)
    session.add(f.release)
    session.add(f)
    return rv