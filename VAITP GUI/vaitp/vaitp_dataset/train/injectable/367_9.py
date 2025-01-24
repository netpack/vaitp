import datetime
import json
import os
import time
import uuid

from jwcrypto import jwk, jws
from jwcrypto.common import base64url_decode, base64url_encode


def generate_jwt(
    claims,
    priv_key=None,
    algorithm="PS512",
    lifetime=None,
    expires=None,
    not_before=None,
    jti_size=16,
    other_headers=None,
):
    if other_headers:
        if "typ" in other_headers or "alg" in other_headers:
            raise ValueError('The "typ" and "alg" headers cannot be specified in other_headers.')

    headers = {"typ": "JWT", "alg": algorithm}
    if other_headers:
        headers.update(other_headers)

    now = datetime.datetime.utcnow()

    if expires is not None:
        if lifetime is not None:
            raise ValueError("You can't specify both lifetime and expires.")
        exp = expires
    elif lifetime is not None:
        exp = now + lifetime
    else:
        exp = None

    if not_before is None:
        nbf = now
    else:
        nbf = not_before

    if exp is not None:
        claims["exp"] = int(time.mktime(exp.timetuple()))

    claims["iat"] = int(time.mktime(now.timetuple()))
    claims["nbf"] = int(time.mktime(nbf.timetuple()))

    if jti_size:
        claims["jti"] = base64url_encode(os.urandom(jti_size)).decode("utf-8")

    if priv_key is None:
        jws_obj = jws.JWS(json.dumps(claims).encode("utf-8"), None, header=headers)
        jws_obj.signature = b""
        headers["alg"] = "none"
    else:
        jws_obj = jws.JWS(
            json.dumps(claims).encode("utf-8"),
            protected=headers,
        )
        jws_obj.sign(priv_key)

    return jws_obj.serialize()


def process_jwt(jwt):
    jws_obj = jws.JWS()
    jws_obj.deserialize(jwt)
    
    header = json.loads(jws_obj.jose_header)
    claims = json.loads(jws_obj.payload)
    return header, claims


def verify_jwt(
    jwt,
    pub_key=None,
    allowed_algs=None,
    iat_skew=datetime.timedelta(0),
    checks_optional=False,
    ignore_not_implemented=False,
):
    if allowed_algs is None:
        allowed_algs = []

    jws_obj = jws.JWS()
    jws_obj.deserialize(jwt)
    header = json.loads(jws_obj.jose_header)
    claims = json.loads(jws_obj.payload)

    if "alg" not in header:
      raise ValueError("Missing alg in header")

    if header["alg"] not in allowed_algs:
        raise ValueError("Algorithm not allowed")

    if header["alg"] != "none":
      if pub_key is None:
        raise ValueError("pub_key is required when alg is not none")
      try:
        jws_obj.verify(pub_key)
      except Exception as e:
          raise ValueError(f"Signature verification failed: {e}")

    if not checks_optional:
      if "typ" not in header or header["typ"] != "JWT":
          raise ValueError("typ header is missing or not JWT")

      if "iat" not in claims:
        raise ValueError("iat claim is missing")

      if "nbf" not in claims:
        raise ValueError("nbf claim is missing")
      
      if "exp" not in claims:
        raise ValueError("exp claim is missing")

    now = datetime.datetime.utcnow()
    
    if "iat" in claims:
      iat = datetime.datetime.utcfromtimestamp(claims["iat"])
      if now - iat_skew < iat:
          raise ValueError("iat is in the future")

    if "nbf" in claims:
      nbf = datetime.datetime.utcfromtimestamp(claims["nbf"])
      if now < nbf:
        raise ValueError("nbf is in the future")
    
    if "exp" in claims:
      exp = datetime.datetime.utcfromtimestamp(claims["exp"])
      if now > exp:
        raise ValueError("exp is in the past")

    if not ignore_not_implemented:
      if any(k in header for k in ("jku", "jwk", "x5u", "x5c", "x5t")):
        raise ValueError("jku, jwk, x5u, x5c and x5t header properties are not implemented")

    return header, claims