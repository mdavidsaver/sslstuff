#!/usr/bin/env python
"""Simple approximation of

  openssl x509 -text -in <myname>.pem
"""

from __future__ import print_function

from OpenSSL import crypto
from pyasn1.codec.ber import decoder

import sys
from calendar import timegm
import time
from struct import Struct

# YYYYMMSSHHMMSSZ
_dt = Struct('!4s2s2s2s2s2sc')

def DT2sec(s):
  parts = _dt.unpack(s)
  assert parts[-1] in ['Z','z']
  TT = tuple(map(int,parts[:6]))+(0,0,-1)
  return timegm(TT)

FN=sys.argv[1]

with open(FN,'rb') as F:
  cert = F.read()

C = crypto.load_certificate(crypto.FILETYPE_PEM, cert)

print('Version',C.get_version())
print('SN',hex(C.get_serial_number()))
print('Sig algo',C.get_signature_algorithm())
print('Issuer',C.get_issuer().get_components())
print('Subject',C.get_subject().get_components())
print('Validity from:', time.ctime(DT2sec(C.get_notBefore())))
print('           to:', time.ctime(DT2sec(C.get_notAfter())))
print('Key size', C.get_pubkey().bits())
for i in range(C.get_extension_count()):
  E = C.get_extension(i)
  print(' ',E.get_short_name(),(' crit' if E.get_critical() else ''))
  try:
    print('    ',decoder.decode(E.get_data()))
  except:
    print('    No Decode ')
  finally:
    print(repr(E.get_data()))
