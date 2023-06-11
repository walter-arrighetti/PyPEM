#!/usr/bin/env python
##################################################
##  PyPEM.py                                    ##
##################################################
##  Python module to parse, generate, validate  ##
##  and perform other ops on PEM-encoded files  ##
##  conforming with the following standards:    ##
##      RFC-7468 - PKIX, PKSCS, CMS structures  ##
##      RFC-4716 - SSH Public Key file format   ##
##      RFC-4880 - OpenPGP message format       ##
##______________________________________________##
##  Copyright (C) 2011-2023 Walter Arrighetti   ##
##  coding by: Walter Arrighetti, PhD, CISSP    ##
##################################################
_version = "0.8"
import hashlib
import base64
import re

try:
	#import pyasn1
	import asn1
	_hasASN1 = True
except:	_hasASN1 = False

class OID:
	def __init__(self, oid0, oid1=None):
		if oid0 and type(oid0)==type(""):	# Parse as a string x.y.z....
			oid0 = oid0.split('.')
		elif type(oid0)==type(1):	oid0 = [str(oid0)]
		elif oid0 and type(oid0) in [type([]),type(list([]))]:	# Parse as a tuple/list [x,y,z,...] or (x,y,z,...)
			oid0 = list(oid0)
		elif oid0.isinstance(OID):	oid0 = oid0.str.split('.')
		else:	return False
		if oid1:
			if type(oid1)==type(""):	oid1 = oid1.split('.')
			elif type(oid1)==type(1):	oid1 = [str(oid1)]
			elif type(oid1) in [type([]),type(list([]))]:	oid1 = list(oid1)
			elif oid1.isinstance(OID):	oid1 = oid1.str.split('.')
			else:	return False
			oid0 += oid1
		try:	oid0 = list(map(int,oid0))
		except:	return False
		self.list, self.depth, self.tuple, self.str = oid0, len(oid0), tuple(oid0), '.'.join(list(map(str,oid0)))
		return self.list
	#def str(self):	return self.oid.join('.')
def isOID(bytes):	return bool(OID(bytes))

class _ASN1_Base(object):
	""" Base class for parsed ASN.1 objects. """
	def __init__(self, payload):
		global _hasASN1
		if isinstance(payload, unicode):	payload = payload.encode('ascii')
		self._payload = payload
		if _hasASN1:
			#received, substrate = pyasn1.codec.native.decoder.decode(self._payload,asn1Spec=pyasn1.codec.native.decoder.Record())
			self._enc, self._dec = asn1.Encoder(), asn1.Decoder()
			self._dec.start(self._payload)
			#tag, value = self._dec.read()
			#self._payload = self._enc.output()
			#self._enc.write(payload,asn1.ObjectIdentifier)
		pass
	def __repr__(self):
		return '<{0}(ASN.1 object with SHA-1 digest {1!r})>'.format( self.__class__.__name__, hashlib.sha1(self._payload).hexdigest() )
	def __str__(self):	return repr(self)
	def __eq__(self, other):
		if not isinstance(other, self.__class__):	return NotImplemented
		return (type(self)==type(other) and self._payload==other._payload)
	def __ne__(self, other):
		if not isinstance(other, self.__class__):	return NotImplemented
		return (type(self)!=type(other) or self._payload!=other._payload)
	def __hash__(self):	return hash(self._payload)
	def raw(self):	return self._payload
	def readall(self, data=None):
		if not data:	data = self._payload
		tags = []
		while True:
			this_tag = self._dec.read()
			if this_tag:	tags.append(this_tag)
			else:	return tags
class ContentInfo(_ASN1_Base):
	""" PKCS#7 or Cryptographic Message Syntac (CMS) object."""
	pass
class DHParameters(_ASN1_Base):
	""" Diffie-Hellmann parameters. """
	pass
class Certificate(_ASN1_Base):
	""" Generic cryptographic certificate. """
	pass
class AttributeCertificate(Certificate):
	""" Attribute certificate. """
	pass
class CertificateList(_ASN1_Base):
	""" Certificates' list."""
	pass
class CertificateRequest(_ASN1_Base):
	""" Certificate Signing Request. """
	pass
class _ASN1_Key(_ASN1_Base):
	""" Generic cryptographic key template-class. """
	pass
class PublicKeyInfo(_ASN1_Key):
	""" Generic cryptographic key. """
	pass
class PrivateKeyInfo(_ASN1_Key):
	""" Generic private key."""
	pass
class SubjectPublicKeyInfo(PublicKeyInfo):
	""" Generic public key. """
	pass
class EncryptedPrivateKeyInfo(PrivateKeyInfo):
	""" Encrypted private key."""
	pass
class RSAPrivateKey(PrivateKeyInfo):
	""" RSA private key. """
	pass


__idpkcs, __idpkixmod, __idsmmod = OID(1.2.840.113549.1), OID(1,3,6,1,5,5,7,0), OID(__idpkcs,(9.16,0))
__PEM_Types = {		# items are 4-ple  (ASN1-class-name, class-OID, OID-x509-name, RFC-number)
	"CERTIFICATE":          (Certificate, OID(__idpkixmod,18),"id-pkix1-e", 5280),
	"X509 CRL":             (CertificateList, OID(__idpkixmod,18),"id-pkix1-e", 5280),
	"CERTIFICATE REQUEST":  (CertificateRequest, OID(__idpkcs,OID(10,1,1)),"id-pkcs10", 2986),
	"PKCS7":                (ContentInfo, OID(__idpkcs,OID(7,0,1)),"id-pkcs7*", 2315),
	"CMS":                  (ContentInfo, OID(__idsmmod,24),"id-cms2004", 5625),
	"PRIVATE KEY":          (PrivateKeyInfo, OID(__idpkcs,OID(8,1,1)),"id-pkcs8", 5208),	# ==OneAsymmetricKey [RFC5958, id-aKPV1, OID(__idsmmod,50)]
	"ENCRYPTED PRIVATE KEY":(EncryptedPrivateKeyInfo, OID(__idsmmod,50),"id-aKPV1", 5958),
	"ATTRIBUTE CERTIFICATE":(AttributeCertificate, OID(__idpkixmod,61),"id-acv2", 5755),
	"PUBLIC KEY":           (SubjectPublicKeyInfo, OID(__idpkixmod,18),"id-pkix1-e", 5280),
	"RSA PRIVATE KEY":      (RSAPrivateKey, OID(__idpkcs,OID(8,1,1)),"", 0),
	"DH PARAMETERS":        (DHParameters, None,"", 0),
	"NEW CERTIFICATE REQUEST":(CertificateRequest, OID(__idpkixmod,18),"", 0),
	#"PRIVACY-ENHANCED MESSAGE":(None, None, "", 1421),
}
def PEM_parse(data, strict=False):
	""" Extract PEM objects from 'data'. """
	__PEMre = re.compile(r"-----BEGIN (?P<label0>[A-Z0-9 ]*)-----\s*(?P<payload>([A-Za-z0-9+/]|\s)+[=]?\s*[=]?)\s*-----END (?P<label1>[A-Z0-9 ]*)-----")
	def _checklabel(match):
		if len(match) and (match.find('  ')>0 or match[0]==' ' or match[-1]==' '):	return False
		return True
	sepr = [ [obj.group('label0').strip(),obj.group('payload').translate(None," \t\n\r\f\v")] for obj in __PEMre.finditer(data) if (_checklabel(obj.group('label0'))!=False and _checklabel(obj.group('label1'))!=False)]
	for n in reverse(range(len(sepr)):
		if (not sepr[n][0]) or (not sepr[n][1]) or (strict and sepr[n][0]!=obj.group('label1').strip()):	del sepr[n]	# RFC does not manadate checking 'label0'=='label'
		elif sepr[n][0] in __PEM_Types.keys():
			sepr[n] = __PEM_Types[sepr[n][0]][0] ( base64.b64decode(sepr[n][1]) )
		elif not strict:
			sepr[n] = ( sepr[n][0], base64.b64decode(sepr[n][1]) )
		else:	del sepr[n]
	if not sepr:	return []
	return sepr
def PEM_parse_file(filename, strict=False):
	""" Reads 'filename' and parses PEM objects from it. """
	with open(filename,'rb') as f:	return PEM_parse(f.read(), strict=strict)
def PEM_write(objs, newline='\n'):
	def chunkstring(data,length):
		return [data[0+i:length+i] for i in xrange(0,len(data),length)]
	def _checklabel(match):
		if (not match) or type(match)!=type("") or match.find('  ')>0 or not re.match(r"[A-Za-z0-9 ]*",label):	return False
		return match.strip().toupper()
	if not newline:	newline=""
	elif newline not in ['\n',"",'\r',"\n\r","\r\n"]:	return False
	if type(objs) not in [type([]),type(tuple([]))]:	objs = [objs]
	payl = []
	for n in range(len(objs)):
		label = False
		if type(objs[n]) in [type([]),type(list([]))] and len(objs[n])==2 and type(objs[n][0])==type(objs[n][1])==type(""):
			label, asn1 = objs[n][0], objs[n][1]
		else:
			for typ in __PEM_Types.keys():
				if objs[n].isinstance(__PEM_Types[typ][0]):
					label, asn1 = typ, objs[n].raw()
					break
		if not label or not asn1:	continue
		payl.append("-----BEGIN %s-----"%label)
		payl.extend(list(chunkstring( base64.b64encode(str(asn1)) ,64)))
		payl.append("-----END %s-----"%label)
	return newline.join(payl)
def PEM_write_file(filename, objs, newline='\n'):
	payload = PEM_write(objs, newline=newline)
	if not payload:	return False
	with open(filename,'wb') as f:	return f.write(payload)

###EXAMPLE THAT READS AND REWRITES A (CHAIN OF) ASN.1 TYPE(S)
#	cert = PEM_parse_file(filename)
#	PEM_write_file("out.pem",cert)
