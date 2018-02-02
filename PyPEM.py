#!/usr/bin/env python
##################################################
##  PyPEM.py                                    ##
##______________________________________________##
##  Python module to parse, generate, validate  ##
##  and perform other ops on PEM-encoded files  ##
##______________________________________________##
##  Copyright (C) 2011-2013 Walter Arrighetti   ##
##  coding by: Walter Arrighetti, PhD, CISSP    ##
##################################################
_version = "0.65"
import hashlib
import base64
import re



class _ASN1_Base(object):
	""" Base class for parsed ASN.1 objects. """
	def __init__(self, payload):
		if isinstance(payload, unicode):	payload = payload.encode('ascii')
		self._payload = payload
	def __repr__(self):
		return '<{0}(ASN.1 object with SHA-1 digest {1!r})>'.format( self.__class__.__name__, hashlib.sha1(self._payload).hexdigest() )
	def __str__(self):	return self._payload
	def __eq__(self, other):
		if not isinstance(other, self.__class__):	return NotImplemented
		return (type(self)==type(other) and self._payload==other._payload)
	def __ne__(self, other):
		if not isinstance(other, self.__class__):	return NotImplemented
		return (type(self)!=type(other) or self._payload!=other._payload)
	def __hash__(self):	return hash(self._payload)
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


__PEM_Types = {		# items are 4-ple  (class[ASN.1 type], RFC#, X.509 module)
	"CERTIFICATE":          (Certificate,5280,"id-pkix1-e"),
	"X509 CRL":             (CertificateList,5280,"id-pkix1-e"),
	"CERTIFICATE REQUEST":  (CertificateRequest,2986,"id-pkcs10"),
	"PKCS7":                (ContentInfo,2315,"id-pkcs7*"),
	"CMS":                  (ContentInfo,5625,"id-cms2004"),
	"PRIVATE KEY":          (PrivateKeyInfo,5208,"id-pkcs8"),	# ==OneAsymmetricKey (RFC5958, id-aKPV1)
	"ENCRYPTED PRIVATE KEY":(EncryptedPrivateKeyInfo,5958,"id-aKPV1"),
	"ATTRIBUTE CERTIFICATE":(AttributeCertificate,5755,"id-acv2"),
	"PUBLIC KEY":           (SubjectPublicKeyInfo,5280,"id-pkix1-e"),
	"RSA PRIVATE KEY":      (RSAPrivateKey,0,""),
	"DH PARAMETERS":        (DHParameters,0,""),
	"NEW CERTIFICATE REQUEST":(CertificateRequest,0,"")
}
def PEM_parse(data):
	""" Extract PEM objects from 'data'. """
	__PEMre = re.compile(r"-----BEGIN (?P<label0>[A-Z0-9 ]*)-----\s*(?P<payload>([A-Za-z0-9+/]|\s)+[=]?\s*[=]?)\s*-----END (?P<label1>[A-Z0-9 ]*)-----")
	def _checklabel(match):
		if len(match) and (match.find('  ')>0 or match[0]==' ' or match[-1]==' '):	return False
		return True
	sepr = [ [obj.group('label0'),obj.group('payload').translate(None," \t\n\r\f\v")] for obj in __PEMre.finditer(data) if (_checklabel(obj.group('label0'))!=False and _checklabel(obj.group('label1'))!=False) ]
	for n in xrange(len(sepr)-1,-1,-1):
		if not sepr[n][1]:	del sepr[n]
	if not sepr:	return []
	for n in xrange(len(sepr)):
		if sepr[n][0] in __PEM_Types.keys():	sepr[n] = __PEM_Types[sepr[n][0]][0]( base64.b64decode(sepr[n][1]) )
		else:	sepr[n] = ( sepr[n][0], base64.b64decode(sepr[n][1]) )
	return sepr
def PEM_parse_file(filename):
	""" Reads 'filename' and parses PEM objects from it. """
	with open(filename,'rb') as f:	return PEM_parse(f.read())
def PEM_write(objs):
	def chunkstring(data,len):
		return (data[0+i:len+i] for i in xrange(0,len(data),len))
	def _checklabel(match):
		if len(match) and (match.find('  ')>0 or match[0]==' ' or match[-1]==' '):	return False
		return True
	payl = []
	for n in xrange(len(objs)):
		label = False
		if type(objs[n]) in [type([]),type(list([]))] and len(objs[n])==2 and type(objs[n][0])==type(objs[n][1])==type(""):
			label, asn1 = _checklabel(objs[n][0]), objs[n][1]
		else:
			for typ in __PEM_Types.keys():
				if objs[n].isinstance(__PEM_Types[typ][0]):
					label, asn1 = typ, str(objs[n])
					break
		if label==False:	continue
		elif label=="":	pass
		elif not re.match(r"[A-Z0-9 ]*",label):	continue
		else:	continue
		payl.append("-----BEGIN %s-----"%label)
		payl.extend(list(chunkstring( base64.b64encode(str(asn1)) ,64)))
		payl.append("-----END %s-----"%label)
	return '\n'.join(payl)
def PEM_write_file(filename, objs):
	payload = PEM_write(objs)
	if not payload:	return False
	with open(filename,'wb') as f:	return f.write(payload)


filename = "C:\\Users\\walter.arrighetti\\Desktop\\temp\\certs\\IntesiGroupEUQualifiedElectronicSealCAG2.pem"
print PEM_parse_file(filename)
