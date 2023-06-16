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
_version = "0.9"
import hashlib
import base64
import re

try:
	#import pyasn1
	import asn1
	_hasASN1 = True
except:	_hasASN1 = False

class OID:
	def __init__(self, oid0, *OIDs, label=None):
		if not oid0 or (label and not self.__islabel(label)):	return None
		elif type(oid0)==type(""):	oid0 = oid0.split('.')
		elif type(oid0)==type(1):	oid0 = [str(oid0)]
		elif type(oid0) in [type([]),type(list([]))]:	# Parse as a tuple/list [x,y,z,...] or (x,y,z,...)
			oid0 = list(oid0)
		#elif isinstance(oid0,OID):	oid0 = oid0.list
		else:	return None
		for oid in OIDs:
			if type(oid)==type(""):	oid0.expand(oid.split('.'))
			elif type(oid)==type(1):	oid0.append(oid)
			elif type(oid) in [type([]),type(list([]))]:	oid0.expand(list(oid))
			#elif isinstance(oid,OID):	oid0.expand(oid.list)
			else:	return None
		try:	oid0 = list(map(int,oid0))
		except:	return None
		self.label = self.___labelize(label)
		if self.label==False:	return None
		self.list, self.depth, self.tuple, self.str = oid0, len(oid0), tuple(oid0), '.'.join(list(map(str,oid0)))
		return self.list
	def ___labelize(self,label):
		def __islabel(s):
			if not s:	return []
			s = s.strip().translate({'.':'-'})
			for n in range(len(s)):
				if n==0 and s[0] in "0123456789-":	return False
				elif n==len(s)-1 and s[-1]=='-':	return False
				elif 0<n<len(s)-1 and not (s[n].isalnum() or s[n]=='-'):	return False
				if s[n]=='-' and n<len(s)-1 and s[n+1]=='-':	return False
				return True
		if not label or type(label) not in [type(""),type([]),type(tuple([]))]:	return False
		if type(label)==type("") and __islabel(label):	return [label.strip().translate({'.':'-'})]
		for l in label:
			if type(l)!=type("") or not __islabel(l):	return False
		return [l.strip().translate({'.':'-'}) for l in list(label)]
	def isinstance(self, classname):
		if classname==OID:	return True
		else:	return False
	def relabel(self, relabel):
		relabel = self.__labelize(relabel)
		if relabel==False:	return False
		self.label = relabel
		return self.relabel
	def addlabel(self, label):
		label = self.__labelize(label)
		if label==False:	return False
		self.label.extend(label)
		return self.label
	def parent(self, relabel=None):
		if self.depth>1:
			if relabel:
				relabel = self.__labelize(relabel)
				if relabel==False:	relabel = None
			return OID(self.list[:-1], label=relabel)
		return None
	def sibling(self, arc, relabel=None):
		if not arc:	return None
		if relabel:
			relabel = self.__labelize(relabel)
			if relabel==False:	relabel = None
		if type(arc)==type(1):	return OID(self.list[:-1].append(arc), label=relabel)
		elif type(arc)==type("") and arc.isdigit():	return OID(self.list[:-1].append(int(arc)), label=relabel)
		else:	return None
	def child(self, arc, relabel=None):
		if not arc:	return None
		if relabel:
			relabel = self.__labelize(relabel)
			if relabel==False:	relabel = None
		if type(arc)==type(1):	return OID(self.list.append(arc), relabel=label)
		elif type(arc)==type("") and arc.isdigit():	return OID(self.list.append(int(arc)), relabel=label)
		else:	return None
	#def str(self):	return self.oid.join('.')

class _ASN1_Base(object):
	""" Base class for parsed ASN.1 objects. """
	def __init__(self, payload):
		global _hasASN1
		#if isinstance(payload, unicode):	payload = payload.encode('ascii')
		#payload = payload.decode()
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


__idpkcs, __idpkixmod = OID(1,2,840,113549,1), OID(1,3,6,1,5,5,7,0);	__idsmmod = OID(__idpkcs,(9,16,0))
__PEM_Types = {		# items are 4-ple  (ASN1-class-name, class-OID, OID-x509-name, RFC-number)
	"CERTIFICATE":          (Certificate, OID(__idpkixmod,18),"id-pkix1-e", 5280),
	"X509 CRL":             (CertificateList, OID(__idpkixmod,18),"id-pkix1-e", 5280),
	"CERTIFICATE REQUEST":  (CertificateRequest, OID(__idpkcs,(10,1,1)),"id-pkcs10", 2986),
	"PKCS7":                (ContentInfo, OID(__idpkcs,(7,0,1)),"id-pkcs7*", 2315),
	"CMS":                  (ContentInfo, OID(__idsmmod,24),"id-cms2004", 5625),
	"PRIVATE KEY":          (PrivateKeyInfo, OID(__idpkcs,(8,1,1)),"id-pkcs8", 5208),	# ==OneAsymmetricKey [RFC5958, id-aKPV1, OID(__idsmmod,50)]
	"ENCRYPTED PRIVATE KEY":(EncryptedPrivateKeyInfo, OID(__idsmmod,50),"id-aKPV1", 5958),
	"ATTRIBUTE CERTIFICATE":(AttributeCertificate, OID(__idpkixmod,61),"id-acv2", 5755),
	"PUBLIC KEY":           (SubjectPublicKeyInfo, OID(__idpkixmod,18),"id-pkix1-e", 5280),
	"RSA PRIVATE KEY":      (RSAPrivateKey, OID(__idpkcs,(8,1,1)),"", 0),
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
	sepr = [ [obj.group('label0').strip(),obj.group('payload').translate(str.maketrans("",""," \t\n\r\f\v"))] for obj in __PEMre.finditer(data) if (_checklabel(obj.group('label0'))!=False and _checklabel(obj.group('label1'))!=False)]
	for n in reversed(range(len(sepr))):
		if (not sepr[n][0]) or (not sepr[n][1]) or (strict and sepr[n][0]!=obj.group('label1').strip()):	del sepr[n]	# RFC does not manadate checking 'label0'=='label'
		elif sepr[n][0] in __PEM_Types.keys():
			sepr[n] = __PEM_Types[sepr[n][0]][0] ( base64.b64decode(sepr[n][1]) )
		elif sepr[n][0]=="NEW CERTIFICATE REQUEST":
			sepr[n] = __PEM_Types["CERTIFICATE REQUEST"][0] ( base64.b64decode(sepr[n][1]) )
		elif not strict:
			if sepr[n][0] in ["X509 CERTIFICATE","X.509 CERTIFICATE"]:
				sepr[n] = __PEM_Types["CERTIFICATE"][0] ( base64.b64decode(sepr[n][1]) )
			elif sepr[n][0]=="CRL":
				sepr[n] = __PEM_Types["X509 CRL"][0] ( base64.b64decode(sepr[n][1]) )
			elif sepr[n][0]=="CERTIFICATE CHAIN":
				sepr[n] = __PEM_Types["PKCS7"][0] ( base64.b64decode(sepr[n][1]) )
			else:
				sepr[n] = ( sepr[n][0], base64.b64decode(sepr[n][1]) )
		else:	del sepr[n]
	if not sepr:	return []
	return sepr
def PEM_parse_file(filename, strict=False):
	""" Reads 'filename' and parses PEM objects from it. """
	with open(filename,'rb') as f:	return PEM_parse(f.read().decode('utf-8'), strict=strict)
def PEM_write(objs, newline='\n'):
	def chunkstring(data,length):
		return [data[0+i:length+i] for i in range(0,len(data),length)]
	def _checklabel(match):
		if (not match) or type(match)!=type("") or match.find('  ')>0 or not re.match(r"[A-Za-z0-9 ]*",label):	return False
		return match.strip().toupper()
	if not newline:	newline=""
	elif newline not in ['\n',"",'\r',"\r\n"]:	return False
	if type(objs) not in [type([]),type(tuple([]))]:	objs = [objs]
	payl = []
	for n in range(len(objs)):
		label = False
		if type(objs[n]) in [type([]),type(list([]))] and len(objs[n])==2 and type(objs[n][0])==type(objs[n][1])==type(""):
			label, asn1 = objs[n][0], objs[n][1]
		else:
			for typ in __PEM_Types.keys():
#				if type(objs[n])==type(__PEM_Types[typ][0]):
				if isinstance(objs[n],__PEM_Types[typ][0]):
					label, asn1 = typ, objs[n].raw()
					break
		if not label or not asn1:	continue
		payl.append("-----BEGIN %s-----"%label)
		payl.extend(list(chunkstring( base64.b64encode(asn1).decode() ,64)))
		payl.append("-----END %s-----"%label)
	return newline.join(payl)
def PEM_write_file(filename, objs, newline='\n'):
	payload = PEM_write(objs, newline=newline)
	if not payload:	return False
	with open(filename,'wb') as f:	return f.write(payload.encode())

###EXAMPLE THAT READS AND REWRITES A (CHAIN OF) ASN.1 TYPE(S)
import sys
chain = []
for arg in sys.argv:
	chain.extend(PEM_parse_file(arg))
PEM_write_file("out.chain.pem",chain)
