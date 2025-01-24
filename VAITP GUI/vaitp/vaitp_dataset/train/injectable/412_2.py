# -*- coding: utf-8 -*-
"""
RDFa 1.1 parser, also referred to as a “RDFa Distiller”. It is
deployed, via a CGI front-end, on the U{W3C RDFa 1.1 Distiller page<http://www.w3.org/2012/pyRdfa/>}.

For details on RDFa, the reader should consult the U{RDFa Core 1.1<http://www.w3.org/TR/rdfa-core/>}, U{XHTML+RDFa1.1<http://www.w3.org/TR/2010/xhtml-rdfa>}, and the U{RDFa 1.1 Lite<http://www.w3.org/TR/rdfa-lite/>} documents.
The U{RDFa 1.1 Primer<http://www.w3.org/TR/owl2-primer/>} may also prove helpful.

This package can also be downloaded U{from GitHub<https://github.com/RDFLib/pyrdfa3>}. The
distribution also includes the CGI front-end and a separate utility script to be run locally.

Note that this package is an updated version of a U{previous RDFa distiller<http://www.w3.org/2007/08/pyRdfa>} that was developed
for RDFa 1.0. Although it reuses large portions of that code, it has been quite thoroughly rewritten, hence put in a completely
different project. (The version numbering has been continued, though, to avoid any kind of misunderstandings. This version has version numbers "3.0.0" or higher.)

(Simple) Usage
==============
From a Python file, expecting a Turtle output::
 from pyRdfa import pyRdfa
 print pyRdfa().rdf_from_source('filename')
Other output formats are also possible. E.g., to produce RDF/XML output, one could use::
 from pyRdfa import pyRdfa
 print pyRdfa().rdf_from_source('filename', outputFormat='pretty-xml')
It is also possible to embed an RDFa processing. Eg, using::
 from pyRdfa import pyRdfa
 graph = pyRdfa().graph_from_source('filename')
returns an RDFLib.Graph object instead of a serialization thereof. See the the description of the
L{pyRdfa class<pyRdfa.pyRdfa>} for further possible entry points details.

There is also, as part of this module, a L{separate entry for CGI calls<processURI>}.

Return (serialization) formats
------------------------------

The package relies on RDFLib. By default, it relies therefore on the serializers coming with the local RDFLib distribution. However, there has been some issues with serializers of older RDFLib releases; also, some output formats, like JSON-LD, are not (yet) part of the standard RDFLib distribution. A companion package, called pyRdfaExtras, is part of the download, and it includes some of those extra serializers. The extra format (not part of the RDFLib core) is U{JSON-LD<http://json-ld.org/spec/latest/json-ld-syntax/>}, whose 'key' is 'json', when used in the 'parse' method of an RDFLib graph.

(Note in 2018: the bugs that needed pyRdfaExtras are gone with the RDFLib versions, and the json-ld serializer and parser can be U{downloaded from github<https://github.com/RDFLib/rdflib-jsonld>} (or installed via pip). This means that importing pyRdfaExtras is done only when running older (i.e., 2.X.X) RDFLib versions and can be safely ignored these days.)  

Options
=======

The package also implements some optional features that are not part of the RDFa recommendations. At the moment these are:

 - possibility for plain literals to be normalized in terms of white spaces. Default: false. (The RDFa specification requires keeping the white spaces and leave applications to normalize them, if needed)
 - inclusion of embedded RDF: Turtle content may be enclosed in a C{script} element and typed as C{text/turtle}, U{defined by the RDF Working Group<http://www.w3.org/TR/turtle/>}. Alternatively, some XML dialects (e.g., SVG) allows the usage of RDF/XML as part of their core content to define metadata in RDF. For both of these cases pyRdfa parses these serialized RDF content and adds the resulting triples to the output Graph. Default: true.
 - extra, built-in transformers are executed on the DOM tree prior to RDFa processing (see below). These transformers can be provided by the end user.

Options are collected in an instance of the L{Options} class and may be passed to the processing functions as an extra argument. E.g., to allow the inclusion of embedded content::
 from pyRdfa.options import Options
 options = Options(embedded_rdf=True)
 print pyRdfa(options=options).rdf_from_source('filename')

See the description of the L{Options} class for the details.


Host Languages
==============

RDFa 1.1. Core is defined for generic XML; there are specific documents to describe how the generic specification is applied to
XHTML and HTML5.

pyRdfa makes an automatic switch among these based on the content type of the source as returned by an HTTP request. The following are the
possible host languages:
 - if the content type is C{text/html}, the content is HTML5
 - if the content type is C{application/xhtml+xml} I{and} the right DTD is used, the content is XHTML1
 - if the content type is C{application/xhtml+xml} and no or an unknown DTD is used, the content is XHTML5
 - if the content type is C{application/svg+xml}, the content type is SVG
 - if the content type is C{application/atom+xml}, the content type is SVG
 - if the content type is C{application/xml} or C{application/xxx+xml} (but 'xxx' is not 'atom' or 'svg'), the content type is XML

If local files are used, pyRdfa makes a guess on the content type based on the file name suffix: C{.html} is for HTML5, C{.xhtml} for XHTML1, C{.svg} for SVG, anything else is considered to be general XML. Finally, the content type may be set by the caller when initializing the L{pyRdfa class<pyRdfa.pyRdfa>}.

Beyond the differences described in the RDFa specification, the main difference is the parser used to parse the source. In the case of HTML5, pyRdfa uses an U{HTML5 parser<http://code.google.com/p/html5lib/>}; for all other cases the simple XML parser, part of the core Python environment, is used. This may be significant in the case of erroneous sources: indeed, the HTML5 parser may do adjustments on
the DOM tree before handing it over to the distiller. Furthermore, SVG is also recognized as a type that allows embedded RDF in the form of RDF/XML.

See the variables in the L{host} module if a new host language is added to the system. The current host language information is available for transformers via the option argument, too, and can be used to control the effect of the transformer.

Vocabularies
============

RDFa 1.1 has the notion of vocabulary files (using the C{@vocab} attribute) that may be used to expand the generated RDF graph. Expansion is based on some very simply RDF Schema and OWL statements on sub-properties and sub-classes, and equivalences.

pyRdfa implements this feature, although it does not do this by default. The extra C{vocab_expansion} parameter should be used for this extra step, for example::
 from pyRdfa.options import Options
 options = Options(vocab_expansion=True)
 print pyRdfa(options=options).rdf_from_source('filename')

The triples in the vocabulary files themselves (i.e., the small ontology in RDF Schema and OWL) are removed from the result, leaving the inferred property and type relationships only (additionally to the “core” RDF content).

Vocabulary caching
------------------

By default, pyRdfa uses a caching mechanism instead of fetching the vocabulary files each time their URI is met as a C{@vocab} attribute value. (This behavior can be switched off setting the C{vocab_cache} option to false.)

Caching happens in a file system directory. The directory itself is determined by the platform the tool is used on, namely:
 - On Windows, it is the C{pyRdfa-cache} subdirectory of the C{%APPDATA%} environment variable
 - On MacOS, it is the C{~/Library/Application Support/pyRdfa-cache}
 - Otherwise, it is the C{~/.pyRdfa-cache}

This automatic choice can be overridden by the C{PyRdfaCacheDir} environment variable.

Caching can be set to be read-only, i.e., the setup might generate the cache files off-line instead of letting the tool writing its own cache when operating, e.g., as a service on the Web. This can be achieved by making the cache directory read only.

If the directories are neither readable nor writable, the vocabulary files are retrieved via HTTP every time they are hit. This may slow down processing, it is advised to avoid such a setup for the package.

The cache includes a separate index file and a file for each vocabulary file. Cache control is based upon the C{EXPIRES} header of a vocabulary file’s HTTP return header: when first seen, this data is stored in the index file and controls whether the cache has to be renewed or not. If the HTTP return header does not have this entry, the date is artificially set ot the current date plus one day.

(The cache files themselves are dumped and loaded using U{Python’s built in cPickle package<http://docs.python.org/release/2.7/library/pickle.html#module-cPickle>}. These are binary files. Care should be taken if they are managed by CVS: they must be declared as binary files when adding them to the repository.)

RDFa 1.1 vs. RDFa 1.0
=====================

Unfortunately, RDFa 1.1 is I{not} fully backward compatible with RDFa 1.0, meaning that, in a few cases, the triples generated from an RDFa 1.1 source are not the same as for RDFa 1.0. (See the separate  U{section in the RDFa 1.1 specification<http://www.w3.org/TR/rdfa-core/#major-differences-with-rdfa-syntax-1.0>} for some further details.)

This distiller’s default behavior is RDFa 1.1. However, if the source includes, in the top element of the file (e.g., the C{html} element) a C{@version} attribute whose value contains the C{RDFa 1.0} string, then the distiller switches to a RDFa 1.0 mode. (Although the C{@version} attribute is not required in RDFa 1.0, it is fairly commonly used.) Similarly, if the RDFa 1.0 DTD is used in the XHTML source, it will be taken into account (a very frequent setup is that an XHTML file is defined with that DTD and is served as text/html; pyRdfa will consider that file as XHTML5, i.e., parse it with the HTML5 parser, but interpret the RDFa attributes under the RDFa 1.0 rules).

Transformers
============

The package uses the concept of 'transformers': the parsed DOM tree is possibly
transformed I{before} performing the real RDFa processing. This transformer structure makes it possible to
add additional 'services' without distoring the core code of RDFa processing.

A transformer is a function with three arguments:

 - C{node}: a DOM node for the top level element of the DOM tree
 - C{options}: the current L{Options} instance
 - C{state}: the current L{ExecutionContext} instance, corresponding to the top level DOM Tree element

The function may perform any type of change on the DOM tree; the typical behavior is to add or remove attributes on specific elements. Some transformations are included in the package and can be used as examples; see the L{transform} module of the distribution. These are:

 - The C{@name} attribute of the C{meta} element is copied into a C{@property} attribute of the same element
 - Interpreting the 'openid' references in the header. See L{transform.OpenID} for further details.
 - Implementing the Dublin Core dialect to include DC statements from the header.  See L{transform.DublinCore} for further details.

The user of the package may refer add these transformers to L{Options} instance. Here is a possible usage with the “openid” transformer added to the call::
 from pyRdfa.options import Options
 from pyRdfa.transform.OpenID import OpenID_transform
 options = Options(transformers=[OpenID_transform])
 print pyRdfa(options=options).rdf_from_source('filename')


@summary: RDFa parser (distiller)
@requires: Python version 2.7 or python 3.8 or up
@requires: U{RDFLib<http://rdflib.net>}; version 3.X is preferred.
@requires: U{html5lib<http://code.google.com/p/html5lib/>} for the HTML5 parsing (note that version 1.0b1 and 1.0b2 should be avoided, it may lead to unicode encoding problems)
@requires: U{httpheader<http://deron.meranda.us/python/httpheader/>}; however, a small modification had to make on the original file, so for this reason and to make distribution easier this module (single file) is added to the package.
@organization: U{World Wide Web Consortium<http://www.w3.org>}
@author: U{Ivan Herman<a href="http://www.w3.org/People/Ivan/">}
@license: This software is available for use under the
U{W3C® SOFTWARE NOTICE AND LICENSE<href="http://www.w3.org/Consortium/Legal/2002/copyright-software-20021231">}

@var builtInTransformers: List of built-in transformers that are to be run regardless, because they are part of the RDFa spec
@var CACHE_DIR_VAR: Environment variable used to define cache directories for RDFa vocabularies in case the default setting does not work or is not appropriate.
@var rdfa_current_version: Current "official" version of RDFa that this package implements by default. This can be changed at the invocation of the package
@var uri_schemes: List of registered (or widely used) URI schemes; used for warnings...
"""

__version__ = "4.0.0"
__author__  = 'Ivan Herman'
__contact__ = 'Ivan Herman, ivan@w3.org'
__license__ = 'W3C® SOFTWARE NOTICE AND LICENSE, http://www.w3.org/Consortium/Legal/2002/copyright-software-20021231'

name = "pyRdfa3"

import sys
PY3 = (sys.version_info[0] >= 3)

if PY3 :
	from io import StringIO
else :
	from StringIO import StringIO

import os
import xml.dom.minidom
if PY3 :
	from urllib.parse import urlparse
else :
	from urlparse import urlparse

import rdflib
from rdflib	import URIRef
from rdflib	import Literal
from rdflib	import BNode
from rdflib	import Namespace
if rdflib.__version__ >= "3.0.0" :
	from rdflib	import RDF  as ns_rdf
	from rdflib	import RDFS as ns_rdfs
	from rdflib	import Graph
else :
	from rdflib.RDFS  import RDFSNS as ns_rdfs
	from rdflib.RDF	  import RDFNS  as ns_rdf
	from rdflib.Graph import Graph

# Namespace, in the RDFLib sense, for the rdfa vocabulary
ns_rdfa		= Namespace("http://www.w3.org/ns/rdfa#")

from .extras.httpheader   import acceptable_content_type, content_type
from .transform.prototype import handle_prototypes

# Vocabulary terms for vocab reporting
RDFA_VOCAB  = ns_rdfa["usesVocabulary"]

# Namespace, in the RDFLib sense, for the XSD Datatypes
ns_xsd		= Namespace('http://www.w3.org/2001/XMLSchema#')

# Namespace, in the RDFLib sense, for the distiller vocabulary, used as part of the processor graph
ns_distill	= Namespace("http://www.w3.org/2007/08/pyRdfa/vocab#")

debug = False

#########################################################################################################

# Exception/error handling. Essentially, all the different exceptions are re-packaged into
# separate exception class, to allow for an easier management on the user level

class RDFaError(Exception) :
	"""Superclass exceptions representing error conditions defined by the RDFa 1.1 specification.
	It does not add any new functionality to the
	Exception class."""
	def __init__(self, msg) :
		self.msg = msg
		Exception.__init__(self)

class FailedSource(RDFaError) :
	"""Raised when the original source cannot be accessed. It does not add any new functionality to the
	Exception class."""
	def __init__(self, msg, http_code = None) :
		self.msg		= msg
		self.http_code 	= http_code
		RDFaError.__init__(self, msg)

class HTTPError(RDFaError) :
	"""Raised when HTTP problems are detected. It does not add any new functionality to the
	Exception class."""
	def __init__(self, http_msg, http_code) :
		self.msg		= http_msg
		self.http_code	= http_code
		RDFaError.__init__(self,http_msg)

class ProcessingError(RDFaError) :
	"""Error found during processing. It does not add any new functionality to the
	Exception class."""
	pass

class pyRdfaError(Exception) :
	"""Superclass exceptions representing error conditions outside the RDFa 1.1 specification."""
	pass

# Error and Warning RDFS classes
RDFA_Error                  = ns_rdfa["Error"]
RDFA_Warning                = ns_rdfa["Warning"]
RDFA_Info                   = ns_rdfa["Information"]
NonConformantMarkup         = ns_rdfa["DocumentError"]
UnresolvablePrefix          = ns_rdfa["UnresolvedCURIE"]
UnresolvableReference       = ns_rdfa["UnresolvedCURIE"]
UnresolvableTerm            = ns_rdfa["UnresolvedTerm"]
VocabReferenceError         = ns_rdfa["VocabReferenceError"]
PrefixRedefinitionWarning   = ns_rdfa["PrefixRedefinition"]

FileReferenceError          = ns_distill["FileReferenceError"]
HTError                     = ns_distill["HTTPError"]
IncorrectPrefixDefinition   = ns_distill["IncorrectPrefixDefinition"]
IncorrectBlankNodeUsage     = ns_distill["IncorrectBlankNodeUsage"]
IncorrectLiteral            = ns_distill["IncorrectLiteral"]

# Error message texts
err_no_blank_node                    = "Blank node in %s position is not allowed; ignored"

err_redefining_URI_as_prefix        = "'%s' a registered or an otherwise used URI scheme, but is defined as a prefix here; is this a mistake? (see, eg, http://en.wikipedia.org/wiki/URI_scheme or http://www.iana.org/assignments/uri-schemes.html for further information for most of the URI schemes)"
err_xmlns_deprecated                = "The usage of 'xmlns' for prefix definition is deprecated; please use the 'prefix' attribute instead (definition for '%s')"
err_bnode_local_prefix              = "The '_' local CURIE prefix is reserved for blank nodes, and cannot be defined as a prefix"
err_col_local_prefix                = "The character ':' is not valid in a CURIE Prefix, and cannot be used in a prefix definition (definition for '%s')"
err_missing_URI_prefix              = "Missing URI in prefix declaration for '%s' (in '%s')"
err_invalid_prefix                  = "Invalid prefix declaration '%s' (in '%s')"
err_no_default_prefix               = "Default prefix cannot be changed (in '%s')"
err_prefix_and_xmlns                = "@prefix setting for '%s' overrides the 'xmlns:%s' setting; may be a source of problem if same file is run through RDFa 1.0"
err_non_ncname_prefix               = "Non NCNAME '%s' in prefix definition (in '%s'); ignored"
err_absolute_reference              = "CURIE Reference part contains an authority part: %s (in '%s'); ignored"
err_query_reference                 = "CURIE Reference query part contains an unauthorized character: %s (in '%s'); ignored"
err_fragment_reference              = "CURIE Reference fragment part contains an unauthorized character: %s (in '%s'); ignored"
err_lang                            = "There is a problem with language setting; either both xml:lang and lang used on an element with different values, or, for (X)HTML5, only xml:lang is used."
err_URI_scheme                      = "Unusual URI scheme used in <%s>; may that be a mistake, e.g., resulting from using an undefined CURIE prefix or an incorrect CURIE?"
err_illegal_safe_CURIE              = "Illegal safe CURIE: %s; ignored"
err_no_CURIE_in_safe_CURIE          = "Safe CURIE is used, but the value does not correspond to a defined CURIE: [%s]; ignored"
err_undefined_terms                 = "'%s' is used as a term, but has not been defined as such; ignored"
err_non_legal_CURIE_ref             = "Relative URI is not allowed in this position (or not a legal CURIE reference) '%s'; ignored"
err_undefined_CURIE                 = "Undefined CURIE: '%s'; ignored"
err_prefix_redefinition             = "Prefix '%s' (defined in the initial RDFa context or in an ancestor) is redefined"

err_unusual_char_in_URI             = "Unusual character in uri: %s; possible error?"

#############################################################################################

from .state            import ExecutionContext
from .parse            import parse_one_node
from .options          import Options
from .transform        import top_about, empty_safe_curie, vocab_for_role
from .utils            import URIOpener
from .host             import HostLanguage, MediaTypes, preferred_suffixes, content_to_host_language

# Environment variable used to characterize cache directories for RDFa vocabulary files.
CACHE_DIR_VAR           = "PyRdfaCacheDir"

# current "official" version of RDFa that this package implements. This can be changed at the invocation of the package
rdfa_current_version    = "1.1"

# I removed schemes that would not appear as a prefix anyway, like iris.beep
# http://en.wikipedia.org/wiki/URI_scheme seems to be a good source of information
# as well as http://www.iana.org/assignments/uri-schemes.html
# There are some overlaps here, but better more than not enough...

# This comes from wikipedia
registered_iana_schemes = [
	"aaa","aaas","acap","cap","cid","crid","data","dav","dict","did","dns","fax","file", "ftp","geo","go",
	"gopher","h323","http","https","iax","icap","im","imap","info","ipp","iris","ldap", "lsid",
	"mailto","mid","modem","msrp","msrps", "mtqp", "mupdate","news","nfs","nntp","opaquelocktoken",
	"pop","pres", "prospero","rstp","rsync", "service","shttp","sieve","sip","sips", "sms", "snmp", "soap", "tag",
	"tel","telnet", "tftp", "thismessage","tn3270","tip","tv","urn","vemmi","wais","ws", "wss", "xmpp"
]

# This comes from wikipedia, too
unofficial_common = [
	"about", "adiumxtra", "aim", "apt", "afp", "aw", "bitcoin", "bolo", "callto", "chrome", "coap",
	"content", "cvs", "doi", "ed2k", "facetime", "feed", "finger", "fish", "git", "gg",
	"gizmoproject", "gtalk", "irc", "ircs", "irc6", "itms", "jar", "javascript",
	"keyparc", "lastfm", "ldaps", "magnet", "maps", "market", "message", "mms",
	"msnim", "mumble", "mvn", "notes", "palm", "paparazzi", "psync", "rmi",
	"secondlife", "sgn", "skype", "spotify", "ssh", "sftp", "smb", "soldat",
	"steam", "svn", "teamspeak", "things", "udb", "unreal", "ut2004",
	"ventrillo", "view-source", "webcal", "wtai", "wyciwyg", "xfire", "xri", "ymsgr"
]

# These come from the IANA page
historical_iana_schemes = [
	"fax", "mailserver", "modem", "pack", "prospero", "snews", "videotex", "wais"
]

provisional_iana_schemes = [
	"afs", "dtn", "dvb", "icon", "ipn", "jms", "oid", "rsync", "ni"
]

other_used_schemes = [
	"hdl", "isbn", "issn", "mstp", "rtmp", "rtspu", "stp"
]

uri_schemes = registered_iana_schemes + unofficial_common + historical_iana_schemes + provisional_iana_schemes + other_used_schemes

# List of built-in transformers that are to be run regardless, because they are part of the RDFa spec
builtInTransformers = [
	empty_safe_curie, top_about, vocab_for_role
]

#########################################################################################################
class pyRdfa :
	"""Main processing class for the distiller

	@ivar options: an instance of the L{Options} class
	@ivar media_type: the preferred default media type, possibly set at initialization
	@ivar base: the base value, possibly set at initialization
	@ivar http_status: HTTP Status, to be returned when the package is used via a CGI entry. Initially set to 200, may be modified by exception handlers
	"""
	def __init__(self, options = None, base = "", media_type = "", rdfa_version = None) :
		"""
		@keyword options: Options for the distiller
		@type options: L{Options}
		@keyword base: URI for the default "base" value (usually the URI of the file to be processed)
		@keyword media_type: explicit setting of the preferred media type (a.k.a. content type) of the the RDFa source
		@keyword rdfa_version: the RDFa version that should be used. If not set, the value of the global L{rdfa_current_version} variable is used
		"""
		self.http_status = 200

		self.base = base
		if base == "" :
			self.required_base = None
		else :
			self.required_base	= base
		self.charset 		= None

		# predefined content type
		self.media_type = media_type

		if options == None :
			self.options = Options()
		else :
			self.options = options

		if media_type != "" :
			self.options.set_host_language(self.media_type)

		if rdfa_version is not None :
			self.rdfa_version = rdfa_version
		else :
			self.rdfa_version = None

	def _get_input(self, name) :
		"""
		Trying to guess whether "name" is a URI or a string (for a file); it then tries to open this source accordingly,
		returning a file-like object. If name is none of these, it returns the input argument (that should
		be, supposedly, a file-like object already).

		If the media type has not been set explicitly at initialization of this instance,
		the method also sets the media_type based on the HTTP GET response or the suffix of the file. See
		L{host.preferred_suffixes} for the suffix to media type mapping.

		@param name: identifier of the input source
		@type name: string or a file-like object
		@return: a file like object if opening "name" is possible and successful, "name" otherwise
		"""
		try :
			# Python 2 branch
			isstring = isinstance(name, basestring)
		except :
			# Python 3 branch
			isstring = isinstance(name, str)

		try :
			if isstring :
				# check if this is a URI, ie, if there is a valid 'scheme' part
				# otherwise it is considered to be a simple file
				if urlparse(name)[0] != "" :
					url_request 	  = URIOpener(name)
					self.base 		  = url_request.location
					if self.media_type == "" :
						if url_request.content_type in content_to_host_language :
							self.media_type = url_request.content_type
						else :
							self.media_type = MediaTypes.xml
						self.options.set_host_language(self.media_type)
					self.charset = url_request.charset
					if self.required_base == None :
						self.required_base = name
					return url_request.data
				else :
					# Creating a File URI for this thing
					if self.required_base == None :
						self.required_base = "file://" + os.path.join(os.getcwd(),name)
					if self.media_type == "" :
						self.media_type = MediaTypes.xml
						# see if the default should be overwritten
						for suffix in preferred_suffixes :
							if name.endswith(suffix) :
								self.media_type = preferred_suffixes[suffix]
								self.charset = 'utf-8'
								break
						self.options.set_host_language(self.media_type)
					return open(name, 'rb')
			else :
				return name
		except HTTPError :
			raise sys.exc_info()[1]
		except RDFaError as e :
			raise e
		except :
			(type, value, traceback) = sys.exc_info()
			raise FailedSource(value)

	@staticmethod
	def _validate_output_format(outputFormat):
		"""
		Malicious actors may create XSS style issues by using an illegal output format... better be careful
		"""
		# protection against possible malicious URL call
		if outputFormat not in ["turtle", "n3", "xml", "pretty-xml", "nt", "json-ld"] :
			outputFormat = "turtle"
		return outputFormat
		
	####################################################################################################################
	# Externally used methods
	#
	def graph_from_DOM(self, dom, graph = None, pgraph = None) :
		"""
		Extract the RDF Graph from a DOM tree. This is where the real processing happens. All other methods get down to this
		one, eventually (e.g., after opening a URI and parsing it into a DOM).
		@param dom: a DOM Node element, the top level entry node for the whole tree (i.e., the C{dom.documentElement} is used to initiate processing down the node hierarchy)
		@keyword graph: an RDF Graph (if None, than a new one is created)
		@type graph: rdflib Graph instance.
		@keyword pgraph: an RDF Graph to hold (possibly) the processor graph content. If None, and the error/warning triples are to be generated, they will be added to the returned graph. Otherwise they are stored in this graph.
		@type pgraph: rdflib Graph instance
		@return: an RDF Graph
		@rtype: rdflib Graph instance
		"""
		def copyGraph(tog, fromg) :
			for t in fromg :
				tog.add(t)
			for k,ns in fromg.namespaces() :
				tog.bind(k,ns)

		if graph == None :
			# Create the RDF Graph, that will contain the return triples...
			graph   = Graph()

		# this will collect the content, the 'default graph', as called in the RDFa spec
		default_graph = Graph()

		# get the DOM tree
		topElement = dom.documentElement

		# Create the initial state. This takes care of things
		# like base, top level namespace settings, etc.
		state = ExecutionContext(topElement, default_graph, base=self.required_base if self.required_base != None else "", options=self.options, rdfa_version=self.rdfa_version)

		# Perform the built-in and external transformations on the HTML tree.
		for trans in self.options.transformers + builtInTransformers :
			trans(topElement, self.options, state)

		# This may have changed if the state setting detected an explicit version information:
		self.rdfa_version = state.rdfa_version

		# The top level subject starts with the current document; this
		# is used by the recursion
		# this function is the real workhorse
		parse_one_node(topElement, default_graph, None, state, [])

		# Massage the output graph in term of rdfa:Pattern and rdfa:copy
		handle_prototypes(default_graph)

		# If the RDFS expansion has to be made, here is the place...
		if self.options.vocab_expansion :
			from .rdfs.process import process_rdfa_sem
			process_rdfa_sem(default_graph, self.options)

		# Experimental feature: nothing for now, this is kept as a placeholder
		if self.options.experimental_features :
			pass

		# What should be returned depends on the way the options have been set up
		if self.options.output_default_graph :
			copyGraph(graph, default_graph)
			if self.options.output_processor_graph :
				if pgraph != None :
					copyGraph(pgraph, self.options.processor_graph.graph)
				else :
					copyGraph(graph, self.options.processor_graph.graph)
		elif self.options.output_processor_graph :
			if pgraph != None :
				copyGraph(pgraph, self.options.processor_graph.graph)
			else :
				copyGraph(graph, self.options.processor_graph.graph)
