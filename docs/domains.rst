Domain Management
-----------------

Domain management is done through the ``/api/v1/domains/`` endpoint.  The
following sections describe how to create, list, modify, and delete domains
using JSON objects.  The structure of the JSON objects is detailed in the next
section.


.. _`domain object`:

Domain Field Reference
~~~~~~~~~~~~~~~~~~~~~~

A JSON object representing a domain has the following structure::

    {
        "created": "2018-09-18T16:36:16.510368Z",
        "keys": [
            {
                "dnskey": "257 3 13 WFRl60...",
                "ds": [
                    "6006 13 1 8581e9...",
                    "6006 13 2 f34b75...",
                    "6006 13 3 dfb325...",
                    "6006 13 4 2fdcf8..."
                ],
                "flags": 257,
                "keytype": "csk"
            },
            ...
        ],
        "minimum_ttl": 3600,
        "name": "example.com",
        "published": "2018-09-18T17:21:38.348112Z"
    }

Field details:

``created``
    :Access mode: read-only

    Timestamp of domain creation, in ISO 8601 format (e.g.
    ``2013-01-29T12:34:56.000000Z``).

``keys``
    :Access mode: read-only

    Array with DNSSEC key information.  Each entry contains ``DNSKEY`` and
    ``DS`` record contents (the latter being computed from the former), and
    some extra information.  For delegation of DNSSEC-secured domains, the
    parent domain needs to publish these ``DS`` records.  (This usually
    involves telling your registrar/registry about those records, and they
    will publish them for you.)

    Notes:

    - Newly created domains are assigned a key after a short while (usually
      around one minute).  Until then, this field is empty.

    - The contents of this field are generated from PowerDNS' ``cryptokeys``
      endpoint, see https://doc.powerdns.com/md/httpapi/api_spec/#cryptokeys.
      We look at each active ``cryptokey_resource`` (``active`` is true) and
      then use the ``dnskey``, ``ds``, ``flags``, and ``keytype`` fields.

.. _`minimum TTL`:

``minimum_ttl``
    :Access mode: read-only

    Smallest TTL that can be used in an `RRset <RRset object_>`__. The value
    is set automatically by the server.

    If you would like to use lower TTL values, you can apply for an exception
    by contacting support.  We reserve the right to reject applications at our
    discretion.

``name``
    :Access mode: read, write-once (upon domain creation)

    Domain name.  Restrictions on what is a valid domain name apply on a
    per-user basis.  In general, a domain name consists of lowercase alphanumeric
    characters as well as hyphens ``-`` and underscores ``_`` (except at the
    beginning of the name).  The maximum length is 191.

``published``
    :Access mode: read-only

    Timestamp of when the domain's DNS records have last been published,
    in ISO 8601 format (e.g. ``2013-01-29T12:34:56.000000Z``).

    As we publish record modifications immediately, this indicates the
    point in time of the last successful write request to a domain's
    ``rrsets/`` endpoint.


Creating a Domain
~~~~~~~~~~~~~~~~~

To create a new domain, issue a ``POST`` request to the ``/api/v1/domains/``
endpoint, like this::

    curl -X POST https://desec.io/api/v1/domains/ \
        --header "Authorization: Token {token}" \
        --header "Content-Type: application/json" --data @- <<< \
        '{"name": "example.com"}'

Only the ``name`` field is mandatory.

Upon success, the response status code will be ``201 Created``, with the
domain object contained in the response body.  ``400 Bad Request`` is returned
if the request contained malformed data.  If the object could not be
created although the request was wellformed, the API responds with ``403
Forbidden`` if the maximum number of domains for this user has been reached,
and with ``409 Conflict`` otherwise.  This can happen, for example, if there
already is a domain with the same name or if the domain name is considered
invalid for policy reasons.

The response body *may* provide further, human-readable information on the
policy violation that occurred.

Restrictions on what is a valid domain name apply.  In particular, domains
listed on the `Public Suffix List`_ cannot be registered.  (If you operate a
public suffix and would like to host it with deSEC, that's certainly possible;
please contact our support.)

.. _Public Suffix List: https://publicsuffix.org/

Furthermore, restrictions on a per-user basis may apply.  In particular, the
number of domains a user can create is limited.  If you find yourself affected
by this limit although you have a legitimate use case, please contact our
support.


Listing Domains
~~~~~~~~~~~~~~~

The ``/api/v1/domains/`` endpoint reponds to ``GET`` requests with an array of
`domain object`_\ s. For example, you may issue the following command::

    curl -X GET https://desec.io/api/v1/domains/ \
        --header "Authorization: Token {token}"

to retrieve an overview of the domains you own.  Domains are returned in
reverse chronological order of their creation.

The response status code in case of success is ``200 OK``.  This is true also
if you do not own any domains; in this case, the response body will be an empty
JSON array.

Up to 500 items are returned at a time.  If you have a larger number of
domains configured, the use of `pagination`_ is required.


Retrieving a Specific Domain
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To retrieve a domain with a specific name, issue a ``GET`` request with the
``name`` appended to the ``domains/`` endpoint, like this::

    curl -X GET https://desec.io/api/v1/domains/:name/ \
        --header "Authorization: Token {token}"

This will return only one domain (i.e., the response is not a JSON array).

If you own a domain with that name, the API responds with ``200 OK`` and
returns the domain object in the reponse body.  Otherwise, the return status
code is ``404 Not Found``.


Deleting a Domain
~~~~~~~~~~~~~~~~~

To delete a domain, send a ``DELETE`` request to the endpoint representing the
domain.  Upon success or if the domain did not exist or was not yours in the
first place, the response status code is ``204 No Content``.
