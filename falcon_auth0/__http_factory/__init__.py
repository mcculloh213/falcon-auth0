# System Imports
from typing import Dict, List, Tuple, Union

# Third-Party Imports
from falcon import HTTPError, HTTP_799

# Local Source Imports

__author__ = 'H.D. "Chip" McCullough IV'

__default_human_title = 'Leonard Bernstein'
__default_description = 'It\'s the end of the world as we know it, and I feel fine!'

def http_error_factory(status: str = HTTP_799, title: str = __default_human_title,
                       description: str = __default_description,
                       headers: Union[Dict[str, str], List[Tuple[str, str]]] = None, href: str = None,
                       href_text: str = None, code: int = None) -> HTTPError:
    """ Returns a raise-able HTTPError based on the input parameters

    :param status: HTTP status code and text, such as '400 Bad Request'
    :type status: str
    :param title: Human-friendly error title. If not provided, defaults to the HTTP status line as determined by the
        :code`status` parameter
    :type title: str
    :param description: Human-friendly description of the error, along with a helpful suggestion or two (default `None`)
    :type description: str
    :param headers: A dict of header names and values to set, or a list of (*name*, *value*) tuples. Both *name* and
        *value* must be of type str or StringType, and only character values 0x00 through 0xFF may be used on platforms
        that use wide characters

        Note:
            The Content-Type header, if present, will be overridden. If
            you wish to return custom error messages, you can create
            your own HTTP error class, and install an error handler
            to convert it into an appropriate HTTP response for the
            client

        Note:
            Falcon can process a list of tuple slightly faster
            than a dict
    :type headers: Union[Dict[str, str], List[Tuple[str, str]]]
    :param href: A URL someone can visit to find out more information (default None). Unicode characters are
        percent-encoded
    :type href: str
    :param href_text: If href is given, use this as the friendly  title/description for the link (default 'API
        documentation for this error')
    :type href_text: str
    :param code: An internal code that customers can reference in their support request or to help them when searching
        for knowledge base articles related to this error (default ``None``)
    :type code: int
    :return: Falcon HTTP Error
    :rtype: HTTPError
    """
    return HTTPError(
        status=status,
        title=title,
        description=description,
        headers=headers,
        href=href,
        href_text=href_text,
        code=code
    )