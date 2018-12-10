# -*- coding: utf-8 -*-
#
# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca.  If not,
# see <http://www.gnu.org/licenses/>.

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ... import ca_settings
from ...utils import is_power2
from ...utils import parse_key_curve
from ..base import KeyCurveAction
from ..base import KeySizeAction
from ..base import PasswordAction
from .sign_cert import Command as SignCommand


class Command(SignCommand):
    help = """Create a new Certificate. The defaults depend on the configured
default profile, currently %s.""" % ca_settings.CA_DEFAULT_PROFILE

    def add_arguments(self, parser):
        super(Command, self).add_arguments(parser)

        self.add_subject(
            parser, help='''The subject of the CA in the format "/key1=value1/key2=value2/...",
                                    valid keys are %s.'''
                         % self.valid_subject_keys)
        parser.add_argument(
            '--key-type', choices=['RSA', 'DSA', 'ECC'], default='RSA',
            help="Key type for the CA private key (default: %(default)s).")
        parser.add_argument(
            '--key-size', type=int, action=KeySizeAction, default=4096,
            metavar='{2048,4096,8192,...}',
            help="Size of the key to generate (default: %(default)s).")

        curve_help = 'Elliptic Curve used for generating ECC keys (default: %(default)s).' % {
            'default': ca_settings.CA_DEFAULT_ECC_CURVE.__class__.__name__,
        }
        parser.add_argument('--ecc-curve', type=str, action=KeyCurveAction,
                            default=ca_settings.CA_DEFAULT_ECC_CURVE,
                            help=curve_help)
        parser.add_argument('--private-key-password', nargs='?', action=PasswordAction, metavar='PASSWORD',
                            prompt='Password to protect generated private key: ',
                            help='Password for the private key of generated certificate.')

    def handle(self, subject, **options):
        # NOTE: Already verified by KeySizeAction, so these checks are only for when the Python API is used
        #       directly.
        if options['key_type'] != 'ECC':
            if not is_power2(options['key_size']):
                raise ValueError("%s: Key size must be a power of two" % options['key_size'])
            elif options['key_size'] < ca_settings.CA_MIN_KEY_SIZE:
                raise ValueError("%s: Key size must be least %s bits" % (
                    options['key_size'], ca_settings.CA_MIN_KEY_SIZE))

        if options['key_type'] == 'DSA':
            options['private_key'] = dsa.generate_private_key(key_size=options['key_size'],
                                                              backend=default_backend())
        elif options['key_type'] == 'ECC':
            ecc_curve = parse_key_curve(options['ecc_curve'])
            options['private_key'] = ec.generate_private_key(ecc_curve, default_backend())
        else:
            options['private_key'] = rsa.generate_private_key(public_exponent=65537, key_size=options['key_size'],
                                                              backend=default_backend())

        # Generate a CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Provide various details about who we are.
            x509.NameAttribute(NameOID.COUNTRY_NAME, subject['C']),
            x509.NameAttribute(NameOID.LOCALITY_NAME, subject['L']),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject['O']),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, '\n'.join(subject['OU'])),
            x509.NameAttribute(NameOID.COMMON_NAME, subject['CN']),
        ])).add_extension(
            x509.SubjectAlternativeName([
                # Describe what sites we want this certificate for.
                x509.DNSName(subject['CN']),
            ]), critical=False,
            # Sign the CSR with our private key.
        ).sign(options['private_key'], hashes.SHA256(), default_backend())

        options['csr'] = csr.public_bytes(serialization.Encoding.PEM)
        options['subject'] = subject

        super(Command, self).handle(subject, **options)
