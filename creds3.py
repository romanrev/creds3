#!/usr/bin/env python
# Copyright 2015 DevOpsyTurvy
# Based on the Credstash code from https://github.com/fugue/credstash
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import print_function

import argparse
import binascii
import csv
import json
import operator
import os
import os.path
import sys
import re
import boto3
import botocore.exceptions

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

try:
    import yaml
    NO_YAML = False
except ImportError:
    NO_YAML = True

from base64 import b64encode, b64decode

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC

_hash_classes = {
    'SHA': hashes.SHA1,
    'SHA224': hashes.SHA224,
    'SHA256': hashes.SHA256,
    'SHA384': hashes.SHA384,
    'SHA512': hashes.SHA512,
    'RIPEMD': hashes.RIPEMD160,
    'WHIRLPOOL': hashes.Whirlpool,
    'MD5': hashes.MD5,
}

DEFAULT_DIGEST = 'SHA256'
HASHING_ALGORITHMS = _hash_classes.keys()
LEGACY_NONCE = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
DEFAULT_REGION = "us-east-1"
PAD_LEN = 19  # number of digits in sys.maxint
WILDCARD_CHAR = "*"


class KeyService(object):

    def __init__(self, kms, key_id, encryption_context):
        self.kms = kms
        self.key_id = key_id
        self.encryption_context = encryption_context

    def generate_key_data(self, number_of_bytes):
        try:
            kms_response = self.kms.generate_data_key(
                KeyId=self.key_id, EncryptionContext=self.encryption_context, NumberOfBytes=number_of_bytes
            )
        except Exception as e:
            raise KmsError("Could not generate key using KMS key %s (Detail: %s)" % (self.key_id, e.message))
        return kms_response['Plaintext'], kms_response['CiphertextBlob']

    def decrypt(self, encoded_key):
        try:
            kms_response = self.kms.decrypt(
                CiphertextBlob=encoded_key,
                EncryptionContext=self.encryption_context
            )
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "InvalidCiphertextException":
                if self.encryption_context is None:
                    msg = ("Could not decrypt hmac key with KMS. The credential may "
                           "require that an encryption context be provided to decrypt "
                           "it.")
                else:
                    msg = ("Could not decrypt hmac key with KMS. The encryption "
                           "context provided may not match the one used when the "
                           "credential was stored.")
            else:
                msg = "Decryption error %s" % e
            raise KmsError(msg)
        return kms_response['Plaintext']


class KmsError(Exception):

    def __init__(self, value=""):
        self.value = "KMS ERROR: " + value if value is not "" else "KMS ERROR"

    def __str__(self):
        return self.value


class IntegrityError(Exception):

    def __init__(self, value=""):
        self.value = "INTEGRITY ERROR: " + value if value is not "" else \
                     "INTEGRITY ERROR"

    def __str__(self):
        return self.value


class ItemNotFound(Exception):
    pass


class KeyValueToDictionary(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace,
                self.dest,
                dict((x[0], x[1]) for x in values))


def printStdErr(s):
    sys.stderr.write(str(s))
    sys.stderr.write("\n")


def fatal(s):
    printStdErr(s)
    sys.exit(1)


def key_value_pair(string):
    output = string.split('=')
    if len(output) != 2:
        msg = "%r is not the form of \"key=value\"" % string
        raise argparse.ArgumentTypeError(msg)
    return output


def expand_wildcard(string, secrets):
    prog = re.compile('^' + string.replace(WILDCARD_CHAR, '.*') + '$')
    output = []
    for secret in secrets:
        if prog.search(secret) is not None:
            output.append(secret)
    return output


def value_or_filename(string):
    # argparse running on old version of python (<2.7) will pass an empty
    # string to this function before it passes the actual value.
    # If an empty string is passes in, just return an empty string
    if string == "":
        return ""

    if string == '-':
        try:
            return sys.stdin.read()
        except KeyboardInterrupt:
            raise argparse.ArgumentTypeError("Unable to read value from stdin")
    elif string[0] == "@":
        filename = string[1:]
        try:
            with open(os.path.expanduser(filename)) as f:
                output = f.read()
        except IOError:
            raise argparse.ArgumentTypeError("Unable to read file %s" %
                                             filename)
    else:
        output = string
    return output


def csv_dump(dictionary):
    csvfile = StringIO()
    csvwriter = csv.writer(csvfile)
    for key in dictionary:
        csvwriter.writerow([key, dictionary[key]])
    return csvfile.getvalue()


def dotenv_dump(dictionary):
    dotenv_buffer = StringIO()
    for key in dictionary:
        dotenv_buffer.write("%s=%s\n" % (key.upper(), dictionary[key]))
    dotenv_buffer.seek(0)
    return dotenv_buffer.read()


def paddedInt(i):
    '''
    return a string that contains `i`, left-padded with 0's up to PAD_LEN digits
    '''
    i_str = str(i)
    pad = PAD_LEN - len(i_str)
    return (pad * "0") + i_str


def getHighestVersion(name, region=None, location=None,
                      **kwargs):
    '''
    Return the highest version of `name` in the S3 location
    '''

    (bucket, prefix) = get_s3_bucket_prefix(location)
    secrets = listSecrets(region, bucket + "/" + prefix + name, True, **kwargs)

    if len(secrets) == 0:
        return 0
    return secrets[0]["version"]


def clean_fail(func):
    '''
    A decorator to cleanly exit on a failed call to AWS.
    catch a `botocore.exceptions.ClientError` raised from an action.
    This sort of error is raised if you are targeting a region that
    isn't set up (see, `creds3 setup`.
    '''
    def func_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except botocore.exceptions.ClientError as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)
    return func_wrapper


def listSecrets(region=None, location=None, only_latest=True, **kwargs):
    '''
    list all credentials stored in the S3 location,
    and return the names and latest versions of every credential
    '''
    session = get_session(**kwargs)
    client = session.client('s3', region_name=region)
    (bucket, prefix) = get_s3_bucket_prefix(location)
    response = client.list_objects_v2(Bucket=bucket,Prefix=prefix)
    if response.get("Contents"):
        # Get the list of all object in the S3 location
        # sorted by the modification date in reverse order
        secrets = sorted( [{ "name": item["Key"].split('/')[0],
            "version": item["Key"].split('/')[1],
            "datetime": item["LastModified"]} for item in response["Contents"] ],
            key=lambda s: s["datetime"],
            reverse=True)
        if only_latest:
            # Form an array with the latest versions of the objects only
            saved = set()
            saved_add = saved.add
            latest = [ item for item in secrets
                if not (item["name"] in saved or saved_add(item["name"])) ]
        else:
            latest = secrets
    else:
        latest = []

    return latest


def putSecret(name, secret, version="", kms_key="alias/creds3",
              region=None, location=None, context=None,
              digest=DEFAULT_DIGEST, **kwargs):
    '''
    put a secret called `name` into the secret-store,
    protected by the key kms_key
    '''
    if not context:
        context = {}
    session = get_session(**kwargs)
    kms = session.client('kms', region_name=region)
    key_service = KeyService(kms, kms_key, context)
    sealed = seal_aes_ctr_legacy(
        key_service,
        secret,
        digest_method=digest,
    )

    client = session.client('s3', region_name=region)
    (bucket, prefix) = get_s3_bucket_prefix(location)
    version_exists = True
    try:
        obj = client.get_object(Bucket = bucket,
            Key = prefix + name + "/" + version)
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            client.put_object(Bucket = bucket,
                  Key = prefix + name + "/" + version,
                  Metadata = sealed[1],
                  Body = sealed[0]
                )
            version_exists = False
        else:
            fatal(e)

    if version_exists:
        latestVersion = getHighestVersion(name, region,
                                            location,
                                            **kwargs)
        fatal("%s version %s is already in the credential store. "
                "Use the -v flag to specify a new version" %
                (name, latestVersion))

    return True


def getAllSecrets(version="", region=None, location=None,
                  context=None, credential=None, session=None, **kwargs):
    '''
    fetch and decrypt all secrets
    '''
    output = {}
    if session is None:
        session = get_session(**kwargs)

    client = session.client('s3', region_name=region)
    kms = session.client('kms', region_name=region)
    secrets = listSecrets(region, location, True, **kwargs)

    for secret in secrets:
        credential = secret["name"]
        try:
            output[credential] = getSecret(credential,
                                           version,
                                           region,
                                           location,
                                           context,
                                           client,
                                           kms,
                                           **kwargs)
        except:
            pass
    return output


@clean_fail
def getAllAction(args, location, region, **session_params):
    secrets = getAllSecrets(args.version,
                            region=region,
                            location=location,
                            context=args.context,
                            **session_params)
    if args.format == "json":
        output_func = json.dumps
        output_args = {"sort_keys": True,
                       "indent": 4,
                       "separators": (',', ': ')}
    elif not NO_YAML and args.format == "yaml":
        output_func = yaml.dump
        output_args = {"default_flow_style": False}
    elif args.format == 'csv':
        output_func = csv_dump
        output_args = {}
    elif args.format == 'dotenv':
        output_func = dotenv_dump
        output_args = {}
    print(output_func(secrets, **output_args))


@clean_fail
def putSecretAction(args, location, region, **session_params):
    if args.autoversion:
        latestVersion = getHighestVersion(args.credential,
                                          region,
                                          location,
                                          **session_params)
        try:
            version = str(int(latestVersion) + 1)
        except ValueError:
            fatal("Can not autoincrement version. The current "
                  "version: %s is not an int" % latestVersion)
    else:
        version = args.version

    try:
        if putSecret(args.credential, args.value, version,
                     kms_key=args.key, region=region, location=location,
                     context=args.context, digest=args.digest,
                     **session_params):
            print("{0} has been stored".format(args.credential))
    except KmsError as e:
        fatal(e)
    except botocore.exceptions.ClientError as e:
        fatal(e)


@clean_fail
def getSecretAction(args, location, region, **session_params):
    try:
        if WILDCARD_CHAR in args.credential:
            names = expand_wildcard(args.credential,
                                    [x["name"]
                                     for x
                                     in listSecrets(region=region,
                                                    location=location,
                                                    only_latest=True,
                                                    **session_params)])
            print(json.dumps(dict((name,
                                   getSecret(name,
                                             args.version,
                                             region=region,
                                             location=location,
                                             context=args.context,
                                             **session_params))
                                  for name in names)))
        else:
            sys.stdout.write(getSecret(args.credential, args.version,
                                       region=region, location=location,
                                       context=args.context,
                                       **session_params))
            if not args.noline:
                sys.stdout.write("\n")
    except ItemNotFound as e:
        fatal(e)
    except KmsError as e:
        fatal(e)
    except IntegrityError as e:
        fatal(e)


def getSecret(name, version="", region=None,
              location=None, context=None,
              client=None, kms=None, **kwargs):
    '''
    fetch and decrypt the secret called `name`
    '''
    if not context:
        context = {}

    # Can we cache
    if client is None or kms is None:
        session = get_session(**kwargs)
        if client is None:
            client = session.client('s3', region_name=region)
        if kms is None:
            kms = session.client('kms', region_name=region)

    (bucket, prefix) = get_s3_bucket_prefix(location)

    if version == "":
        secrets = listSecrets(region, bucket + "/" + prefix + name,
                True, **kwargs)
        # do a consistent fetch of the credential with the highest version
        if secrets:
            obj = client.get_object(Bucket = bucket,
                    Key = prefix + name + "/" + secrets[0]["version"])
        else:
            raise ItemNotFound("Item {'name': '%s'} couldn't be found in %s" %
                    (name, location))
    else:
        obj = client.get_object(Bucket = bucket,
                    Key = prefix + name + "/" + version)
    material = { "contents": obj["Body"].read() }
    material.update(obj["Metadata"])

    key_service = KeyService(kms, None, context)

    return open_aes_ctr_legacy(key_service, material)


def get_s3_bucket_prefix(location):
    if location.find('/') > 0:
        bucket = location[:location.find('/')]
        prefix = location[location.find('/')+1:]
        if prefix[-1] != '/':
            prefix = prefix + '/'
    else:
        bucket = location
        prefix = ''
    return bucket, prefix

@clean_fail
def deleteSecrets(name, region=None, location=None, **kwargs):
    session = get_session(**kwargs)
    client = session.client('s3', region_name=region)
    (bucket, prefix) = get_s3_bucket_prefix(location)
    response = client.list_objects_v2(Bucket=bucket,Prefix=prefix + name)

    for secret in response["Contents"]:
        print("Deleting %s -- version %s" %
              (name, secret["Key"]))
        client.delete_object(Bucket=bucket,Key=secret["Key"])


@clean_fail
def createS3Bucket(region=None, location=None, **kwargs):
    '''
    create the secret store S3 bucket in the specified region
    '''
    session = get_session(**kwargs)
    client = session.client("s3", region_name=region)
    (bucket, prefix) = get_s3_bucket_prefix(location)

    try:
        response = client.create_bucket(ACL='private',
                Bucket=bucket,
                CreateBucketConfiguration={
                    'LocationConstraint': region
                })
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "BucketAlreadyOwnedByYou":
            print("Credential Store bucket '%s' exists and owned by you" %
                    bucket)
        elif e.response["Error"]["Code"] == "BucketAlreadyExists":
            print("Bucket '%s' exists already - please use another name" %
                    bucket)
            return
        else:
            fatal(e)

    print("Checking the Credential Store bucket '%s' ..." % bucket)
    response = client.head_bucket(Bucket=bucket)
    customer_kms = response.get('ResponseMetadata').get('SSECustomerKeyMD5')
    if customer_kms:
        print("Looks like S3 bucket '%s' employs encryption with a "
                "customer  KMS key %s" % (bucket, customer_kms))
        print("This is not currently supported for Credential Store!")
        fatal(" ".join(["Disable encryption with customer KMS for %s",
                "or use different S3 bucket for Credential Store"]) % bucket)
    print("Credential Store is ok. "
          "Go read the README about how to create your KMS key")


def get_session(aws_access_key_id=None, aws_secret_access_key=None,
                aws_session_token=None, profile_name=None):
    if get_session._cached_session is None:
        get_session._cached_session = \
                boto3.Session(aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key,
                              aws_session_token=aws_session_token,
                              profile_name=profile_name)
    return get_session._cached_session
get_session._cached_session = None


def get_assumerole_credentials(arn):
    sts_client = boto3.client('sts')
    # Use client object and pass the role ARN
    assumedRoleObject = sts_client.assume_role(RoleArn=arn,
                                               RoleSessionName="AssumeRoleCredstashSession1")
    credentials = assumedRoleObject['Credentials']
    return dict(aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'])


def open_aes_ctr_legacy(key_service, material):
    """
    Decrypts secrets stored by `seal_aes_ctr_legacy`.
    Assumes that the plaintext is unicode (non-binary).
    """
    key = key_service.decrypt(b64decode(material['key']))
    digest_method = material.get('digest', DEFAULT_DIGEST)
    ciphertext = b64decode(material['contents'])
    if hasattr(material['hmac'], "value"):
        hmac = binascii.unhexlify(material['hmac'].value)
    else:
        hmac = binascii.unhexlify(material['hmac'])
    return _open_aes_ctr(key, LEGACY_NONCE, ciphertext, hmac, digest_method).decode("utf-8")


def seal_aes_ctr_legacy(key_service, secret, digest_method=DEFAULT_DIGEST):
    """
    Encrypts `secret` using the key service.
    You can decrypt with the companion method `open_aes_ctr_legacy`.
    """
    # generate a a 64 byte key.
    # Half will be for data encryption, the other half for HMAC
    key, encoded_key = key_service.generate_key_data(64)
    ciphertext, hmac = _seal_aes_ctr(
        secret, key, LEGACY_NONCE, digest_method,
    )
    return ( b64encode(ciphertext).decode('utf-8'),
            {
              'key': b64encode(encoded_key).decode('utf-8'),
              'hmac': binascii.hexlify(hmac).decode('utf-8'),
              'digest': digest_method }
            )


def _open_aes_ctr(key, nonce, ciphertext, expected_hmac, digest_method):
    data_key, hmac_key = _halve_key(key)
    hmac = _get_hmac(hmac_key, ciphertext, digest_method)
    # Check the HMAC before we decrypt to verify ciphertext integrity
    if hmac != expected_hmac:
        raise IntegrityError("Computed HMAC on %s does not match stored HMAC")

    decryptor = Cipher(
        algorithms.AES(data_key),
        modes.CTR(nonce),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def _seal_aes_ctr(plaintext, key, nonce, digest_method):
    data_key, hmac_key = _halve_key(key)
    encryptor = Cipher(
        algorithms.AES(data_key),
        modes.CTR(nonce),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext.encode("utf-8")) + encryptor.finalize()
    return ciphertext, _get_hmac(hmac_key, ciphertext, digest_method)


def _get_hmac(key, ciphertext, digest_method):
    hmac = HMAC(
        key,
        get_digest(digest_method),
        backend=default_backend()
    )
    hmac.update(ciphertext)
    return hmac.finalize()


def _halve_key(key):
    half = len(key) // 2
    return key[:half], key[half:]


def get_digest(digest):
    try:
        return _hash_classes[digest]()
    except KeyError:
        raise ValueError("Could not find " + digest + " in cryptography.hazmat.primitives.hashes")


@clean_fail
def list_credentials(region, location, **session_params):
    credential_list = listSecrets(region=region,
                                  location=location,
                                  only_latest=False,
                                  **session_params)
    if credential_list:
        # print list of credential names and versions,
        # sorted by name and then by version
        max_len = max([len(x["name"]) for x in credential_list])
        for cred in sorted(credential_list,
                           key=operator.itemgetter("name", "version")):
            print("{0:{1}} -- version {2:>}".format(
                cred["name"], max_len, cred["version"]))
    else:
        return


def get_session_params(profile, arn):
    params = {}
    if profile is None and arn:
        params = get_assumerole_credentials(arn)
    elif profile:
        params = dict(profile_name=profile)
    return params


def get_parser():
    """get the parsers dict"""
    parsers = {}
    parsers['super'] = argparse.ArgumentParser(
        description="A credential/secret storage system")

    parsers['super'].add_argument("-r", "--region",
                                  help="the AWS region in which to operate. "
                                  "If a region is not specified, creds3h "
                                  "will use the value of the "
                                  "AWS_DEFAULT_REGION env variable, "
                                  "or if that is not set, the value in "
                                  "`~/.aws/config`. As a last resort, "
                                  "it will use " + DEFAULT_REGION)
    parsers['super'].add_argument("-l", "--location",
                                  help="S3 location to use for "
                                  "credential storage")
    role_parse = parsers['super'].add_mutually_exclusive_group()
    role_parse.add_argument("-p", "--profile", default=None,
                            help="Boto config profile to use when "
                            "connecting to AWS")
    role_parse.add_argument("-n", "--arn", default=None,
                            help="AWS IAM ARN for AssumeRole")
    subparsers = parsers['super'].add_subparsers(help='Try commands like '
                                                 '"{name} get -h" or "{name} '
                                                 'put --help" to get each '
                                                 'sub command\'s options'
                                                 .format(name=sys.argv[0]))

    action = 'delete'
    parsers[action] = subparsers.add_parser(action,
                                 help='Delete a credential from the store')
    parsers[action].add_argument("credential", type=str,
                                 help="the name of the credential to delete")
    parsers[action].set_defaults(action=action)

    action = 'get'
    parsers[action] = subparsers.add_parser(action, help="Get a credential "
                                            "from the store")
    parsers[action].add_argument("credential", type=str,
                                 help="the name of the credential to get."
                                 "Using the wildcard character '%s' will "
                                 "search for credentials that match the "
                                 "pattern" % WILDCARD_CHAR)
    parsers[action].add_argument("context", type=key_value_pair,
                                 action=KeyValueToDictionary, nargs='*',
                                 help="encryption context key/value pairs "
                                 "associated with the credential in the form "
                                 "of \"key=value\"")
    parsers[action].add_argument("-n", "--noline", action="store_true",
                                 help="Don't append newline to returned "
                                 "value (useful in scripts or with "
                                 "binary files)")
    parsers[action].add_argument("-v", "--version", default="",
                                 help="Get a specific version of the "
                                 "credential (defaults to the latest version)")
    parsers[action].set_defaults(action=action)

    action = 'getall'
    parsers[action] = subparsers.add_parser(action,
                                            help="Get all credentials from "
                                            "the store")
    parsers[action].add_argument("context", type=key_value_pair,
                                 action=KeyValueToDictionary, nargs='*',
                                 help="encryption context key/value pairs "
                                 "associated with the credential in the form "
                                 "of \"key=value\"")
    parsers[action].add_argument("-v", "--version", default="",
                                 help="Get a specific version of the "
                                 "credential (defaults to the latest version)")
    parsers[action].add_argument("-f", "--format", default="json",
                                 choices=["json", "csv", "dotenv"] +
                                 ([] if NO_YAML else ["yaml"]),
                                 help="Output format. json(default) " +
                                 ("" if NO_YAML else "yaml ") + " csv or dotenv.")
    parsers[action].set_defaults(action=action)

    action = 'list'
    parsers[action] = subparsers.add_parser(action,
                                            help="list credentials and "
                                            "their versions")
    parsers[action].set_defaults(action=action)

    action = 'put'
    parsers[action] = subparsers.add_parser(action,
                                            help="Put a credential into "
                                            "the store")
    parsers[action].add_argument("credential", type=str,
                                 help="the name of the credential to store")
    parsers[action].add_argument("value", type=value_or_filename,
                                 help="the value of the credential to store "
                                 "or, if beginning with the \"@\" character, "
                                 "the filename of the file containing "
                                 "the value, or pass \"-\" to read the value "
                                 "from stdin", default="")
    parsers[action].add_argument("context", type=key_value_pair,
                                 action=KeyValueToDictionary, nargs='*',
                                 help="encryption context key/value pairs "
                                 "associated with the credential in the form "
                                 "of \"key=value\"")
    parsers[action].add_argument("-k", "--key", default="alias/creds3",
                                 help="the KMS key-id of the master key "
                                 "to use. See the README for more "
                                 "information. Defaults to alias/creds3")
    parsers[action].add_argument("-v", "--version", default="1",
                                 help="Put a specific version of the "
                                 "credential (update the credential; "
                                 "defaults to version `1`).")
    parsers[action].add_argument("-a", "--autoversion", action="store_true",
                                 help="Automatically increment the version of "
                                 "the credential to be stored. This option "
                                 "causes the `-v` flag to be ignored. "
                                 "(This option will fail if the currently stored "
                                 "version is not numeric.)")
    parsers[action].add_argument("-d", "--digest", default=DEFAULT_DIGEST,
                                 choices=HASHING_ALGORITHMS,
                                 help="the hashing algorithm used to "
                                 "to encrypt the data. Defaults to SHA256")
    parsers[action].set_defaults(action=action)

    action = 'setup'
    parsers[action] = subparsers.add_parser(action,
                                            help='setup the credential store')
    parsers[action].set_defaults(action=action)
    return parsers

def get_aws_account_id(session):
    sts = session.client("sts")
    user_arn = sts.get_caller_identity()["Arn"]
    return user_arn.split(":")[4]

def main():
    parsers = get_parser()
    args = parsers['super'].parse_args()

    # Check for assume role and set  session params
    session_params = get_session_params(args.profile, args.arn)

    try:
        region = args.region
        session = get_session(**session_params)
        session.client('s3', region_name=region)
        account_id = get_aws_account_id(session)
    except botocore.exceptions.NoRegionError:
        if 'AWS_DEFAULT_REGION' not in os.environ:
            region = DEFAULT_REGION

    location = args.location if args.location \
            else "credential-store-" + account_id

    if "action" in vars(args):
        if args.action == "delete":
            deleteSecrets(args.credential,
                          region=region,
                          location=location,
                          **session_params)
            return
        if args.action == "list":
            list_credentials(region, location, **session_params)
            return
        if args.action == "put":
            putSecretAction(args, location, region, **session_params)
            return
        if args.action == "get":
            getSecretAction(args, location, region, **session_params)
            return
        if args.action == "getall":
            getAllAction(args, location, region, **session_params)
            return
        if args.action == "setup":
            createS3Bucket(region=region, location=location,
                           **session_params)
            return
    else:
        parsers['super'].print_help()

if __name__ == '__main__':
    main()
