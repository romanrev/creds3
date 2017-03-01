**Table of Contents**  *generated with [DocToc](http://doctoc.herokuapp.com/)*

- [CredS3](#creds3)
	- [Quick Installation](#quick-installation)
		- [Linux install-time dependencies](#linux-install-time-dependencies)
	- [What is this?](#what-is-this)
	- [How does it work?](#how-does-it-work)
		- [Stashing Secrets](#stashing-secrets)
		- [Getting Secrets](#getting-secrets)
		- [Controlling and Auditing Secrets](#controlling-and-auditing-secrets)
		- [Versioning Secrets](#versioning-secrets)
	- [Dependencies](#dependencies)
	- [Setup](#setup)
		- [tl;dr](#tldr)
		- [Setting up KMS](#setting-up-kms)
		- [Setting up creds3](#setting-up-creds3)
		- [Working with multiple AWS accounts (profiles)](#working-with-multiple-aws-accounts-profiles)
	- [Usage](#usage)
	- [IAM Policies](#iam-policies)
		- [Secret Writer](#secret-writer)
		- [Secret Reader](#secret-reader)
		- [Setup Permissions](#setup-permissions)
	- [Security Notes](#security-notes)
	- [Frequently Asked Questions (FAQ)](#frequently-asked-questions-faq)
		- [1. Where is the master key stored?](#1-where-is-the-master-key-stored)
		- [2. How is credential rotation handled?](#2-how-is-credential-rotation-handled)
		- [3. How much do the AWS services needed to run creds3 cost?](#3-how-much-do-the-aws-services-needed-to-run-creds3-cost)
		- [4. Why S3 for the credential store? Why not DynamoDB?](#4-why-s3-for-the-credential-store-why-not-dynamodb)
		- [5. Where can I learn more about use cases and context for something like creds3?](#5-where-can-i-learn-more-about-use-cases-and-context-for-something-like-creds3)

# CredS3

This is a rip-off of a perfect [Credstash](https://github.com/fugue/credstash)
package where the S3 location is used instead of the DynamoDB table.
See [FAQ](#frequently-asked-questions-faq) to find out why this was done.

All kudos go to the original author of Credstash.

## Quick Installation
0. (Linux only) Install dependencies 
1. `pip install creds3`
2. Set up a key called creds3 in KMS (found in the IAM console)
3. Make sure you have AWS creds in a place that boto/botocore can read them
4. `creds3 setup`

### Linux install-time dependencies
Cred3 recently makes use of `cryptography`. `cryptography` uses pre-built binary wheels on OSX and Windows, but does not on Linux. That means that you need to install some dependencies if you want to run creds3 on linux. 

For Debian and Ubuntu, the following command will ensure that the required dependencies are installed:
```
$ sudo apt-get install build-essential libssl-dev libffi-dev python-dev
```
For Fedora and RHEL-derivatives, the following command will ensure that the required dependencies are installed:
```
$ sudo yum install gcc libffi-devel python-devel openssl-devel
```

In either case, once you've installed the dependencies, you can do `pip install creds3` as usual.

See [this](https://cryptography.io/en/latest/installation/) for more information


## What is this?

Software systems often need access to some shared credential. For example,
your web application needs access to a database password, or an API key
for some third party service.

Some organizations build complete credential-management systems, but for most
of us, managing these credentials is usually an afterthought. In the best case,
people use systems like ansible-vault, which does a pretty good job, but leads
to other management issues (like where/how to store the master key).
A lot of credential management schemes amount to just SCP'ing a `secrets` file
out to the fleet, or in the worst case, burning secrets into the SCM (do a
github search on `password`).

CredS3 is a very simple, easy to use credential management and distribution
system that uses AWS Key Management Service (KMS) for key wrapping and
master-key storage, and S3 for credential storage and sharing.

## How does it work?

After you complete the steps in the `Setup` section, you will have an
encryption key in KMS (in this README, we will refer to that key as the
`master key`), and a credential storage in an S3 bucket location.

If you do not specify an S3 bucket location via the `-l` option to `setup`
command, the bucket that will be created by default will have the name of
`credential-store-AWSACCOUNTID` where the `AWSACCOUNTID` is the AWS
account ID under which the bucket is created.

### Stashing Secrets

Whenever you want to store/share a credential, such as a database password,
you simply run `creds3 put [credential-name] [credential-value]`. For example,
`creds3 put myapp.db.prod supersecretpassword1234`. creds3 will go to the KMS
and generate a unique data encryption key, which itself is encrypted by the
master key (this is called key wrapping). creds3 will use the data encryption
key to encrypt the credential value. It will then store the encrypted
credential, along with the wrapped (encrypted) data encryption key in the
credential store in an S3 location.

The key and its value is stored in the specified S3 bucket location under
the following structure:

    credential-store-AWSACCOUNTID
                            |
                            ├── [credential 1 name]
                            ...                  ├── [version number 1]
                                                 ├── [version number 2]
                                                 ...
### Getting Secrets

When you want to fetch the credential, for example as part of the bootstrap
process on your web-server, you simply do `creds3 get [credential-name]`.
For example, `export DB_PASSWORD=$(creds3 get myapp.db.prod)`. When you run
`get`, creds3 will go and fetch the encrypted credential and the wrapped
encryption key from the credential store (S3). It will then send the wrapped
encryption key to KMS, where it is decrypted with the master key. creds3 then
uses the decrypted data encryption key to decrypt the credential.
The credential is printed to `stdout`, so you can use it in scripts or assign
it to environment variables.

### Controlling and Auditing Secrets

Optionally, you can include any number of
[Encryption Context](http://docs.aws.amazon.com/kms/latest/developerguide/encrypt-context.html)
key value pairs to associate with the credential. The exact set of encryption
context key value pairs that were associated with the credential when it was
`put` in S3 must be provided in the `get` request to successfully decrypt
the credential. These encryption context key value pairs are useful to provide
auditing context to the encryption and decryption operations in your CloudTrail
logs. They are also useful for constraining access to a given creds3 stored
credential by using KMS Key Policy conditions and KMS Grant conditions.
Doing so allows you to, for example, make sure that your database servers and
web-servers can read the web-server DB user password but your database servers
can not read your web-servers TLS/SSL certificate's private key.
A `put` request with encryption context would look like

    creds3 put myapp.db.prod supersecretpassword1234 app.tier=db \
        environment=prod

In order for your web-servers to read that same credential they would execute
a `get` call like

    export DB_PASSWORD=$(creds3 get myapp.db.prod environment=prod app.tier=db)

### Versioning Secrets

Credentials stored in the credential-store are versioned and immutable.
That is, if you `put` a credential called `foo` with a version of `1` and
a value of `bar`, then foo version 1 will always have a value of bar, and
there is no way in `creds3` to change its value (although you could go fiddle
with the bits in the version file in S3 bucket, but you shouldn't do that).
Credential rotation is handed through versions. Suppose you do
`creds3 put foo bar`, and then decide later to rotate `foo`,
you can put version 2 of `foo` by doing `creds3 put -v 2 foo baz`.
The next time you do `creds3 get foo`, it will return `baz`. You can get
specific credential versions as well (with the `-v <version>` flag). You can
fetch a list of all credentials in the credential-store and their versions
with the `list` command.

If you use incrementing integer version numbers
(for example, `[1, 2, 3, ...]`), then you can use the `-a` flag with the
`put` command to automatically increment the version number.

## Dependencies

creds3 uses the following AWS services:

* AWS Key Management Service (KMS) - for master key management and key wrapping
* AWS Identity and Access Management - for access control
* Amazon S3 - for credential storage

## Setup

### tl;dr

1. Set up a key called `creds3` in KMS
2. Install creds3's python dependencies (or just use pip)
3. Make sure you have AWS creds in a place that boto/botocore can read them
4. Run `creds3 setup`

### Setting up KMS

`creds3` will not currently set up your KMS master key. To create a KMS
master key,

1. Go to the AWS console
2. Go to the IAM console/tab
3. Click "Encryption Keys" in the left
4. Click "Create Key". For alias, put "creds3". If you want to use a different name, be sure to pass it to creds3 with the `-k` flag
5. Decide what IAM principals you want to be able to manage the key
6. On the "Key Usage Permissions" screen, pick the IAM users/roles that will be using creds3 (you can change your mind later)
7. Done!

### Setting up creds3

The easiest thing to do is to just run `pip install creds3`. That will
download and install creds3 and its dependencies (boto and PyCypto).

The second easiest thing to do is to do `python setup.py install` in the
`creds3` directory.

The python dependencies for creds3 are in the `requirements.txt` file. You
can install them with `pip install -r requirements.txt`.

In all cases, you will need a C compiler for building `PyCrypto` (you can
install `gcc` by doing `apt-get install gcc` or `yum install gcc`).

You will need to have AWS credentials accessible to boto/botocore. The
easiest thing to do is to run creds3 on an EC2 instance with an IAM role.
Alternatively, you can put AWS credentials in the `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY` environment variables.
Or, you can put them in a file as described
[here](http://boto.readthedocs.org/en/latest/boto_config_tut.html).

You can specify the region in which `creds3` should operate by using the `-r`
flag, or by setting the `AWS_DEFAULT_REGION` environment variable.
Note that the command line flag takes precedence over the environment variable.
If you set neither, then `creds3` will operate against us-east-1.

Once credentials are in place, run `creds3 setup`. This will create the S3
bucket needed for credential storage.

### Working with multiple AWS accounts (profiles)

If you need to work with multiple AWS accounts, an easy thing to do is to
set up multiple profiles in your `~/.aws/credentials` file. For example,

```
[dev]
aws_access_key_id = AKIDEXAMPLEASDFASDF
aws_secret_access_key = SKIDEXAMPLE2103429812039423
[prod]
aws_access_key_id= AKIDEXAMPLEASDFASDF
aws_secret_access_key= SKIDEXAMPLE2103429812039423
```

Then, by setting the `AWS_PROFILE` environment variable to the name of the
profile, (dev or prod, in this case), you can point creds3 at the appropriate
account.

See [this document](https://blogs.aws.amazon.com/security/post/Tx3D6U6WSFGOK2H/A-New-and-Standardized-Way-to-Manage-Credentials-in-the-AWS-SDKs)
for more information.

## Usage

Running `creds3 --help will produce this ind of helpful screen:

    usage: creds3 [-h] [-r REGION] [-l LOCATION] {delete,get,getall,list,put,setup} ...

    A credential/secret storage system

    delete
        usage: creds3 delete [-h] [-r REGION] [-l LOCATION] credential

        positional arguments:
        credential  the name of the credential to delete

    get
        usage: creds3 get [-h] [-r REGION] [-l LOCATION] [-k KEY] [-n] [-v VERSION]
                            credential [context [context ...]]

        positional arguments:
        credential            the name of the credential to get. Using the wildcard
                                character '*' will search for credentials that match
                                the pattern
        context               encryption context key/value pairs associated with the
                                credential in the form of "key=value"

        optional arguments:
        -n, --noline          Don't append newline to returned value (useful in
                                scripts or with binary files)
        -v VERSION, --version VERSION
                                Get a specific version of the credential (defaults to
                                the latest version).

    getall
        usage: creds3 getall [-h] [-r REGION] [-l LOCATION] [-v VERSION] [-f {json,yaml,csv}]
                                [context [context ...]]

        positional arguments:
        context               encryption context key/value pairs associated with the
                                credential in the form of "key=value"

        optional arguments:
        -v VERSION, --version VERSION
                                Get a specific version of the credential (defaults to
                                the latest version).
        -f {json,yaml,csv}, --format {json,yaml,csv}
                                Output format. json(default), yaml or csv.


    list
        usage: creds3 list [-h] [-r REGION] [-l LOCATION]

    put
    usage: creds3 put [-h] [-k KEY] [-v VERSION] [-a]
                        credential value [context [context ...]]

    positional arguments:
    credential            the name of the credential to store
    value                 the value of the credential to store or, if beginning
                            with the "@" character, the filename of the file
                            containing the value
    context               encryption context key/value pairs associated with the
                            credential in the form of "key=value"

    optional arguments:
    -h, --help            show this help message and exit
    -k KEY, --key KEY     the KMS key-id of the master key to use. See the
                            README for more information. Defaults to
                            alias/creds3
    -v VERSION, --version VERSION
                            Put a specific version of the credential (update the
                            credential; defaults to version `1`).
    -a, --autoversion     Automatically increment the version of the credential
                            to be stored. This option causes the `-v` flag to be
                            ignored. (This option will fail if the currently
                            stored version is not numeric.)

    setup
        usage: creds3 setup [-h] [-r REGION] [-l LOCATION]

    optional arguments:
    -r REGION, --region REGION
                            the AWS region in which to operate. If a region is not
                            specified, creds3 will use the value of the
                            AWS_DEFAULT_REGION env variable, or if that is not
                            set, us-east-1
    -l LOCATION, --location LOCATION
                            S3 location to use for credential storage
    -n ARN, --arn ARN     AWS IAM ARN for AssumeRole

## IAM Policies

### Secret Writer
You can put or write secrets to creds3 by either using KMS Key Grants, KMS
Key Policies, or IAM Policies. If you are using IAM Policies, the following
IAM permissions are the minimum required to be able to put or write secrets:

    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Action": [
            "kms:GenerateDataKey"
          ],
          "Effect": "Allow",
          "Resource": "arn:aws:kms:us-east-1:AWSACCOUNTID:key/KEY-GUID"
        },
        {
          "Action": [
            "s3:PutObject"
          ],
          "Effect": "Allow",
          "Resource": "arn:aws:s3::::credential-store-AWSACCOUNTID"
        }
      ]
    }

If you are using Key Policies or Grants, then the `kms:GenerateDataKey`
is not required in the policy for the IAM user/group/role.
Replace `AWSACCOUNTID` with the account ID for your bucket, and replace
the KEY-GUID with the identifier for your KMS key (which you can find in
the KMS console).

### Secret Reader

You can read secrets from creds3 with the get or getall actions by either
using KMS Key Grants, KMS Key Policies, or IAM Policies. If you are using
IAM Policies, the following IAM permissions are the minimum required to be
able to get or read secrets:


    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Action": [
            "kms:Decrypt"
          ],
          "Effect": "Allow",
          "Resource": "arn:aws:kms:us-east-1:AWSACCOUNTID:key/KEY-GUID"
        },
        {
          "Action": [
            "s3:List*"
          ],
          "Effect": "Allow",
          "Resource": "arn:aws:s3:::credential-store-AWSACCOUNTID"
        },
        {
          "Action": [
            "s3:GetObject",
            "s3:List*"
          ],
          "Effect": "Allow",
          "Resource": "arn:aws:s3:::credential-store-AWSACCOUNTID/*"
        }
      ]
    }

If you are using Key Policies or Grants, then the `kms:Decrypt` is not
required in the policy for the IAM user/group/role.
Replace `AWSACCOUNTID` with the account ID for your bucket name, and
replace the KEY-GUID with the identifier for your KMS key
(which you can find in the KMS console).

### Setup Permissions

In order to run `creds3 setup`, you will also need to be able to perform
the following operations:

    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": [
                    "s3:CreateBucket",
                    "s3:HeadBucket"
                ],
                "Effect": "Allow",
                "Resource": "*"
            }
        ]
    }


## Security Notes

Any IAM principal who can get items from the credential store S3 bucket, and
can call KMS.Decrypt, can read stored credentials.

The target deployment-story for `creds3` is an EC2 instance running with an
IAM role that has permissions to read the credential store and use the master
key. Since IAM role credentials are vended by the instance metadata service,
by default, any user on the system can fetch creds and use them to retrieve
credentials. That means that by default, the instance boundary is the security
boundary for this system. If you are worried about unauthorized users on your
instance, you should take steps to secure access to the Instance Metadata
Service (for example, use iptables to block connections to 169.254.169.254
except for privileged users).
Also, because creds3 is written in python, if an attacker can dump the memory
of the creds3 process, they may be able to recover credentials. This is a
known issue, but again, in the target deployment case, the security boundary
is assumed to be the instance boundary.

## Frequently Asked Questions (FAQ)

### 1. Where is the master key stored?

The master key is stored in AWS Key Management Service (KMS), where it is
stored in secure HSM-backed storage. The Master Key never leaves the
KMS service.

### 2. How is credential rotation handled?

Every credential in the store has a version number. Whenever you want to a
credential to a new value, you have to do a `put` with a new credential
version. For example, if you have `foo` version 1 in the database, then to
update `foo`, you can put version 2. You can either specify the version
manually (i.e. `creds3 put foo bar -v 2`), or you can use the `-a` flag,
which will attempt to autoincrement the version number (for example,
`creds3 put foo baz -a`). Whenever you do a `get` operation, creds3 will
fetch the most recent (highest version) version of that credential.
So, to do credential rotation, simply put a new version of the credential,
and clients fetching the credential will get the new version.

### 3. How much do the AWS services needed to run creds3 cost?

tl;dr: If you are using less than 25 reads/hour and 2 writes per hour on
S3 bucket today, it will cost ~$1/month to use creds3.

The master key in KMS costs $1 per month.

If you are using creds3 heavily reads/writes, you may incur additional charges
and might consider switching to using
[Credstash](https://github.com/fugue/credstash) instead which employs 
DynamoDB as a credential storage with much more generous allowances
for reads and writes.

You can estimate your bill using the
[S3 AWS Simple Monthly Calculator](http://calculator.s3.amazonaws.com/index.html#s=S3).

### 4. Why S3 for the credential store? Why not DynamoDB?

While DDB fits the application really well, there might be places where one is
forced to use S3 for storing the secrets (the word 'enterprise' come to mind).

This package is a total rip-off of the
excellent [Credstash](https://github.com/fugue/credstash) tool where the
DynamoDB storage is replaced by S3 to serve that particular use case.

### 5. Where can I learn more about use cases and context for something like creds3?

Check out this [blog post](http://blog.fugue.it/2015-04-21-aws-kms-secrets.html)
from the Credstash author

