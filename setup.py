from setuptools import setup

setup(
    name='creds3',
    version='1.0.3',
    description='A clone of Credstash for managing secrets in the cloud using AWS KMS and S3',
    license='Apache2',
    url='https://github.com/romanrev/creds3',
    classifiers=[
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
    ],
    scripts=['creds3.py'],
    py_modules=['creds3'],
    install_requires=[
        'cryptography>=1.5, <2.0',
        'boto3>=1.1.1',
    ],
    extras_require={
        'YAML': ['PyYAML>=3.10']
    },
    entry_points={
        'console_scripts': [
            'creds3 = creds3:main'
        ]
    }
)
