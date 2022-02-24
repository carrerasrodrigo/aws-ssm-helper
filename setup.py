import setuptools

setuptools.setup(
    name="ssm",
    version="0.0.1",
    author='Rodrigo N. Carreras',
    author_email='rodrigo@comparaencasa.com',
    packages=['ssm'],
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'boto3'
    ]
)
