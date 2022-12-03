import os

import setuptools

os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setuptools.setup(
    name="ssm",
    version="0.1.0",
    author='Rodrigo N. Carreras',
    author_email='rodrigo@comparaencasa.com',
    packages=['ssm'],
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'boto3',
        'click'
    ],
    entry_points = {
        'console_scripts': [
            'ssm_get_key = ssm.scripts.ssm_get_key:main',
            'ssm_replace_from_input = ssm.scripts.ssm_replace_from_input:main'
        ],
    }
)
