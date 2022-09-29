from setuptools import setup, find_packages

setup(
  name='georgeJ',
  version='1.0',
  description='Start wireshark for kubernetes pod',
  url='https://github.com/jukrut/georgeJ',
  packages=find_packages(),
  install_requires=['sh', 'kubernetes', 'pick'],
  python_requires='>=3.6',
  entry_points={
        'console_scripts': [
            'georgeJ=georgeJ:main',
        ],
    },
)

