from setuptools import setup

setup(name='peinjector',
      version='0.1',
      description='Injects any data into a PE32|PE32+ file.',
      url='https://github.com/adeilsonsilva/legendary-invention',
      author='Adeilson Silva',
      author_email='adeilson@protonmail.com',
      license='gplv3',
      packages=['.'],
      install_requires=[
        'numpy==1.17.0',
        'pefile==2019.4.18'
      ],
      zip_safe=False)
