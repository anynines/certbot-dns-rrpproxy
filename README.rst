RRPProxy DNS Authenticator plugin for Certbot
=============================================

This is an extension plugin for the `certbot <https://certbot.eff.org/>`_ CLI which enables certbot to authenticate DNS-01 challenges against the `RRPproxy <https://www.rrpproxy.net/>`_ API.

Installation
------------
To install the plugin, you need ``Python3`` and the Python-module ``pip3`` to be installed to your system.
For the installation of these, see `Downloading Python <https://wiki.python.org/moin/BeginnersGuide/Download>`_ and `Install pip <https://docs.python.org/3/installing/index.html#pip-not-installed>`_

Once you've installed the required tools, you can install ``certbot-dns-rrpproxy`` including all its requirements:
.. codeblock:: Bash
  git clone https://github.com/anynines/certbot-dns-rrpproxy
  pip3 install --user ./certbot-dns-rrpproxy

Usage
-----
To use the dns-rrpproxy Plugin, sample files exist within the ``.workspace`` directory. Copy those example files to ``.ini`` files and modify them to your needs.
Then, navigate inside the directory and execute certbot with the parameter ``-c config.ini``.
.. codeblock:: Bash
  cd certbot-dns-rrpproxy
  cp .workspace/config.ini.example .workspace/config.ini
  cp .workspace/rrpproxy.production.ini.example .workspace/rrpproxy.production.ini
  # update the .ini files to your needs
  certbot certonly -c .workspace/config.ini
