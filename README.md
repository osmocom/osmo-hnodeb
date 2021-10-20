osmo-hnodeb - Osmocom hNodeB Implementation
===========================================

This repository contains a C-language implementation of a 3G Home NodeB (hNodeB).
It is part of the [Osmocom](https://osmocom.org/) Open Source Mobile Communications
project.

You can use it to interface Iuh-speaking Home NodeB Gateway (HNB-GW), such as osmo-hnbgw.

IMPORTANT: This is a first step towards implementing a minimal hNodeB upper
layer part, mainly handling HNBAP/RUA/RANAP messages on the Iuh interface.  This
is not expected to be a full / usable hNodeB anytime soon [if ever].

Homepage
--------

The official homepage of the project is
https://osmocom.org/projects/osmohnodeb/wiki

GIT Repository
--------------

You can clone from the official osmo-hnodeb.git repository using

	git clone git://git.osmocom.org/osmo-hnodeb.git

There is a cgit interface at https://git.osmocom.org/osmo-hnodeb/

Documentation
-------------

User Manuals and VTY reference manuals are [optionally] built in PDF form
as part of the build process.

Pre-rendered PDF version of the current "master" can be found at
[User Manual](https://ftp.osmocom.org/docs/latest/osmohnodeb-usermanual.pdf)
as well as the [VTY Reference Manual](https://ftp.osmocom.org/docs/latest/osmohnodeb-vty-reference.pdf)


Mailing List
------------

Discussions related to osmo-bts are happening on the
openbsc@lists.osmocom.org mailing list, please see
https://lists.osmocom.org/mailman/listinfo/openbsc for subscription
options and the list archive.

Please observe the [Osmocom Mailing List
Rules](https://osmocom.org/projects/cellular-infrastructure/wiki/Mailing_List_Rules)
when posting.

Contributing
------------

Our coding standards are described at
https://osmocom.org/projects/cellular-infrastructure/wiki/Coding_standards

We us a gerrit based patch submission/review process for managing
contributions.  Please see
https://osmocom.org/projects/cellular-infrastructure/wiki/Gerrit for
more details

The current patch queue for osmo-bts can be seen at
https://gerrit.osmocom.org/#/q/project:osmo-hnodeb+status:open
