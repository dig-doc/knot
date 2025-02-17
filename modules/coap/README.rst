.. _mod-coap:

CoAP
==============

The ``coap`` module implements DNS over COAP.

.. code-block:: lua

        modules.unload('coap')

Config
================
.. code-block:: yaml

    lua:
      script:  |
        modules = {
            coap = {
                host = 127.0.0.1,
                port = 53
            }
        }
        net.ipv6 = false


Building and Running with Docker
================================

To build the Docker image, navigate to the directory containing the Dockerfile and run:

.. code-block:: bash
    docker build -t knot-resolver-coap .

    To run the Docker container with the host network, use the following command:

    .. code-block:: bash

    docker run --network host knot-resolver-coap
