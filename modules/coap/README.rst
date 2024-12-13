.. _mod-coap:

COAP
==============

The ``coap`` module implements DNS over COAP.

.. code-block:: lua

        modules.unload('coap')

Building and Running with Docker
================================

To build the Docker image, navigate to the directory containing the Dockerfile and run:

.. code-block:: bash

    docker build -t knot-resolver-coap .


To run the Docker container with the host network, use the following command:

.. code-block:: bash

    docker run --network=host knot-resolver-coap
