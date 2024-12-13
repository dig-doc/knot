# C module: coap
# SPDX-License-Identifier: GPL-3.0-or-later

coap_src = files([
  'coap.c',
])
c_src_lint += coap_src

# Dependencies
libdns = dependency('ldns', required: true)
libcoap = dependency('libcoap-3-openssl', required: true)

coap_mod = shared_module(
  'coap',
  coap_src,
  dependencies: mod_deps + [libdns, libcoap],
  include_directories: mod_inc_dir,
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
  link_with: kresd,
)