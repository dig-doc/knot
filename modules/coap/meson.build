# C module: coap

coap_src = files([
  'coap.c',
])
c_src_lint += coap_src

coap_mod = shared_module(
  'coap',
  coap_src,
  dependencies: mod_deps,
  include_directories: mod_inc_dir,
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
  link_with: kresd,
)
