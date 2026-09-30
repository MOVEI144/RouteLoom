# RouteLoom endpoint — C example

The C form of [`examples/endpoint_cpp`](../endpoint_cpp): the same DevRam
quick-start endpoint (Kconfig identity and development key, endpoint role and
profile, PT-4M-v2), written against the Device C API
[`routeloom/device.h`](../../components/routeloom_device/include/routeloom/device.h).

> EXPERIMENTAL: the default `CONFIG_ROUTELOOM_DEVELOPMENT_KEY_HEX` is a shared
> development key and DevRam reports `RL_DEV_SECURITY_DEVELOPMENT`. Do not
> deploy the default key.

- `rl_dev_start(&observer)` boots the node from the component Kconfig on its
  own Owner task and returns the handle.
- Callbacks (`on_message`, `on_delivery`, `on_membership`, ...) and
  `on_poll` run on the Owner task. Device calls from inside a callback
  return `RL_STATUS_BUSY`; make them from `on_poll` or a posted job.
- `rl_dev_post()` is the only call another task may make (eight waiting
  jobs; a full queue returns `RL_STATUS_BUSY`).
- Every struct starts with `{struct_size, version}`: fill it with
  `rl_dev_struct_init()` or `rl_dev_send_options_init()`.

Build in the repository:

```bash
idf.py set-target esp32c3
idf.py build
```

Outside the repository, uncomment the git dependency in
`main/idf_component.yml` exactly as described in the
[C++ example's README](../endpoint_cpp/README.md#style-b-component-manager-git-dependency).
`menuconfig → RouteLoom example` sets the node the example greets once a
minute (0 = receive only). A successful build proves compile and link only.
