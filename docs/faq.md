# Frequently Asked Questions

_This page covers common pitfalls that could be encountered during the usage of the microsurf library._

## Emulation Errors

To get the most information, make sure to set the environment variable `DEBUG` (`export DEBUG=1`). This will cause *Microsurf* to be more verbose, which might help tracking down any problems.

### `QlErrorCoreHook: _hook_intr_cb : not handled`

This is an issue with the underlying emulator (Qiling): Not all interrupts are handled, and some are yet to be added. In the meanwhile, if you wish to improve Qiling, feel free to open a pull [request](https://github.com/qilingframework/qiling).

Compiling with an older toolchain usually resolves the problem.

### `Application returned a non zero exit code`

The emulated application returned a non-zero exit code. This might be due to an incorrect list of arguments provided to the application.

Sometimes, the emulation root directory might not be set up correctly and the runtime linker might have problems finding certain shared objects. In that case, the output will often contain a line such as `error while loading shared libraries: 'libcrypto.so.3'`                                                                                                                                     

make sure that all shared objects are where the binary expects them to be. If the target architecture matches the host architecture, you can check where an application expects shared objects to be located by running `ldd my-binary.elf`.

## Does the lack of reported leaks imply that my binary is safe ?

No, it does not. A common trait of dynamic detection frameworks is that they can only reason about observed behavior. It may be possible that the generated secrets did not trigger every code path.

Nevertheless, dynamic approaches are useful as constant-time debugging tools, especially given that they are much more scalable and easy to use compared to formal tools that may provide guarantees in the absence of leakages.

