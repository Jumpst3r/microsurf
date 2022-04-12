# Advanced Usage

```{note}
Make sure you [installed](installation.md) the framework if you wish to follow along.
```

In the [Quickstart](quickstart.md) section, we went over how to use the microsurf library in an end-to-end manner. This is very useful for the average user, as it only requires two basic steps:

1. Create a `SCDetector` object.
2. Call the `.exec()` function on the created object.

However, from a research perspective, it is sometimes required to be able to have fine-grained control on some aspects of the process. Fortunately, microsurf is a *framework*, and as such, provides you with the tools you need to build your own multi-arch, custom side channel detection pipeline.

To do so, you will still need to create a `SCDetector` object (refer to the [Quickstart](quickstart.md) for more information). Once the object is created, you will have access to a number of lower level functions, which are documented below, along with the `SCDetector` constructor:

## SCDetector module

```{eval-rst}
.. autoclass:: microsurf.SCDetector
  :members:
```

## Elf tools module

The microsurf framework also exposes a number of function which allow you to parse ELF files (using [pyelftools](https://github.com/eliben/pyelftools) under the hood). These can be useful to add context to detected side channels, if the binary is compiled with debug symbols (or not stripped).

```{eval-rst}
.. automodule:: microsurf.utils.elf
  :members:
```

## Traces module

In microsurf, traces are represented as objects:

```{eval-rst}
.. automodule:: microsurf.pipeline.tracetools.Trace
  :members:
```
