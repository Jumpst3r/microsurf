## Test: secret-dep-cf-1

#### Test description

A simple secret dependent control flow example, branching depending on bit position:

``
if (secret & (1<<3)){
otherFct(2);
}
``

### Expected behavior:

When running the detection module with default parameters (no variable secret dependent hit count detection),
the following leaks should be detected (not including the dependencies in libc functions such as ``____
strtoul_l_internal`,
which also appear in the results):

- The secret dependent conditional in the main function

For the corresponding test to succeed, the framework needs to detect the conditional if branch in the main function.

