# Binary-Translation-and-Optimization-project
optimization on a given code using function inlining and code reordering.

we were asked to write a Pintool in JIT mode and in Probe mode,when applied with the “-prof” knob, the pintool should preferably count executed instructions in the
MainExecutable image only and print them and when applied with the “-opt” knob, the pintool should run in probe mode and apply Function Inlining of
functions that have a single Hot call site, followed by Code Reordering:

so we started with collecting information(profiling) for the inlining part and for the code reordering(info on the basic blocks)
and then for the optimization part we commited the inlined functions in the desired place in the routine and commited the bbls of the routine in the desired order.
