# Overview

DISCLAIMER: I have developed this prototype just up to the point of getting some form of LBR samples from the system and align them to .NET JIT Schema. In terms of correctness, performance, etc., I haven't actually spent much time. In summary, my first effort was to get LBR data into a .NET schema. 

I am currently working on actually populating the schema now in a way that actually makes sense.

# High Level Overview

`lbr.cpp` contains most of the implementation of my work and functions similar to `pgo.cpp`. 

Roughly, the POC functions:

0. On JIT startup, the `LBRManager` will start an ETW trace and insert hooks to listen for LBR samples for its own process id. Any samples captured will be bucketed per method using some of the runtimes metadata `EECodeInfo` in `LBRManager::ReceiveLbrEvent` method. These samples are saved for alignment at a JIT method recompile.

1. On the first pass of a method compile, we create a dummy instrumentation (using a barebones version of the block based instrumenter) to create a schema for a method, including the mapping of IL code to machine code (in the form of basic block offsets I believe). This makes it easier for the `LBRManager` to correlate LBR samples for each method.

2. On a JIT recompile of a method, the `LBRManager` will attempt to map the LRB samples saved for a method to native code blocks for that method, and then use the native code to IL code mapping from `ICorDebugInfo` to populate the IL blocks in the PGO schema. I have added some methods to then save the schema so that the optimizer will read the schema popualted by the `LBRManager` at runtime.

# Relevant Environment Variables

You can view these at `clrconfigvalues.h`, but I have added two environment variables for controling the LBR sampling: `DOTNET_UseLBRSampling={0,1}`, which will trigger the LBR sampling PGO instead of DPGO, and `DOTNET_LBRDump=methodName` which will dump various debug information when aligning LBR samples for `methodName` (only works on a single method right now) if in debug mode.

# Running

NOTE: You must run in administrator mode. Also, right now I believe the unpublished interfaces into working with some of the ETW LBR streams requires Windows 11 23H2 (my OS build is 22631.4751).

This is how I am currently running a sample, using these environment variables to help get the prototype to get the LBR samples and align on a method recompile:

```powershell
set "DOTNET_UseLBRSampling=1"
set "DOTNET_LBRDump=MakeChoice"
set "DOTNET_TieredPGO=0"
set "DOTNET_PGODataPath=lbr-block.txt"
set "DOTNET_TC_CallCountingDelayMs=1500"
set "DOTNET_WritePGOData=1"

path/to/corerun sample-program.dll 
```

# Next Steps

Every LBR sample is tuple (`from`, `to`) where `from` is the address of the branch taken, and `to` is the address of the jump. Right now I independetly treat each address is a "sample" to bucket into a block. This isn't really correct, and leads to odd populations of the block schema. As I said earlier, I just wanted to get something to function. 

I am going to work on making this data and population make more sense, and then will go about doing some perf collection.
