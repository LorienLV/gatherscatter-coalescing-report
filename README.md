# Gather/Scatter Coalescing Report

Gather/Scatter Coalescing Report is a simple client for DynamoRIO designed to analyze the number of different cache lines accessed by gather and scatter instructions.

## Dependencies

To use this project, you must have DynamoRIO installed. You can download it from the [DynamoRIO website](https://dynamorio.org/).

## Building the Project

To compile the project, follow these steps:

```
mkdir build
cd build
# Replace "DYNAMORIO_FOLDER" with the actual path to DynamoRIO's root folder.
cmake -DDynamoRIO_DIR="DYNAMORIO_FOLDER/cmake" ..
make
```

## Obtaining the Report for your Application

To execute the client, use the following command:

```
# Replace "DYNAMORIO_FOLDER" with the actual path to DynamoRIO's root folder and "YOUR_APP" with the application you want to analyze.
DYNAMORIO_FOLDER/bin64/drrun -c ./build/libgatherscatter_coalescing_report.so -- YOUR_APP
```

The GatherScatterCoalescingReport by default assumes a cache line size of 64 bytes, but you can manually set the size of the cache line:
```
DYNAMORIO_FOLDER/bin64/drrun -c ./build/libgatherscatter_coalescing_report.so CACHE_SIZE_BYTES -- YOUR_APP
```

## Example Output

The output of this tool will show the number of gather and scatter instructions that access a specific number of cache lines. For example:

```
Using a cache line size of: 64 bytes

Number of gathers that access 1 cache lines: 123
Number of gathers that access 2 cache lines: 141
Number of gathers that access 3 cache lines: 214
Number of gathers that access 4 cache lines: 122
Number of gathers that access 5 cache lines: 576
Number of gathers that access 6 cache lines: 987
Number of gathers that access 7 cache lines: 552
Number of gathers that access 8 cache lines: 244

Number of scatters that access 1 cache lines: 124
Number of scatters that access 2 cache lines: 643
Number of scatters that access 3 cache lines: 532
Number of scatters that access 4 cache lines: 241
Number of scatters that access 5 cache lines: 523
Number of scatters that access 6 cache lines: 636
Number of scatters that access 7 cache lines: 532
Number of scatters that access 8 cache lines: 453
```
