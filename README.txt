Majd Abdo 207930660
Abed Alhalim Kadi 206624603

* i opened a new directory in $PIN_TOOL_DIR/source/tools/ named homeworks

compile:	
	1. Copy the files: project.cpp,rtn-translation.cpp,makefile and makefile.rules into $PIN_TOOL_DIR/source/tools/homeworks			
	2. cd $PIN_TOOL_DIR/source/tools/homeworks
	3. make project.test
// after compiling there will be $PIN_TOOL_DIR/source/tools/homeworks/obj-intel64/ directory containing project.so.



run:
	1. copy bzip2 and input-long.txt to $PIN_TOOL_DIR/source/tools/homeworks/
	2. run bzip2 test:
		$PIN_TOOL_DIR/pin -t ./obj-intel64/project.so -prof -- ./bzip2 -k -f input-long.txt

*we used 2 files "reorder-bbl-count.csv" and "inilne-rtn-count.csv" for collecting  profiling information  

		$PIN_TOOL_DIR/pin -t ./obj-intel64/project.so -opt -- ./bzip2 -k -f input-long.txt
		$PIN_TOOL_DIR/pin -t ./obj-intel64/project.so -opt -no_tc_commit -- ./bzip2 -k -f input-long.txt