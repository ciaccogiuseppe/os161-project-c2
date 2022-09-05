vname="SHELL";

cd os161-base-2.0.3/kern/conf
./config $vname
cd ..
cd compile
cd $vname
bmake depend
bmake
bmake install