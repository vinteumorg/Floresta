# Prepares our enviroment to run our tests
#
# This script shold be executed once, before running our functinal test
# for the first time. It'll download and build all needed dependecies
# to make sure we are not missing anything during our tests.

# Check for dependecies, we need Golang for Utreexod and Rust for Floresta
go version &>/dev/null

if [ $? -ne 0 ]
then
	echo "You must have golang installed to run those tests!"
fi

cargo version &>/dev/null

if [ $? -ne 0 ]
then
	echo "You must have cargo installed to run those tests!"
fi


mkdir -p ./bin

cd bin

# Download and build utreexod
ls -la utreexod &>/dev/null
if [ $? -ne 0 ]
then
	git clone https://github.com/utreexo/utreexod
fi

cd utreexod
go build . &>/dev/null

# build floresta
cd ../../
cargo build --bin florestad --features json-rpc &>/dev/null

echo "All done!"
