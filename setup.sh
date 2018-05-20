pip3 install requests, prettytable

# Install pe-parse and python library pepy
git clone https://github.com/KuechA/pe-parse.git
cd pe-parse
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --config Release
cmake --build . --config Release --target install
cd ../python
python setup.py build
python setup.py install

