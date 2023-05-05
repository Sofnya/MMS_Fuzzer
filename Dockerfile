FROM python:3
COPY . /fuzzer
RUN apt-get update 
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y tshark
RUN pip3 install -r /fuzzer/requirements.txt
RUN git clone https://github.com/mz-automation/libiec61850.git
WORKDIR /fuzzer
RUN make -C ./trafficGen all
