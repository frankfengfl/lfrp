CFLAGS = -g -m64 -std=c++11 -O2 -march=native
#CFLAGS = -g -m64 -std=c++11 -g -march=native
targetTun = ./bin/lfrpTun
targetCli = ./bin/lfrpCli
targetSvr = ./bin/lfrpSvr
targetEchoCli = ./bin/EchoClient
targetEchoSvr = ./bin/EchoServer
TARGETDIR = ./bin
INCLUDE = -I /usr/include/
dirlib = -L /usr/lib/

src = $(wildcard *.cpp)
objs = $(patsubst %.cpp,%.o,$(src))

srcTun = $(wildcard ./lfrpTun/*.cpp)
objsTun = $(patsubst %.cpp,%.o,$(srcTun))

srcCli = $(wildcard ./lfrpCli/*.cpp)
objsCli = $(patsubst %.cpp,%.o,$(srcCli))

srcSvr = $(wildcard ./lfrpSvr/*.cpp)
objsSvr = $(patsubst %.cpp,%.o,$(srcSvr))

srcEchoCli = $(wildcard ./EchoClient/*.cpp)
objsEchoCli = $(patsubst %.cpp,%.o,$(srcEchoCli))

srcEchoSvr = $(wildcard ./EchoServer/*.cpp)
objsEchoSvr = $(patsubst %.cpp,%.o,$(srcEchoSvr))

all : $(targetTun) $(targetCli) $(targetSvr) $(targetEchoCli) $(targetEchoSvr)

#bin:
#	mkdir -p ./bin

$(targetTun) : $(objs) $(objsTun)
	@mkdir -p $(TARGETDIR)
	g++ $(CFLAGS) $(objs) $(objsTun) $(dirlib) $(lib) -o $(targetTun) $(INCLUDE)
	
$(targetCli) : $(objs) $(objsCli)
	@mkdir -p $(TARGETDIR)
	g++ $(CFLAGS) $(objs) $(objsCli) $(dirlib) $(lib) -o $(targetCli) $(INCLUDE)
	
$(targetSvr) : $(objs) $(objsSvr)
	@mkdir -p $(TARGETDIR)
	g++ $(CFLAGS) $(objs) $(objsSvr) $(dirlib) $(lib) -o $(targetSvr) $(INCLUDE)
	
$(targetEchoCli) : $(objsEchoCli)
	@mkdir -p $(TARGETDIR)
	g++ $(CFLAGS) $(objsEchoCli) $(dirlib) $(lib) -o $(targetEchoCli) $(INCLUDE)
	
$(targetEchoSvr) : $(objsEchoSvr)
	@mkdir -p $(TARGETDIR)
	g++ $(CFLAGS) $(objsEchoSvr) $(dirlib) $(lib) -o $(targetEchoSvr) $(INCLUDE)

%.o: %.cpp
	g++ $(CFLAGS) $(INCLUDE) $(lib) $(dirlib) -c $< -o $@ 

.PHONY:clean
clean:
	rm -f $(objs) $(targetTun) $(objsTun) $(targetCli) $(objsCli) $(targetSvr) $(objsSvr) $(targetEchoCli) $(objsEchoCli) $(targetEchoSvr) $(objsEchoSvr)