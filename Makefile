# Detect operating system
ifeq ($(OS),Windows_NT)
    LIBS = C:/Windows/System32/wpcap.dll -lws2_32
    TARGET = live_dpi.exe
    CLEAN = del /Q $(TARGET) *.o 2>NUL || true
else
    LIBS = -lpcap
    TARGET = live_dpi
    CLEAN = rm -f $(TARGET) *.o
endif

CXX = g++
CXXFLAGS = -std=c++17 -O2 -I include

# Object files list
OBJS = src/live_dpi.o src/packet_parser.o src/sni_extractor.o src/types.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

# Compilation rule for .cpp to .o
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	$(CLEAN)
