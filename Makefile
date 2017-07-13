CFLAGS = -g

all: ping.exe
	@echo "Done"

ping.exe:
	gcc lajiping.c $(CFLAGS) -o $@ 
	
clean:
	rm ./ping.exe

.PHONY: clean all