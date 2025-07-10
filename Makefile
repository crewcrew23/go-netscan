.PHONY: build run clear

EXE=./bin/go-netscaner.exe

build:
	go build -o $(EXE) .\cmd\main.go

run: 
	$(EXE) --find-interfaces

clear:
	rm -f $(EXE)
