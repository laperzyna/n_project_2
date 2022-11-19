

#the "|| exit 1" is extra that is only because I have an extra second line that runs the program right after
#it is made. With "|| exit 1", the program does not try to run when the build

#client:
#	gcc -o $(OUT_FILE) $(C_FILES) || exit 1
#	./$(OUT_FILE)

PROG = projectPart2


$(PROG): $(PROG).c JsonParse.h
	gcc -g -o $(PROG) $(PROG).c

run:
	sudo ./$(PROG) config.json

clean:
	rm -rf projectPart2
	