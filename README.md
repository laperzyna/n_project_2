# Networks Final Project Part 2

## Table of Contents
1. [Description](#description)
2. [Instructions](#instructions)
3. [Incomplete Features](#incomplete-features)
7. [Contributers](#contributers)

## Description
This project is an example of End-to-End Detection of Network Compression. It is a standalone application that uses a third party JSON parser as well as an inputed config file. This application will detect compression upon the different between two SYN packet and two UDP packet trains.

## Instructions
In order to run this program:
1. Clone the repo from github or include the following files in the same folder:
    - highEntropy
    - jsmn.h (https://github.com/zserge/jsmn) <-- link to this third party parser
    - JsonParse.h
    - Makefile
    - NetworkCapture.pcapng
    - projectPart2.c
    - a config.json file
2. Once you have the correct file structure you may simply just run "make" in order to compile the program
3. In order to run the program you must write "sudo ./projectPart2.c [your config.json file]".


## Incomplete Features
Most of the program fullfills the required features, however we did struggle on one particular area that was ultimately not fullfilled. We could not recieve our RST packets in our program. We worked on this for a long time and were able to see that our packets were being sent correctly we just could not recieve our RST packets so for the time being our timers starts when we send our two SYN packets and the difference is calculated between the two to get the final compression result.

## Contributers
Maleke Hanson <br>
Lidia Perzyna
