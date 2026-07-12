FROM ubuntu:latest
LABEL authors="pc"

ENTRYPOINT ["top", "-b"]