FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential libz-dev clang

COPY . /repo
WORKDIR /repo
RUN make -j8
RUN clang++ /repo/mayhem/fuzz_mm_split_rm_tmp.cpp -fsanitize=fuzzer,address -I /repo/ /repo/libminimap2.a -o /fuzz

FROM ubuntu:20.04 as package
COPY --from=builder /repo/minimap2 /
COPY --from=builder /repo/test/q2.fa /repo/test/q2.fa
COPY --from=builder /fuzz /fuzz_mm_split_rm_tmp
