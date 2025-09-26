# NAT on p4

### Environment setting

Install the p4 vm from [official github](https://github.com/p4lang/tutorials) and clone the folder into `./tutorials/exercises`


## Introduction

Only the switch `s3` build from `nat.p4`(find detail in `s3-runtime.json`). Other 2 switches `s1`, `s2` are build from `nonat.p4`(find detail in `s1-runtime.json` and `s2-runtime.json`).  

## Test
After setting up your VM, open two consoles and navigate to `~/tutorials/exercises` Run the following commands:

- terminal 1
```
make run
```

- terminal 2
```
python3 run_controller.py
```

- test script(send.py, recieve.py)
```
# use the send.py and recieve.py to test the NAT
```