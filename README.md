# gsm
gsm stands General Security Manager, the objective of this program is to be a Kernel module and a app, which will work together.
This is still a code sketch, for now he will not delete any file with contains "luke" at the name or if it is in "/etc/". It will not be deleted no matter what, even if run as sudo or with -rf, it won't be deleted, to delete a file you need to use this command:

```
echo -n "luke123" | sudo tee /proc/gsm_control
```

The password for now is hardcoded in the code, i will make it be interchangeable.

Currently is only the kernel module, for the 6.6.9.

Going to increase both functionality's and the README soon.
