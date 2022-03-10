A simple C example featuring:


A secret dependent, deterministic memory access 

```
val = T[secret];
```


Note that it seems that `____strtol_l_internal` (called by `atoi`) is also subject to some leaks, though these adresses are not included in the json file.